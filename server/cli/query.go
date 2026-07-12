package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/server/internal/analysis"
	"github.com/adithyan-ak/agenthound/server/internal/analysis/prebuilt"
	"github.com/adithyan-ak/agenthound/server/internal/appdb"
	"github.com/adithyan-ak/agenthound/server/internal/graph"
	"github.com/adithyan-ak/agenthound/server/model"
	"github.com/spf13/cobra"
)

var queryCmd = &cobra.Command{
	Use:   "query [cypher]",
	Short: "Execute Cypher queries against the graph",
	Long: `Execute queries against the AgentHound graph database.

Modes:
  agenthound-server query "MATCH (n:MCPServer) RETURN n.name"   Raw Cypher
  agenthound-server query --prebuilt agents-shell-access         Pre-built query
  agenthound-server query --findings [--severity critical]       List findings
  agenthound-server query --shortest-path --from Kind:name --to Kind:name`,
	RunE: runQuery,
}

func init() {
	queryCmd.Flags().String("prebuilt", "", "Run a pre-built query by ID")
	queryCmd.Flags().Bool("findings", false, "List all findings")
	queryCmd.Flags().String("severity", "", "Filter by severity: critical, high, medium, low")
	queryCmd.Flags().Bool("shortest-path", false, "Find shortest path between two nodes")
	queryCmd.Flags().String("from", "", "Source node in Kind:name format (e.g. AgentInstance:my-agent)")
	queryCmd.Flags().String("to", "", "Target node in Kind:name format (e.g. MCPResource:postgres://prod)")
	queryCmd.Flags().String("path-mode", "security", "Path mode: security (directed policy) or topology (undirected graph)")
	queryCmd.Flags().String("format", "table", "Output format: table or json")
	queryCmd.Flags().String("fail-on", "", "Exit 1 if findings at or above severity: critical, high, medium, low")
	queryCmd.Flags().Bool("all-findings", false, "Include suppressed findings (accepted-risk, false-positive); --fail-on always ignores suppressed")
	queryCmd.Flags().String("diff", "", "Diff two scans' findings: scanA,scanB")
	rootCmd.AddCommand(queryCmd)
}

func runQuery(cmd *cobra.Command, args []string) error {
	prebuiltID, _ := cmd.Flags().GetString("prebuilt")
	findings, _ := cmd.Flags().GetBool("findings")
	severity, _ := cmd.Flags().GetString("severity")
	shortestPath, _ := cmd.Flags().GetBool("shortest-path")
	fromNode, _ := cmd.Flags().GetString("from")
	toNode, _ := cmd.Flags().GetString("to")
	pathMode, _ := cmd.Flags().GetString("path-mode")
	format, _ := cmd.Flags().GetString("format")

	failOn, _ := cmd.Flags().GetString("fail-on")
	includeSuppressed, _ := cmd.Flags().GetBool("all-findings")
	diffArg, _ := cmd.Flags().GetString("diff")

	if format != "table" && format != "json" {
		return fmt.Errorf("invalid format %q: must be table or json", format)
	}

	modes := 0
	if len(args) > 0 {
		modes++
	}
	if prebuiltID != "" {
		modes++
	}
	if findings {
		modes++
	}
	if shortestPath {
		modes++
	}
	if diffArg != "" {
		modes++
	}
	if modes == 0 {
		return fmt.Errorf("specify a query mode: raw Cypher argument, --prebuilt, --findings, --diff, or --shortest-path")
	}
	if modes > 1 {
		return fmt.Errorf("specify only one query mode at a time")
	}

	ctx := context.Background()

	switch {
	case findings:
		return runFindings(ctx, severity, format, failOn, includeSuppressed)
	case diffArg != "":
		return runDiff(ctx, diffArg, format, includeSuppressed)
	case prebuiltID != "":
		return runPrebuilt(ctx, prebuiltID, format)
	case shortestPath:
		return runShortestPath(ctx, fromNode, toNode, pathMode, format)
	default:
		return runRawCypher(ctx, args[0], format)
	}
}

func runRawCypher(ctx context.Context, cypher, format string) error {
	infra, cleanup, err := Bootstrap(ctx)
	if err != nil {
		return err
	}
	defer cleanup()

	rows, err := infra.GraphDB.Query(ctx, cypher, nil)
	if err != nil {
		return fmt.Errorf("query: %w", err)
	}

	return printRows(rows, format)
}

func runPrebuilt(ctx context.Context, id, format string) error {
	q, ok := prebuilt.Get(id)
	if !ok {
		_, _ = fmt.Fprintf(os.Stderr, "Unknown pre-built query %q. Available queries:\n\n", id)
		printPrebuiltList()
		return fmt.Errorf("pre-built query %q not found", id)
	}

	_, _ = fmt.Fprintf(os.Stderr, "[%s] %s\n", q.Severity, q.Name)
	_, _ = fmt.Fprintf(os.Stderr, "%s\n\n", q.Description)

	infra, cleanup, err := Bootstrap(ctx)
	if err != nil {
		return err
	}
	defer cleanup()

	if id == "shortest-to-database" {
		result, err := analysis.FindShortestDatabasePaths(ctx, infra.GraphDB)
		if err != nil {
			return fmt.Errorf("query %s: %w", id, err)
		}
		_, _ = fmt.Fprintf(
			os.Stderr,
			"[path] scope=%s direction=%s algorithm=%s complete=%t\n\n",
			result.Metadata.Scope,
			result.Metadata.Direction,
			result.Metadata.Algorithm,
			result.Metadata.Complete,
		)
		return printRows(analysis.DatabasePathRows(result), format)
	}

	rows, err := infra.GraphDB.Query(ctx, q.Cypher, nil)
	if err != nil {
		return fmt.Errorf("query %s: %w", id, err)
	}

	return printRows(rows, format)
}

func runFindings(ctx context.Context, severity, format, failOn string, includeSuppressed bool) error {
	if severity != "" {
		switch severity {
		case "critical", "high", "medium", "low":
		default:
			return fmt.Errorf("invalid severity %q: must be critical, high, medium, or low", severity)
		}
	}
	threshold := 0
	if failOn != "" {
		var ok bool
		threshold, ok = severityRank[failOn]
		if !ok {
			return fmt.Errorf("invalid --fail-on value %q: must be critical, high, medium, or low", failOn)
		}
	}

	infra, cleanup, err := Bootstrap(ctx)
	if err != nil {
		return err
	}
	defer cleanup()

	findings, scope, err := infra.FindingStore.ListPublished(ctx, severity, includeSuppressed)
	if err != nil {
		return fmt.Errorf("query findings: %w", err)
	}
	if err := validateCurrentFindingScope(scope); err != nil {
		return err
	}

	failureCount := 0
	if failOn != "" {
		// --fail-on ALWAYS evaluates against the non-suppressed set so an
		// accepted-risk / false-positive never breaks CI, regardless of
		// whether --all-findings was passed to widen the display.
		gate := findings
		if includeSuppressed {
			var gateScope appdb.FindingScope
			gate, gateScope, err = infra.FindingStore.ListPublished(ctx, severity, false)
			if err != nil {
				return fmt.Errorf("query findings for fail-on: %w", err)
			}
			if err := validateCurrentFindingScope(gateScope); err != nil {
				return fmt.Errorf("query findings for fail-on: %w", err)
			}
			if !sameFindingScope(scope, gateScope) {
				return fmt.Errorf(
					"published findings snapshot changed during query: scan=%s revision=%d became scan=%s revision=%d",
					scope.ScanID,
					*scope.Revision,
					gateScope.ScanID,
					*gateScope.Revision,
				)
			}
		}
		failureCount = countAtOrAbove(gate, threshold)
	}

	if err := printPublishedFindings(findings, scope, format); err != nil {
		return err
	}
	if failureCount > 0 {
		_, _ = fmt.Fprintf(
			os.Stderr,
			"Failed: %d finding(s) at severity %q or above\n",
			failureCount,
			failOn,
		)
		return fmt.Errorf("%d finding(s) at severity %q or above", failureCount, failOn)
	}

	return nil
}

func validateCurrentFindingScope(scope appdb.FindingScope) error {
	if !scope.Available ||
		scope.ScanID == "" ||
		scope.Revision == nil ||
		*scope.Revision < 1 {
		return fmt.Errorf("no complete published findings snapshot is available")
	}
	if scope.Stale ||
		scope.ProjectionStatus != model.ProjectionComplete ||
		scope.SnapshotStatus != model.LifecycleComplete {
		return fmt.Errorf(
			"published findings snapshot is stale: scan=%s revision=%d projection=%s snapshot=%s",
			scope.ScanID,
			*scope.Revision,
			scope.ProjectionStatus,
			scope.SnapshotStatus,
		)
	}
	return nil
}

func sameFindingScope(left, right appdb.FindingScope) bool {
	return left.ScanID == right.ScanID &&
		left.Revision != nil &&
		right.Revision != nil &&
		*left.Revision == *right.Revision
}

func printPublishedFindings(
	findings []model.Finding,
	scope appdb.FindingScope,
	format string,
) error {
	if err := validateCurrentFindingScope(scope); err != nil {
		return err
	}
	if format == "json" {
		return printJSON(struct {
			Findings []model.Finding    `json:"findings"`
			Scope    appdb.FindingScope `json:"scope"`
		}{
			Findings: findings,
			Scope:    scope,
		})
	}

	_, _ = fmt.Fprintf(
		os.Stderr,
		"Published snapshot: scan=%s revision=%d\n",
		scope.ScanID,
		*scope.Revision,
	)
	if len(findings) == 0 {
		fmt.Println("No findings found.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "ID\tSEVERITY\tTRIAGE\tCATEGORY\tTITLE\tSOURCE\tTARGET")
	for _, f := range findings {
		srcLabel := f.SourceName
		if srcLabel == "" {
			srcLabel = f.SourceID
		}
		tgtLabel := f.TargetName
		if tgtLabel == "" {
			tgtLabel = f.TargetID
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			f.ID, f.Severity, triageStatus(f), f.Category, f.Title, srcLabel, tgtLabel)
	}
	_ = w.Flush()
	_, _ = fmt.Fprintf(os.Stderr, "\n%d finding(s)\n", len(findings))
	return nil
}

func runShortestPath(ctx context.Context, from, to, scopeValue, format string) error {
	if from == "" || to == "" {
		return fmt.Errorf("--shortest-path requires both --from and --to flags in Kind:name format")
	}

	fromKind, fromName, err := parseNodeRef(from)
	if err != nil {
		return fmt.Errorf("--from: %w", err)
	}
	toKind, toName, err := parseNodeRef(to)
	if err != nil {
		return fmt.Errorf("--to: %w", err)
	}

	scope, err := analysis.ParseTraversalScope(scopeValue)
	if err != nil {
		return fmt.Errorf("--path-mode: %w", err)
	}

	infra, cleanup, err := Bootstrap(ctx)
	if err != nil {
		return err
	}
	defer cleanup()

	result, err := findShortestPath(
		ctx,
		infra.GraphDB,
		fromKind,
		fromName,
		toKind,
		toName,
		scope,
	)
	if err != nil {
		return fmt.Errorf("shortest path: %w", err)
	}

	if len(result.Paths) == 0 {
		fmt.Printf("No path found from %s:%s to %s:%s\n", fromKind, fromName, toKind, toName)
		return nil
	}
	if format == "json" {
		return printJSON(result)
	}
	return printRows(traversalPathRows(result), format)
}

func findShortestPath(
	ctx context.Context,
	db graph.GraphDB,
	fromKind, fromName, toKind, toName string,
	scope analysis.TraversalScope,
) (analysis.TraversalResult, error) {
	sources, err := analysis.ResolveTraversalNodes(ctx, db, analysis.TraversalSelector{
		Kind: fromKind, Property: "name", Value: &fromName,
	})
	if err != nil {
		return analysis.TraversalResult{}, err
	}
	targets, err := analysis.ResolveTraversalNodes(ctx, db, analysis.TraversalSelector{
		Kind: toKind, Property: "name", Value: &toName,
	})
	if err != nil {
		return analysis.TraversalResult{}, err
	}
	return analysis.FindBoundedTraversalPaths(
		ctx,
		db,
		sources,
		targets,
		analysis.TraversalOptions{
			Scope: scope, Cost: analysis.TraversalCostHops,
			MaxHops: 15, Limit: 1, MaxExpansions: 100000,
		},
	)
}

func traversalPathRows(result analysis.TraversalResult) []map[string]any {
	rows := make([]map[string]any, 0, len(result.Paths))
	for _, path := range result.Paths {
		nodeNames := make([]string, 0, len(path.Nodes))
		nodeKinds := make([]string, 0, len(path.Nodes))
		for _, node := range path.Nodes {
			nodeNames = append(nodeNames, node.Name)
			kind := ""
			if len(node.Kinds) > 0 {
				kind = node.Kinds[0]
			}
			nodeKinds = append(nodeKinds, kind)
		}
		edgeKinds := make([]string, 0, len(path.Edges))
		for _, edge := range path.Edges {
			edgeKinds = append(edgeKinds, edge.Kind)
		}
		rows = append(rows, map[string]any{
			"path_nodes":  nodeNames,
			"path_kinds":  nodeKinds,
			"path_edges":  edgeKinds,
			"path_length": path.Hops,
			"scope":       result.Metadata.Scope,
			"direction":   result.Metadata.Direction,
			"algorithm":   result.Metadata.Algorithm,
		})
	}
	return rows
}

func parseNodeRef(ref string) (kind, name string, err error) {
	idx := strings.Index(ref, ":")
	if idx < 1 || idx >= len(ref)-1 {
		return "", "", fmt.Errorf("invalid format %q: expected Kind:name (e.g. MCPServer:my-server)", ref)
	}
	kind = ref[:idx]
	name = ref[idx+1:]

	if !ingest.AllowedNodeKinds[kind] {
		valid := make([]string, 0, len(ingest.AllowedNodeKinds))
		for k := range ingest.AllowedNodeKinds {
			valid = append(valid, k)
		}
		return "", "", fmt.Errorf("unknown node kind %q; valid kinds: %s", kind, strings.Join(valid, ", "))
	}
	return kind, name, nil
}

func printRows(rows []map[string]any, format string) error {
	if len(rows) == 0 {
		fmt.Println("(no results)")
		return nil
	}

	if format == "json" {
		return printJSON(rows)
	}

	cols := orderedColumns(rows[0])

	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, strings.Join(cols, "\t"))
	for _, row := range rows {
		vals := make([]string, len(cols))
		for i, col := range cols {
			vals[i] = formatValue(row[col])
		}
		_, _ = fmt.Fprintln(w, strings.Join(vals, "\t"))
	}
	_ = w.Flush()

	_, _ = fmt.Fprintf(os.Stderr, "\n%d row(s)\n", len(rows))
	return nil
}

func orderedColumns(row map[string]any) []string {
	cols := make([]string, 0, len(row))
	for k := range row {
		cols = append(cols, k)
	}
	return cols
}

func formatValue(v any) string {
	if v == nil {
		return "<null>"
	}
	switch val := v.(type) {
	case string:
		return val
	case float64:
		if val == float64(int64(val)) {
			return fmt.Sprintf("%d", int64(val))
		}
		return fmt.Sprintf("%.4f", val)
	case int64:
		return fmt.Sprintf("%d", val)
	case bool:
		if val {
			return "true"
		}
		return "false"
	case []any:
		parts := make([]string, len(val))
		for i, item := range val {
			parts[i] = formatValue(item)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	default:
		return fmt.Sprintf("%v", val)
	}
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func printPrebuiltList() {
	w := tabwriter.NewWriter(os.Stderr, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "ID\tCATEGORY\tSEVERITY\tNAME")
	for _, q := range prebuilt.List() {
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", q.ID, q.Category, q.Severity, q.Name)
	}
	_ = w.Flush()
}

var severityRank = map[string]int{
	"critical": 0,
	"high":     1,
	"medium":   2,
	"low":      3,
}

func countAtOrAbove(findings []model.Finding, threshold int) int {
	count := 0
	for _, f := range findings {
		if rank, ok := severityRank[f.Severity]; ok && rank <= threshold {
			count++
		}
	}
	return count
}

func triageStatus(f model.Finding) string {
	if f.Triage != nil && f.Triage.Status != "" {
		return f.Triage.Status
	}
	return "new"
}

// runDiff compares two scans' persisted findings snapshots. By default
// suppressed findings are dropped from the added set so CI-style diffs
// don't re-alert on an accepted risk reappearing; --all-findings includes
// them.
func runDiff(ctx context.Context, diffArg, format string, includeSuppressed bool) error {
	parts := strings.SplitN(diffArg, ",", 2)
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		return fmt.Errorf("--diff requires two scan IDs separated by a comma: scanA,scanB")
	}
	scanA, scanB := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])

	infra, cleanup, err := Bootstrap(ctx)
	if err != nil {
		return err
	}
	defer cleanup()

	diff, err := infra.FindingStore.Diff(ctx, scanA, scanB, includeSuppressed)
	if err != nil {
		return fmt.Errorf("diff findings: %w", err)
	}

	if format == "json" {
		return printJSON(diff)
	}

	printDiffSection("+ ADDED", diff.Added)
	printDiffSection("- REMOVED", diff.Removed)
	printDiffSection("= UNCHANGED", diff.Unchanged)
	_, _ = fmt.Fprintf(os.Stderr, "\n+%d  -%d  =%d   (%s -> %s)\n",
		len(diff.Added), len(diff.Removed), len(diff.Unchanged), scanA, scanB)
	return nil
}

func printDiffSection(label string, findings []model.Finding) {
	if len(findings) == 0 {
		return
	}
	fmt.Printf("\n%s (%d)\n", label, len(findings))
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "ID\tSEVERITY\tCATEGORY\tTITLE\tSOURCE\tTARGET")
	for _, f := range findings {
		srcLabel := f.SourceName
		if srcLabel == "" {
			srcLabel = f.SourceID
		}
		tgtLabel := f.TargetName
		if tgtLabel == "" {
			tgtLabel = f.TargetID
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			f.ID, f.Severity, f.Category, f.Title, srcLabel, tgtLabel)
	}
	_ = w.Flush()
}
