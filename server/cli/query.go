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
	queryCmd.Flags().String("format", "table", "Output format: table or json")
	queryCmd.Flags().String("fail-on", "", "Exit 1 if findings at or above severity: critical, high, medium, low")
	rootCmd.AddCommand(queryCmd)
}

func runQuery(cmd *cobra.Command, args []string) error {
	prebuiltID, _ := cmd.Flags().GetString("prebuilt")
	findings, _ := cmd.Flags().GetBool("findings")
	severity, _ := cmd.Flags().GetString("severity")
	shortestPath, _ := cmd.Flags().GetBool("shortest-path")
	fromNode, _ := cmd.Flags().GetString("from")
	toNode, _ := cmd.Flags().GetString("to")
	format, _ := cmd.Flags().GetString("format")

	failOn, _ := cmd.Flags().GetString("fail-on")

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
	if modes == 0 {
		return fmt.Errorf("specify a query mode: raw Cypher argument, --prebuilt, --findings, or --shortest-path")
	}
	if modes > 1 {
		return fmt.Errorf("specify only one query mode at a time")
	}

	ctx := context.Background()

	switch {
	case findings:
		return runFindings(ctx, severity, format, failOn)
	case prebuiltID != "":
		return runPrebuilt(ctx, prebuiltID, format)
	case shortestPath:
		return runShortestPath(ctx, fromNode, toNode, format)
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

	rows, err := infra.GraphDB.Query(ctx, q.Cypher, nil)
	if err != nil {
		return fmt.Errorf("query %s: %w", id, err)
	}

	return printRows(rows, format)
}

func runFindings(ctx context.Context, severity, format, failOn string) error {
	if severity != "" {
		switch severity {
		case "critical", "high", "medium", "low":
		default:
			return fmt.Errorf("invalid severity %q: must be critical, high, medium, or low", severity)
		}
	}

	infra, cleanup, err := Bootstrap(ctx)
	if err != nil {
		return err
	}
	defer cleanup()

	findings, err := analysis.QueryFindings(ctx, infra.GraphDB, severity)
	if err != nil {
		return fmt.Errorf("query findings: %w", err)
	}

	if len(findings) == 0 {
		fmt.Println("No findings found.")
		return nil
	}

	if format == "json" {
		return printJSON(findings)
	}

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

	_, _ = fmt.Fprintf(os.Stderr, "\n%d finding(s)\n", len(findings))

	if failOn != "" {
		threshold, ok := severityRank[failOn]
		if !ok {
			return fmt.Errorf("invalid --fail-on value %q: must be critical, high, medium, or low", failOn)
		}
		count := countAtOrAbove(findings, threshold)
		if count > 0 {
			_, _ = fmt.Fprintf(os.Stderr, "Failed: %d finding(s) at severity %q or above\n", count, failOn)
			os.Exit(1)
		}
	}

	return nil
}

func runShortestPath(ctx context.Context, from, to, format string) error {
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

	cypher := fmt.Sprintf(
		`MATCH (src:%s {name: $from_name}), (tgt:%s {name: $to_name})
MATCH p = shortestPath((src)-[*..15]-(tgt))
RETURN [n IN nodes(p) | coalesce(n.name, n.objectid)] AS path_nodes,
       [n IN nodes(p) | labels(n)[0]] AS path_kinds,
       [rel IN relationships(p) | type(rel)] AS path_edges,
       length(p) AS path_length`,
		fromKind, toKind)

	params := map[string]any{
		"from_name": fromName,
		"to_name":   toName,
	}

	infra, cleanup, err := Bootstrap(ctx)
	if err != nil {
		return err
	}
	defer cleanup()

	rows, err := infra.GraphDB.Query(ctx, cypher, params)
	if err != nil {
		return fmt.Errorf("shortest path: %w", err)
	}

	if len(rows) == 0 {
		fmt.Printf("No path found from %s:%s to %s:%s\n", fromKind, fromName, toKind, toName)
		return nil
	}

	return printRows(rows, format)
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

func countAtOrAbove(findings []analysis.Finding, threshold int) int {
	count := 0
	for _, f := range findings {
		if rank, ok := severityRank[f.Severity]; ok && rank <= threshold {
			count++
		}
	}
	return count
}
