package cli

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/adithyan-ak/agenthound/collector/apiclient"
	"github.com/adithyan-ak/agenthound/collector/internal/clientcfg"
	icollector "github.com/adithyan-ak/agenthound/internal/collector"
	a2acollector "github.com/adithyan-ak/agenthound/modules/a2a"
	configcollector "github.com/adithyan-ak/agenthound/modules/config"
	mcpcollector "github.com/adithyan-ak/agenthound/modules/mcp"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/sdk/rules"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan AI agent infrastructure and ship the result to the server (or to a file)",
	Long: `Discover and enumerate MCP servers, A2A agents, and client configurations,
then ship the merged trust graph as JSON.

By default, the collector runs config + MCP enumeration. Use --config, --mcp,
or --a2a to scope the scan. Output goes to a file when --output is set,
otherwise it is uploaded to the agenthound-server at $AGENTHOUND_SERVER_URL.`,
	RunE: runScan,
}

func init() {
	scanCmd.Flags().Bool("config", false, "Run config collector only")
	scanCmd.Flags().Bool("mcp", false, "Run MCP collector only")
	scanCmd.Flags().Bool("a2a", false, "Run A2A collector only")

	scanCmd.Flags().String("path", "", "Path to specific config file")
	scanCmd.Flags().StringSlice("paths", nil, "Paths to multiple config files")
	scanCmd.Flags().String("project-dir", "", "Project directory for instruction file discovery")
	scanCmd.Flags().Bool("include-credential-values", false, "Include raw credential values")

	scanCmd.Flags().String("url", "", "URL of a single HTTP MCP server")

	scanCmd.Flags().String("target", "", "URL of a single A2A agent")
	scanCmd.Flags().StringSlice("targets", nil, "URLs of multiple A2A agents")
	scanCmd.Flags().StringSlice("discover-domain", nil, "Domains to probe for well-known agent cards")
	scanCmd.Flags().String("targets-file", "", "File with A2A agent URLs (one per line)")
	scanCmd.Flags().String("auth-token", "", "Bearer token for authenticated A2A agents")

	scanCmd.Flags().Int("scan-concurrency", 5, "Max parallel connections")
	scanCmd.Flags().Duration("timeout", 120*time.Second, "Timeout per server/agent")
	scanCmd.Flags().Bool("insecure", false, "Skip TLS verification")

	scanCmd.Flags().String("scan-output", "", "Export JSON to file (skip server upload)")
	scanCmd.Flags().String("fail-on", "", "Exit 1 if findings at or above severity: critical, high, medium, low")

	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	runConfig, _ := cmd.Flags().GetBool("config")
	runMCP, _ := cmd.Flags().GetBool("mcp")
	runA2A, _ := cmd.Flags().GetBool("a2a")

	path, _ := cmd.Flags().GetString("path")
	paths, _ := cmd.Flags().GetStringSlice("paths")
	projectDir, _ := cmd.Flags().GetString("project-dir")
	includeCredValues, _ := cmd.Flags().GetBool("include-credential-values")

	url, _ := cmd.Flags().GetString("url")

	target, _ := cmd.Flags().GetString("target")
	targets, _ := cmd.Flags().GetStringSlice("targets")
	discoverDomains, _ := cmd.Flags().GetStringSlice("discover-domain")
	targetsFile, _ := cmd.Flags().GetString("targets-file")
	authToken, _ := cmd.Flags().GetString("auth-token")

	concurrency, _ := cmd.Flags().GetInt("scan-concurrency")
	timeout, _ := cmd.Flags().GetDuration("timeout")
	insecure, _ := cmd.Flags().GetBool("insecure")

	output, _ := cmd.Flags().GetString("scan-output")
	if output == "" {
		// Fall back to root --output flag.
		if v, _ := cmd.Root().PersistentFlags().GetString("output"); v != "" {
			output = v
		}
	}

	failOn, _ := cmd.Flags().GetString("fail-on")

	if !runConfig && !runMCP && !runA2A {
		runConfig = true
		runMCP = true
	}

	if runConfig && url != "" {
		return fmt.Errorf("--url requires --mcp")
	}
	if runMCP && (target != "" || len(targets) > 0) && !runA2A {
		return fmt.Errorf("--target/--targets requires --a2a")
	}
	if runA2A && target == "" && len(targets) == 0 && len(discoverDomains) == 0 && targetsFile == "" {
		return fmt.Errorf("A2A requires --target, --targets, --discover-domain, or --targets-file")
	}

	for _, domain := range discoverDomains {
		targets = append(targets, fmt.Sprintf("https://%s/.well-known/agent-card.json", domain))
	}

	if failOn != "" {
		if _, ok := severityRank[failOn]; !ok {
			return fmt.Errorf("invalid --fail-on value %q: must be critical, high, medium, or low", failOn)
		}
	}

	start := time.Now()
	ctx := context.Background()

	merged := collectAll(ctx, runConfig, runMCP, runA2A,
		path, paths, projectDir, includeCredValues,
		url, target, targets, targetsFile, authToken,
		concurrency, timeout, insecure)

	if output != "" {
		_, _ = fmt.Fprintf(os.Stderr, "Collected %d nodes, %d edges\n", len(merged.Graph.Nodes), len(merged.Graph.Edges))
		return writeCollectorOutput(merged, output)
	}

	clientCfg, err := clientcfg.LoadClientConfig(cmd.Root().PersistentFlags())
	if err != nil {
		return err
	}
	if clientCfg == nil {
		return fmt.Errorf("no server configured\n\nRun 'agenthound setup' to connect to a server, or pass --output <file> to save the JSON locally")
	}

	return shipToServer(ctx, clientCfg, merged, start, failOn)
}

func collectAll(ctx context.Context, runConfig, runMCP, runA2A bool,
	path string, paths []string, projectDir string, includeCredValues bool,
	url, target string, targets []string, targetsFile, authToken string,
	concurrency int, timeout time.Duration, insecure bool) *ingest.IngestData {

	merged := &ingest.IngestData{
		Meta: ingest.IngestMeta{
			Version:          1,
			Type:             "agenthound-ingest",
			Collector:        "scan",
			CollectorVersion: "0.1.0",
			Timestamp:        time.Now().UTC().Format(time.RFC3339),
			ScanID:           uuid.New().String(),
		},
	}

	if runConfig {
		data, err := collectConfig(ctx, path, paths, projectDir, includeCredValues)
		if err != nil {
			slog.Error("config collector failed", "error", err)
		} else {
			merged.Graph.Nodes = append(merged.Graph.Nodes, data.Graph.Nodes...)
			merged.Graph.Edges = append(merged.Graph.Edges, data.Graph.Edges...)
		}
	}

	if runMCP {
		data, err := collectMCP(ctx, url, concurrency, timeout, insecure)
		if err != nil {
			slog.Error("mcp collector failed", "error", err)
		} else {
			merged.Graph.Nodes = append(merged.Graph.Nodes, data.Graph.Nodes...)
			merged.Graph.Edges = append(merged.Graph.Edges, data.Graph.Edges...)
		}
	}

	if runA2A {
		data, err := collectA2A(ctx, target, targets, targetsFile, authToken, concurrency, timeout, insecure)
		if err != nil {
			slog.Error("a2a collector failed", "error", err)
		} else {
			merged.Graph.Nodes = append(merged.Graph.Nodes, data.Graph.Nodes...)
			merged.Graph.Edges = append(merged.Graph.Edges, data.Graph.Edges...)
		}
	}

	return merged
}

func shipToServer(ctx context.Context, clientCfg *clientcfg.ClientConfig, merged *ingest.IngestData, start time.Time, failOn string) error {
	client := apiclient.New(clientCfg.ServerURL)

	if err := client.Health(ctx); err != nil {
		return fmt.Errorf("server check: %w", err)
	}

	_, _ = fmt.Fprintf(os.Stderr, "Collected %d nodes, %d edges → shipping to %s\n",
		len(merged.Graph.Nodes), len(merged.Graph.Edges), clientCfg.ServerURL)

	result, err := client.Ingest(ctx, merged)
	if err != nil {
		return fmt.Errorf("ingest via API: %w", err)
	}

	_, _ = fmt.Fprintf(os.Stderr, "\nScan complete (%.1fs)\n\n", time.Since(start).Seconds())
	_, _ = fmt.Fprintf(os.Stderr, "  %-8s  %d nodes, %d edges\n", "Graph", result.NodesWritten, result.EdgesWritten)

	var processorCount, compositeEdges int
	for _, ps := range result.PostProcessingStats {
		processorCount++
		compositeEdges += ps.EdgesCreated
	}
	if processorCount > 0 {
		_, _ = fmt.Fprintf(os.Stderr, "  %-8s  %d processors, %d composite edges\n", "Analysis", processorCount, compositeEdges)
	}

	findings, err := client.GetFindings(ctx, "")
	if err != nil {
		slog.Warn("failed to fetch findings", "error", err)
	} else if len(findings) > 0 {
		counts := countFindingsBySeverity(findings)
		_, _ = fmt.Fprintf(os.Stderr, "\n  Findings %d critical, %d high, %d medium, %d low\n",
			counts["critical"], counts["high"], counts["medium"], counts["low"])
	}

	_, _ = fmt.Fprintln(os.Stderr)

	if failOn != "" {
		threshold := severityRank[failOn]
		if findings == nil {
			findings, err = client.GetFindings(ctx, "")
			if err != nil {
				return fmt.Errorf("query findings for --fail-on: %w", err)
			}
		}
		count := countAtOrAbove(findings, threshold)
		if count > 0 {
			_, _ = fmt.Fprintf(os.Stderr, "Failed: %d finding(s) at severity %q or above\n", count, failOn)
			os.Exit(1)
		}
	}

	return nil
}

func loadRulesEngineOrNil() *rules.Engine {
	engine, err := buildRulesEngine()
	if err != nil {
		slog.Warn("failed to load rules engine, falling back to legacy patterns", "error", err)
		return nil
	}
	slog.Info("rules engine loaded", "rules", engine.RuleCount())
	return engine
}

func collectConfig(ctx context.Context, path string, paths []string, projectDir string, includeCredValues bool) (*ingest.IngestData, error) {
	c := configcollector.NewConfigCollector()
	opts := icollector.CollectOptions{
		Discover:                path == "" && len(paths) == 0,
		ConfigPath:              path,
		ConfigPaths:             paths,
		ProjectDir:              projectDir,
		IncludeCredentialValues: includeCredValues,
		RulesEngine:             loadRulesEngineOrNil(),
	}
	slog.Info("running config collector", "discover", opts.Discover, "path", path)
	return c.Collect(ctx, opts)
}

func collectMCP(ctx context.Context, url string, concurrency int, timeout time.Duration, insecure bool) (*ingest.IngestData, error) {
	var mcpOpts []mcpcollector.Option
	if concurrency > 0 {
		mcpOpts = append(mcpOpts, mcpcollector.WithConcurrency(concurrency))
	}
	if timeout > 0 {
		mcpOpts = append(mcpOpts, mcpcollector.WithTimeout(timeout))
	}

	c := mcpcollector.NewMCPCollector(mcpOpts...)
	opts := icollector.CollectOptions{
		Discover:    url == "",
		TargetURL:   url,
		Insecure:    insecure,
		RulesEngine: loadRulesEngineOrNil(),
	}
	slog.Info("running mcp collector", "discover", opts.Discover, "url", url)
	return c.Collect(ctx, opts)
}

func collectA2A(ctx context.Context, target string, targets []string, targetsFile, authToken string,
	concurrency int, timeout time.Duration, insecure bool) (*ingest.IngestData, error) {
	var a2aOpts []a2acollector.Option
	if concurrency > 0 {
		a2aOpts = append(a2aOpts, a2acollector.WithConcurrency(concurrency))
	}
	if timeout > 0 {
		a2aOpts = append(a2aOpts, a2acollector.WithTimeout(timeout))
	}
	if insecure {
		a2aOpts = append(a2aOpts, a2acollector.WithInsecure(true))
	}

	c := a2acollector.NewA2ACollector(a2aOpts...)
	opts := icollector.CollectOptions{
		TargetURL:      target,
		TargetURLs:     targets,
		TargetURLsFile: targetsFile,
		AuthToken:      authToken,
		Insecure:       insecure,
		RulesEngine:    loadRulesEngineOrNil(),
	}
	slog.Info("running a2a collector", "target", target, "targets", len(targets))
	return c.Collect(ctx, opts)
}

var severityRank = map[string]int{
	"critical": 0,
	"high":     1,
	"medium":   2,
	"low":      3,
}

func countFindingsBySeverity(findings []apiclient.Finding) map[string]int {
	counts := map[string]int{
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
	}
	for _, f := range findings {
		counts[f.Severity]++
	}
	return counts
}

func countAtOrAbove(findings []apiclient.Finding, threshold int) int {
	count := 0
	for _, f := range findings {
		if rank, ok := severityRank[f.Severity]; ok && rank <= threshold {
			count++
		}
	}
	return count
}
