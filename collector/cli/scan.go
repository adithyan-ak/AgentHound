package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"time"

	a2acollector "github.com/adithyan-ak/agenthound/modules/a2a"
	configcollector "github.com/adithyan-ak/agenthound/modules/config"
	mcpcollector "github.com/adithyan-ak/agenthound/modules/mcp"
	icollector "github.com/adithyan-ak/agenthound/sdk/collector"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/sdk/rules"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan AI agent infrastructure and write the result to a file or stdout",
	Long: `Discover and enumerate MCP servers, A2A agents, and client configurations,
then write the merged trust graph as JSON.

By default, the collector runs config + MCP enumeration. Use --config, --mcp,
or --a2a to scope the scan. Output goes to a file: pass --output <path> to
choose the path, or pass --output - to stream the JSON to stdout (useful for
piping into 'agenthound-server ingest -'). When --output is unset, the scan
is written to ./scan-<scan_id>.json in the current working directory.

Operators ingest the resulting JSON on their analysis box via either:

  agenthound-server ingest scan.json
  cat scan.json | agenthound-server ingest -

or by drag-dropping the file into the UI's Scan Manager → Import Scan dialog.`,
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

	scanCmd.Flags().String("scan-output", "", "Write scan JSON to this path. Use '-' for stdout. Defaults to ./scan-<scan_id>.json in CWD.")

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
		// Fall back to the root --output persistent flag (and its
		// AGENTHOUND_OUTPUT env-var resolution, which lives on cfg).
		if cfg != nil && cfg.Output != "" {
			output = cfg.Output
		} else if v, _ := cmd.Root().PersistentFlags().GetString("output"); v != "" {
			output = v
		}
	}

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

	ctx := context.Background()

	merged := collectAll(ctx, runConfig, runMCP, runA2A,
		path, paths, projectDir, includeCredValues,
		url, target, targets, targetsFile, authToken,
		concurrency, timeout, insecure)

	// Default behavior: if no --output set, auto-name to scan-<scan_id>.json in CWD.
	if output == "" {
		output = fmt.Sprintf("scan-%s.json", merged.Meta.ScanID)
	}

	_, _ = fmt.Fprintf(os.Stderr, "Collected %d nodes, %d edges\n", len(merged.Graph.Nodes), len(merged.Graph.Edges))

	// "-" means stdout.
	if output == "-" {
		return writeCollectorOutputStdout(merged)
	}
	return writeCollectorOutput(merged, output)
}

// writeCollectorOutputStdout writes the merged scan as indented JSON to
// os.Stdout. Used for piping into 'agenthound-server ingest -'. No atomic
// write semantics; stdout is the operator's responsibility (e.g., via SSH).
func writeCollectorOutputStdout(data *ingest.IngestData) error {
	encoded, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal JSON: %w", err)
	}
	if _, err := os.Stdout.Write(encoded); err != nil {
		return fmt.Errorf("write stdout: %w", err)
	}
	if _, err := os.Stdout.Write([]byte("\n")); err != nil {
		return fmt.Errorf("write stdout: %w", err)
	}
	return nil
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
