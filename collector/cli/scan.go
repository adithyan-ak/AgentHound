package cli

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	a2acollector "github.com/adithyan-ak/agenthound/modules/a2a"
	configcollector "github.com/adithyan-ak/agenthound/modules/config"
	"github.com/adithyan-ak/agenthound/modules/jupyterfp"
	mcpcollector "github.com/adithyan-ak/agenthound/modules/mcp"
	"github.com/adithyan-ak/agenthound/modules/networkscan"
	"github.com/adithyan-ak/agenthound/sdk/action"
	icollector "github.com/adithyan-ak/agenthound/sdk/collector"
	"github.com/adithyan-ak/agenthound/sdk/common"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/sdk/module"
	"github.com/adithyan-ak/agenthound/sdk/rules"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan [CIDR|host|@targets-file]",
	Short: "Scan AI agent infrastructure and write the result to a file or stdout",
	Long: `Discover and enumerate MCP servers, A2A agents, and client configurations,
then write the merged trust graph as JSON.

Two modes:

  agenthound scan
    Default mode — runs config + MCP collectors against the local host. Use
    --config, --mcp, or --a2a to scope the scan to one collector.

  agenthound scan 10.0.0.0/24
  agenthound scan 10.0.0.5
  agenthound scan @hosts.txt
    Network mode — when a positional argument is supplied, the network
    scanner sweeps the targets for AI/ML services on standard ports
    (Ollama, vLLM, Qdrant, MLflow, LiteLLM, Jupyter, LangServe, Open WebUI).
    Public IP space requires --allow-public-targets and an interactive
    AUTHORIZED confirmation. CIDRs larger than /16 require --allow-large-cidr.

Output goes to a file: pass --output <path> to choose the path, or pass
--output - to stream the JSON to stdout (useful for piping into
'agenthound-server ingest -'). When --output is unset, the scan is written
to ./scan-<scan_id>.json in the current working directory.

Local scans can save and ingest in one command:

  agenthound scan --config --ingest http://127.0.0.1:8080

The artifact is saved before upload. A compact receipt is printed by default;
pass --json for the full server receipt.

Operators ingest the resulting JSON on their analysis box via either:

  agenthound-server ingest scan.json
  cat scan.json | agenthound-server ingest -

or by drag-dropping the file into the UI's Scan Manager → Import Scan dialog.`,
	Args: cobra.MaximumNArgs(1),
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
	scanCmd.Flags().Bool("no-verify-jwks", false, "Disable remote JWKS (jku) resolution during A2A signature verification (offline: --a2a-trusted-keys only)")
	scanCmd.Flags().String("a2a-trusted-keys", "", "Path to a JWKS JSON file of trusted keys for A2A signature verification (offline key store)")

	scanCmd.Flags().Int("scan-concurrency", 5, "Max parallel connections")
	scanCmd.Flags().Duration("timeout", 120*time.Second, "Timeout per server/agent")
	scanCmd.Flags().Bool("insecure", false, "Skip TLS verification")

	scanCmd.Flags().String("scan-output", "", "Write scan JSON to this path. Use '-' for stdout. Defaults to ./scan-<scan_id>.json in CWD.")
	scanCmd.Flags().String("ingest", "", "Save and ingest the scan into an AgentHound server base URL")
	scanCmd.Flags().Bool("json", false, "Print the full remote ingest receipt as JSON (requires --ingest)")

	// Network-scan mode flags.
	scanCmd.Flags().IntSlice("ports", nil, "Override the default AI-service port set (network mode only). Default: 11434, 8000, 6333, 5000, 4000, 8888, 3000.")
	scanCmd.Flags().Int("network-scan-concurrency", networkscan.DefaultConcurrency, "Max parallel TCP connect probes (network mode only)")
	scanCmd.Flags().Bool("allow-public-targets", false, "Allow scanning public (non-RFC1918) IP space. Requires interactive AUTHORIZED confirmation.")
	scanCmd.Flags().Bool("allow-large-cidr", false, "Allow scanning CIDRs larger than /16 (IPv4) or /112 (IPv6).")
	scanCmd.Flags().String("authorization-file", "", "Path to a written-authorization document. The path and SHA-256 are recorded in the scan-output watermark.")

	scanCmd.Flags().Bool("verbose", false, "List per-host scan results (network mode). Default is a one-line summary.")

	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	remoteURL, _ := cmd.Flags().GetString("ingest")
	fullReceipt, _ := cmd.Flags().GetBool("json")

	// Network-mode dispatch: when a positional CIDR/host/@file is supplied,
	// the scanner runs instead of the legacy collector flow. The network path
	// performs the port sweep and then dispatches every registered fingerprinter.
	if len(args) == 1 {
		if remoteURL != "" || fullReceipt {
			return fmt.Errorf("--ingest and --json are supported only for local scans")
		}
		return runNetworkScan(cmd, args[0])
	}

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
	noVerifyJWKS, _ := cmd.Flags().GetBool("no-verify-jwks")
	a2aTrustedKeys, _ := cmd.Flags().GetString("a2a-trusted-keys")

	scanConcurrency, _ := cmd.Flags().GetInt("scan-concurrency")
	cfgConcurrency := 0
	if cfg != nil {
		cfgConcurrency = cfg.Concurrency
	}
	concurrency := resolveScanConcurrency(scanConcurrency, cmd.Flags().Changed("scan-concurrency"), cfgConcurrency)
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
	if fullReceipt && remoteURL == "" {
		return fmt.Errorf("--json requires --ingest")
	}
	if remoteURL != "" && output == "-" {
		return fmt.Errorf("--ingest cannot be combined with --output -; use a file path for the backup artifact")
	}
	if remoteURL != "" {
		if _, err := resolveRemoteIngestEndpoint(remoteURL); err != nil {
			return err
		}
	}

	if !runConfig && !runMCP && !runA2A {
		if url != "" {
			// --url with no explicit mode flags infers MCP-only mode. The
			// config collector ignores --url, so defaulting it on would
			// trip the "--url requires --mcp" guard below.
			runMCP = true
		} else {
			runConfig = true
			runMCP = true
		}
	}

	// Explicit --config combined with --url is a usage error: the config
	// collector has no notion of a target URL. We only error when the user
	// actually asked for config (not the default-on case handled above).
	if cmd.Flags().Changed("config") && runConfig && url != "" {
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
	rulesEngine, ruleset := loadEffectiveRules()

	merged, enabled, failed := collectAll(ctx, runConfig, runMCP, runA2A,
		path, paths, projectDir, includeCredValues,
		url, target, targets, targetsFile, authToken,
		concurrency, timeout, insecure, noVerifyJWKS, a2aTrustedKeys,
		rulesEngine, ruleset)

	// Default behavior: if no --output set, auto-name to scan-<scan_id>.json in CWD.
	if output == "" {
		output = fmt.Sprintf("scan-%s.json", merged.Meta.ScanID)
	}

	if !quietEnabled(cmd) {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Collected %d nodes, %d edges\n", len(merged.Graph.Nodes), len(merged.Graph.Edges))
	}

	if remoteURL != "" {
		artifact, err := marshalCollectorArtifact(merged)
		if err != nil {
			return err
		}
		if err := writeOutputAtomic(output, artifact); err != nil {
			return fmt.Errorf("write file: %w", err)
		}
		if !quietEnabled(cmd) {
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "[scan] saved artifact: %s\n", output)
		}
		if allCollectorsFailed(enabled, failed) {
			return fmt.Errorf("all %d enabled collector(s) failed", enabled)
		}
		if !quietEnabled(cmd) {
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "[scan] ingesting into %s\n", remoteURL)
		}
		receipt, err := postRemoteIngest(ctx, remoteURL, artifact)
		if err != nil {
			return err
		}
		if err := validateRemoteIngestScanID(receipt.result, merged.Meta.ScanID); err != nil {
			return err
		}
		if err := writeRemoteIngestResult(cmd.OutOrStdout(), receipt, output, fullReceipt); err != nil {
			return err
		}
		return validateRemoteIngestResult(receipt.result)
	}

	// Write the (possibly empty) artifact before deciding the exit code so
	// the operator keeps the envelope and logs even on total failure.
	var writeErr error
	if output == "-" {
		writeErr = writeCollectorOutputStdout(merged)
	} else {
		writeErr = writeCollectorOutput(merged, output)
	}
	if writeErr != nil {
		return writeErr
	}

	// Total-failure exit code: when every enabled collector errored, exit
	// non-zero. Partial success (>=1 collector succeeded) and a legitimately
	// empty-but-successful scan both exit 0 — the decision keys on collector
	// errors, not node count.
	if allCollectorsFailed(enabled, failed) {
		return fmt.Errorf("all %d enabled collector(s) failed", enabled)
	}
	return nil
}

// allCollectorsFailed reports whether every enabled collector errored. A scan
// with no enabled collectors, or with at least one success, returns false so
// runScan exits 0. The exit code keys on collector errors, never node count —
// a legitimately empty-but-successful scan must still exit 0.
func allCollectorsFailed(enabled, failed int) bool {
	return enabled > 0 && failed == enabled
}

// writeCollectorOutputStdout writes the merged scan as indented JSON to
// os.Stdout. Used for piping into 'agenthound-server ingest -'. No atomic
// write semantics; stdout is the operator's responsibility (e.g., via SSH).
func writeCollectorOutputStdout(data *ingest.IngestData) error {
	encoded, err := marshalCollectorArtifact(data)
	if err != nil {
		return err
	}
	if _, err := os.Stdout.Write(encoded); err != nil {
		return fmt.Errorf("write stdout: %w", err)
	}
	if _, err := os.Stdout.Write([]byte("\n")); err != nil {
		return fmt.Errorf("write stdout: %w", err)
	}
	return nil
}

// resolveScanConcurrency applies the concurrency precedence: an explicitly
// set --scan-concurrency always wins; otherwise the root
// --concurrency / AGENTHOUND_CONCURRENCY value (resolved onto cfg.Concurrency)
// is used when positive; otherwise the --scan-concurrency default holds.
func resolveScanConcurrency(scanConcurrency int, scanConcurrencyChanged bool, cfgConcurrency int) int {
	if !scanConcurrencyChanged && cfgConcurrency > 0 {
		return cfgConcurrency
	}
	return scanConcurrency
}

// resolveProbeTimeout picks the per-TCP-probe timeout for network mode. The
// shared --timeout flag defaults to 120s, which is tuned for the legacy
// per-server MCP/A2A HTTP collectors, NOT a per-connect probe. Applying it
// verbatim would make networkscan's intended 3s default unreachable and stall
// sweeps for minutes against drop-policy ports. So an explicit --timeout wins;
// otherwise we fall back to networkscan.DefaultProbeTimeout.
func resolveProbeTimeout(timeout time.Duration, timeoutChanged bool) time.Duration {
	if timeoutChanged && timeout > 0 {
		return timeout
	}
	return networkscan.DefaultProbeTimeout
}

func resolveFingerprintTimeout(timeout time.Duration, timeoutChanged bool) time.Duration {
	if timeoutChanged && timeout > 0 {
		return timeout
	}
	return 5 * time.Second
}

func normalizeNetworkConcurrency(value int) int {
	if value <= 0 {
		return networkscan.DefaultConcurrency
	}
	if value > networkscan.MaxConcurrency {
		return networkscan.MaxConcurrency
	}
	return value
}

// collectAll runs each enabled collector and merges its output. It returns
// the merged envelope plus the count of enabled collectors and how many of
// them failed, so the caller can decide the exit code (total failure → non-
// zero, partial/empty success → zero).
func collectAll(ctx context.Context, runConfig, runMCP, runA2A bool,
	path string, paths []string, projectDir string, includeCredValues bool,
	url, target string, targets []string, targetsFile, authToken string,
	concurrency int, timeout time.Duration, insecure bool,
	noVerifyJWKS bool, a2aTrustedKeys string,
	rulesEngine *rules.Engine, ruleset *ingest.RulesetManifest,
) (data *ingest.IngestData, enabled, failed int) {

	merged := common.NewIngestData("scan", uuid.New().String())
	merged.Meta.Ruleset = ruleset
	var reports []*ingest.CollectionReport

	if runConfig {
		enabled++
		data, err := collectConfig(ctx, path, paths, projectDir, includeCredValues, merged.Meta.ScanID, rulesEngine)
		if err != nil {
			failed++
			slog.Error("config collector failed", "error", err)
			reports = append(reports, failedCollectionReport("config", err))
		} else {
			merged.Graph.Nodes = append(merged.Graph.Nodes, data.Graph.Nodes...)
			merged.Graph.Edges = append(merged.Graph.Edges, data.Graph.Edges...)
			reports = append(reports, rootedCollectionReport(
				"config",
				data.Meta.Collection,
				path == "" && len(paths) == 0,
			))
		}
	}

	if runMCP {
		enabled++
		data, err := collectMCP(ctx, url, projectDir, concurrency, timeout, insecure, merged.Meta.ScanID, rulesEngine)
		if err != nil {
			failed++
			slog.Error("mcp collector failed", "error", err)
			reports = append(reports, failedCollectionReport("mcp", err))
		} else {
			merged.Graph.Nodes = append(merged.Graph.Nodes, data.Graph.Nodes...)
			merged.Graph.Edges = append(merged.Graph.Edges, data.Graph.Edges...)
			reports = append(reports, rootedCollectionReport(
				"mcp",
				data.Meta.Collection,
				url == "",
			))
		}
	}

	if runA2A {
		enabled++
		data, err := collectA2A(ctx, target, targets, targetsFile, authToken, concurrency, timeout, insecure, noVerifyJWKS, a2aTrustedKeys, merged.Meta.ScanID, rulesEngine)
		if err != nil {
			failed++
			slog.Error("a2a collector failed", "error", err)
			reports = append(reports, failedCollectionReport("a2a", err))
		} else {
			merged.Graph.Nodes = append(merged.Graph.Nodes, data.Graph.Nodes...)
			merged.Graph.Edges = append(merged.Graph.Edges, data.Graph.Edges...)
			reports = append(reports, rootedCollectionReport(
				"a2a",
				data.Meta.Collection,
				false,
			))
		}
	}
	merged.Meta.Collection = ingest.MergeCollectionReports(reports...)

	return merged, enabled, failed
}

func loadEffectiveRules() (*rules.Engine, *ingest.RulesetManifest) {
	var loadFailures []string
	engine, err := buildRulesEngine()
	if err != nil {
		slog.Warn("failed to load configured rules engine; falling back to built-ins", "error", err)
		loadFailures = append(
			loadFailures,
			"load configured text rules: "+err.Error(),
		)
		engine, err = rules.NewEngine(rules.LoadOptions{})
		if err != nil {
			loadFailures = append(
				loadFailures,
				"load builtin text rules: "+err.Error(),
			)
			manifest := ingest.EmptyRulesetManifest()
			manifest.LoadState = ingest.OutcomeFailed
			manifest.Errors = loadFailures
			return nil, manifest
		}
	}
	loadFailures = append(loadFailures, engine.LoadFailures()...)
	fingerprints, fingerprintErr := rules.LoadFingerprints()
	loadFailures = append(loadFailures, rules.FingerprintLoadFailures()...)
	if fingerprintErr != nil {
		loadFailures = append(
			loadFailures,
			"load fingerprint rules: "+fingerprintErr.Error(),
		)
	}
	effectiveFingerprints, detectors, dispatchFailures := effectiveFingerprintSemantics(
		fingerprints,
	)
	loadFailures = append(loadFailures, dispatchFailures...)
	manifest := rules.BuildManifestWithDetectors(
		engine.Rules(),
		effectiveFingerprints,
		detectors,
		loadFailures...,
	)
	slog.Info("rules engine loaded",
		"text_rules", engine.RuleCount(),
		"fingerprint_rules", len(effectiveFingerprints),
		"native_detectors", len(detectors),
		"ruleset_digest", manifest.Digest)
	return engine, &manifest
}

func effectiveFingerprintSemantics(
	fingerprints []rules.FingerprintRule,
) ([]rules.FingerprintRule, []rules.CodeDetector, []string) {
	effective := make([]rules.FingerprintRule, 0, len(fingerprints))
	var failures []string
	jupyterOverridePresent := false

	for _, fingerprint := range fingerprints {
		switch {
		case fingerprint.ID == jupyterfp.BundleOverrideID:
			jupyterOverridePresent = true
			if err := jupyterfp.ValidateBundleOverride(fingerprint); err != nil {
				failures = append(failures, err.Error())
				continue
			}
			effective = append(effective, fingerprint)
		case fingerprint.ServiceKind == "jupyter":
			failures = append(failures, fmt.Sprintf(
				"fingerprint rule %s cannot execute: Jupyter bundle overrides must use id %q",
				fingerprint.ID,
				jupyterfp.BundleOverrideID,
			))
		default:
			effective = append(effective, fingerprint)
		}
	}

	if jupyterOverridePresent {
		return effective, nil, failures
	}
	return effective, []rules.CodeDetector{
		jupyterfp.NativeDetectorDefinition(),
	}, failures
}

func collectorRootCoverageKey(collectorName string) string {
	return ingest.CollectorRootCoverageKey(collectorName)
}

func rootedCollectionReport(
	collectorName string,
	report *ingest.CollectionReport,
	authoritative bool,
) *ingest.CollectionReport {
	state := ingest.OutcomeUnknown
	if report != nil {
		state = report.State
		if state == "" {
			state = ingest.AggregateOutcomeState(report.Outcomes)
		}
	}
	rootKey := collectorRootCoverageKey(collectorName)
	root := &ingest.CollectionReport{
		State:        state,
		CoverageKeys: []string{rootKey},
		Outcomes: []ingest.CollectionOutcome{{
			Collector:   collectorName,
			CoverageKey: rootKey,
			Target:      collectorName,
			Method:      "collect",
			State:       state,
		}},
	}
	if authoritative && report != nil {
		children := make([]string, 0, len(report.CoverageKeys))
		for _, key := range report.CoverageKeys {
			if key != "" && key != rootKey {
				children = append(children, key)
			}
		}
		sort.Strings(children)
		root.AuthoritativeRoots = []ingest.CoverageRoot{{
			CoverageKey:       rootKey,
			ChildCoverageKeys: children,
		}}
	}
	return ingest.MergeCollectionReports(report, root)
}

func failedCollectionReport(collectorName string, err error) *ingest.CollectionReport {
	coverageKey := collectorRootCoverageKey(collectorName)
	return &ingest.CollectionReport{
		State:        ingest.OutcomeFailed,
		CoverageKeys: []string{coverageKey},
		Outcomes: []ingest.CollectionOutcome{{
			Collector:   collectorName,
			CoverageKey: coverageKey,
			Target:      collectorName,
			Method:      "collect",
			State:       ingest.OutcomeFailed,
			Error:       err.Error(),
		}},
	}
}

func collectConfig(
	ctx context.Context,
	path string,
	paths []string,
	projectDir string,
	includeCredValues bool,
	scanID string,
	engine *rules.Engine,
) (*ingest.IngestData, error) {
	c := configcollector.NewConfigCollector()
	opts := icollector.CollectOptions{
		Discover:                path == "" && len(paths) == 0,
		ConfigPath:              path,
		ConfigPaths:             paths,
		ProjectDir:              projectDir,
		IncludeCredentialValues: includeCredValues,
		ScanID:                  scanID,
		RulesEngine:             engine,
	}
	slog.Info("running config collector", "discover", opts.Discover, "path", path)
	return c.Collect(ctx, opts)
}

func collectMCP(
	ctx context.Context,
	url, projectDir string,
	concurrency int,
	timeout time.Duration,
	insecure bool,
	scanID string,
	engine *rules.Engine,
) (*ingest.IngestData, error) {
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
		ProjectDir:  projectDir,
		Insecure:    insecure,
		ScanID:      scanID,
		RulesEngine: engine,
	}
	logURL := ""
	if url != "" {
		logURL = ingest.SanitizeHTTPEndpoint(url).Display
	}
	slog.Info("running mcp collector", "discover", opts.Discover, "url", logURL)
	return c.Collect(ctx, opts)
}

func collectA2A(ctx context.Context, target string, targets []string, targetsFile, authToken string,
	concurrency int, timeout time.Duration, insecure bool,
	noVerifyJWKS bool, a2aTrustedKeys, scanID string,
	engine *rules.Engine,
) (*ingest.IngestData, error) {
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
	if noVerifyJWKS {
		a2aOpts = append(a2aOpts, a2acollector.WithJWKSFetch(false))
	}
	if a2aTrustedKeys != "" {
		a2aOpts = append(a2aOpts, a2acollector.WithTrustedKeysFile(a2aTrustedKeys))
	}

	c := a2acollector.NewA2ACollector(a2aOpts...)
	opts := icollector.CollectOptions{
		TargetURL:      target,
		TargetURLs:     targets,
		TargetURLsFile: targetsFile,
		AuthToken:      authToken,
		Insecure:       insecure,
		ScanID:         scanID,
		RulesEngine:    engine,
	}
	slog.Info("running a2a collector", "target", target, "targets", len(targets))
	return c.Collect(ctx, opts)
}

// runNetworkScan handles `agenthound scan <CIDR|host|@file>`. It runs the port
// sweep, dispatches fingerprint probes, and writes the combined scan-output
// JSON envelope.
//
// Safety controls in this path:
//   - --allow-public-targets gates public IP space AND requires the
//     interactive AUTHORIZED prompt below before the scan runs.
//   - --allow-large-cidr gates CIDRs larger than /16 (IPv4) or /112 (IPv6).
//   - --authorization-file is captured into the scan-output watermark
//     (path + SHA-256) so the operator has an auditable record of which
//     authorization document covered the scan.
//   - Link-local and multicast addresses are refused unconditionally (no
//     flag turns them on).
func runNetworkScan(cmd *cobra.Command, spec string) error {
	allowPublic, _ := cmd.Flags().GetBool("allow-public-targets")
	allowLarge, _ := cmd.Flags().GetBool("allow-large-cidr")
	ports, _ := cmd.Flags().GetIntSlice("ports")
	concurrency, _ := cmd.Flags().GetInt("network-scan-concurrency")
	authzFile, _ := cmd.Flags().GetString("authorization-file")
	timeout, _ := cmd.Flags().GetDuration("timeout")
	verbose, _ := cmd.Flags().GetBool("verbose")
	quiet := quietEnabled(cmd)
	concurrency = normalizeNetworkConcurrency(concurrency)
	timeoutChanged := cmd.Flags().Changed("timeout")
	tcpTimeout := resolveProbeTimeout(timeout, timeoutChanged)
	fingerprintTimeout := resolveFingerprintTimeout(timeout, timeoutChanged)

	// AUTHORIZED prompt — required whenever --allow-public-targets is set,
	// before any network IO. This keys solely on the flag, NOT on the spec:
	// it always prompts when the flag is present, even for a private/loopback
	// spec. The prompt is a deliberate fail-closed speed-bump (empty/EOF stdin
	// aborts); the real gate is Expand refusing public targets unless the flag
	// is set. For non-interactive automation, do not pass --allow-public-targets
	// for private scans — its only purpose is to authorize public IP space.
	if allowPublic {
		if err := requireAuthorizedPrompt(spec, cmd.OutOrStderr(), cmd.InOrStdin()); err != nil {
			return err
		}
	}

	// Authorization-file → watermark.
	var authzHash string
	if authzFile != "" {
		hash, err := sha256OfFile(authzFile)
		if err != nil {
			return fmt.Errorf("--authorization-file %s: %w", authzFile, err)
		}
		authzHash = hash
	}

	output, _ := cmd.Flags().GetString("scan-output")
	if output == "" {
		if cfg != nil && cfg.Output != "" {
			output = cfg.Output
		} else if v, _ := cmd.Root().PersistentFlags().GetString("output"); v != "" {
			output = v
		}
	}

	// Look up the registered network scanner. The module self-registers via
	// modules/networkscan/register.go; if it isn't found the binary was
	// linked without the module which is a build-time mistake.
	mod, ok := module.GetByTarget("network", action.Scan)
	if !ok {
		return errors.New("network scanner module not registered (build error)")
	}
	scanner, ok := mod.(action.Scanner)
	if !ok {
		return fmt.Errorf("registered network module %q is not a Scanner", mod.ID())
	}

	// Configure runtime overrides directly on the *networkscan.Scanner if
	// possible — avoids constructing a parallel options struct. We don't
	// type-assert here because module.Get returns the concrete value the
	// init() registered.
	reporter := newProgressReporter(cmd.OutOrStderr(), "[scan] probing "+spec, quiet)
	if ns, ok := mod.(*networkscan.Scanner); ok {
		if len(ports) > 0 {
			ns.Ports = ports
		}
		ns.Concurrency = concurrency
		ns.ExpandOpts = networkscan.ExpandOptions{
			AllowLargeCIDR:     allowLarge,
			AllowPublicTargets: allowPublic,
		}
		ns.Timeout = tcpTimeout
		ns.Progress = reporter.update
	}

	ctx, stop := signalContext()
	defer stop()
	if !quiet {
		_, _ = fmt.Fprintf(cmd.OutOrStderr(), "[scan] expanding targets: %s\n", spec)
	}
	targets, err := scanner.Scan(ctx, spec)
	reporter.clear()
	if err != nil && !errors.Is(err, context.Canceled) {
		return fmt.Errorf("scan: %w", err)
	}

	// Default output is a single summary line. The full per-host listing —
	// which can run to thousands of lines on a large sweep — is gated behind
	// --verbose. --quiet suppresses both.
	if !quiet {
		_, _ = fmt.Fprintf(cmd.OutOrStderr(),
			"[scan] %s: %d host(s) with at least one open port\n", spec, len(targets))
		switch {
		case verbose:
			for _, t := range targets {
				_, _ = fmt.Fprintf(cmd.OutOrStderr(),
					"[scan]   %s — open: %s — candidates: %s\n",
					t.Address, t.Meta["open_ports"], t.Meta["candidate_kinds"])
			}
		case len(targets) > 0:
			_, _ = fmt.Fprintf(cmd.OutOrStderr(),
				"[scan] (re-run with --verbose to list per-host open ports)\n")
		}
	}

	// Evaluate every registered fingerprinter on every open endpoint.
	// PortToKind is an ordering hint only, so a real service on a custom port is
	// still discoverable. Operationally indeterminate probes make this domain
	// partial and therefore cannot retire a previously observed service.
	envelope := buildNetworkScanEnvelope(spec, targets, authzFile, authzHash, allowPublic)
	_, ruleset := loadEffectiveRules()
	envelope.Meta.Ruleset = ruleset
	networkState := ingest.OutcomeComplete
	if ctx.Err() != nil {
		networkState = ingest.OutcomePartial
	}
	envelope.Meta.Collection = &ingest.CollectionReport{
		State:        networkState,
		CoverageKeys: []string{ingest.CanonicalCoverageKey("scan", "network", spec)},
		Outcomes: []ingest.CollectionOutcome{{
			Collector:   "scan",
			CoverageKey: ingest.CanonicalCoverageKey("scan", "network", spec),
			Target:      spec,
			Method:      "port_scan",
			State:       networkState,
			Items:       len(targets),
		}},
	}
	// On cancellation (Ctrl-C), every fingerprint probe would immediately fail
	// against the dead context, so skip dispatch and write the partial
	// port-sweep envelope instead of spinning through guaranteed-failing probes.
	if ctx.Err() != nil {
		if !quiet {
			_, _ = fmt.Fprintf(cmd.OutOrStderr(),
				"[scan] interrupted; skipping fingerprint dispatch and writing partial results\n")
		}
		envelope.Meta.Collection.Outcomes = append(envelope.Meta.Collection.Outcomes, ingest.CollectionOutcome{
			Collector: "scan", CoverageKey: envelope.Meta.Collection.CoverageKeys[0],
			Target: spec, Method: "fingerprint", State: ingest.OutcomePartial,
			Error: "fingerprint phase canceled before dispatch",
		})
	} else {
		dispatchFingerprints(
			ctx, cmd.OutOrStderr(), targets, envelope, quiet,
			normalizeFingerprintWorkers(concurrency), fingerprintTimeout, spec,
		)
	}
	envelope.Meta.Collection.State = ingest.AggregateOutcomeState(envelope.Meta.Collection.Outcomes)
	ingest.TagObservationDomain(&envelope.Graph, envelope.Meta.Collection.CoverageKeys[0])

	if output == "" {
		output = fmt.Sprintf("scan-%s.json", envelope.Meta.ScanID)
	}
	if output == "-" {
		return writeCollectorOutputStdout(envelope)
	}
	return writeCollectorOutput(envelope, output)
}

// buildNetworkScanEnvelope constructs the ingest envelope populated by the
// network scanner and subsequent fingerprint dispatch. The authorization
// watermark lets downstream analysis tools refuse to operate on public-target
// scans that lack an authorization record.
func buildNetworkScanEnvelope(spec string, targets []action.Target, authzFile, authzHash string, allowPublic bool) *ingest.IngestData {
	scanID := uuid.New().String()
	env := common.NewIngestData("scan", scanID)
	coverageKey := ingest.CanonicalCoverageKey("scan", "network", spec)
	env.Meta.Collection = &ingest.CollectionReport{
		State:        ingest.OutcomeComplete,
		CoverageKeys: []string{coverageKey},
		Outcomes: []ingest.CollectionOutcome{{
			Collector:   "scan",
			CoverageKey: coverageKey,
			Target:      spec,
			Method:      "port_scan",
			State:       ingest.OutcomeComplete,
			Items:       len(targets),
		}},
	}
	// Authorization watermark is recorded as a top-level Meta extension via
	// a property on the envelope. Fingerprinters append nodes/edges
	// to env.Graph; the watermark is independent of the graph payload.
	env.Meta.Extra = map[string]any{
		"network_scan_spec":    spec,
		"network_scan_targets": len(targets),
		"allow_public_targets": allowPublic,
	}
	if authzFile != "" {
		env.Meta.Extra["authorization_file_path"] = authzFile
		env.Meta.Extra["authorization_file_sha256"] = authzHash
	}
	return env
}

// requireAuthorizedPrompt blocks the scan until the operator types
// "AUTHORIZED" exactly. The prompt prints the spec being scanned so the
// operator gets a last-chance review of what they're about to do.
//
// Returns nil on a clean AUTHORIZED match; an error otherwise. The error
// message is intentionally dry — there's no useful retry path; the
// operator either had authorization or didn't.
func requireAuthorizedPrompt(spec string, stderr io.Writer, stdin io.Reader) error {
	_, _ = fmt.Fprintf(stderr, "\n")
	_, _ = fmt.Fprintf(stderr, "[scan] --allow-public-targets is set. About to scan: %s\n", spec)
	_, _ = fmt.Fprintf(stderr, "[scan] Scanning IP space without written authorization may violate CFAA-style laws.\n")
	_, _ = fmt.Fprintf(stderr, "[scan] If you have written authorization for these targets, type AUTHORIZED to proceed: ")
	r := bufio.NewReader(stdin)
	line, err := r.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("read authorization prompt: %w", err)
	}
	if strings.TrimSpace(line) != "AUTHORIZED" {
		return errors.New("authorization not confirmed; aborting scan")
	}
	_, _ = fmt.Fprintf(stderr, "[scan] authorization confirmed; proceeding\n")
	return nil
}

func sha256OfFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("read for hashing: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// dispatchFingerprints evaluates every registered fingerprinter once per open
// endpoint. Port mappings only prioritize likely matches. Failures are
// retained as partial fingerprint coverage rather than authoritative absence.
type fingerprintCandidate struct {
	id     string
	target string
	fp     action.Fingerprinter
}

type fingerprintTask struct {
	sequence  int
	host      string
	port      int
	meta      map[string]string
	candidate fingerprintCandidate
}

type fingerprintTaskResult struct {
	task   fingerprintTask
	result *action.FingerprintResult
	err    error
}

const maxFingerprintWorkers = 64

func normalizeFingerprintWorkers(value int) int {
	if value <= 0 {
		return min(networkscan.DefaultConcurrency, maxFingerprintWorkers)
	}
	return min(value, maxFingerprintWorkers)
}

func registeredFingerprinters() []fingerprintCandidate {
	var candidates []fingerprintCandidate
	for _, mod := range module.ListByAction(action.Fingerprint) {
		fp, ok := mod.(action.Fingerprinter)
		if !ok {
			continue
		}
		candidates = append(candidates, fingerprintCandidate{id: mod.ID(), target: mod.Target(), fp: fp})
	}
	return candidates
}

func orderedFingerprinters(port int, candidates []fingerprintCandidate) []fingerprintCandidate {
	var ordered []fingerprintCandidate
	used := make(map[string]bool)
	for _, hint := range networkscan.PortToKind[port] {
		for _, candidate := range candidates {
			if candidate.target == hint && !used[candidate.id] {
				ordered = append(ordered, candidate)
				used[candidate.id] = true
			}
		}
	}
	for _, candidate := range candidates {
		if !used[candidate.id] {
			ordered = append(ordered, candidate)
		}
	}
	return ordered
}

type fingerprintEndpoint struct {
	host string
	port int
	meta map[string]string
}

func fingerprintEndpoints(targets []action.Target) []fingerprintEndpoint {
	var endpoints []fingerprintEndpoint
	seen := make(map[string]bool)
	for _, target := range targets {
		for _, rawPort := range splitCSV(target.Meta["open_ports"]) {
			port, err := strconv.Atoi(rawPort)
			if err != nil || port < 1 || port > 65535 {
				continue
			}
			key := target.Address + "\x00" + strconv.Itoa(port)
			if seen[key] {
				continue
			}
			seen[key] = true
			endpoints = append(endpoints, fingerprintEndpoint{
				host: target.Address, port: port, meta: target.Meta,
			})
		}
	}
	return endpoints
}

func dispatchFingerprints(
	ctx context.Context,
	stderr io.Writer,
	targets []action.Target,
	envelope *ingest.IngestData,
	quiet bool,
	workers int,
	timeout time.Duration,
	scopeTarget string,
) {
	dispatchFingerprintCandidates(ctx, stderr, targets, envelope, quiet, workers, timeout, scopeTarget, registeredFingerprinters())
}

func dispatchFingerprintCandidates(
	ctx context.Context,
	stderr io.Writer,
	targets []action.Target,
	envelope *ingest.IngestData,
	quiet bool,
	workers int,
	timeout time.Duration,
	scopeTarget string,
	candidates []fingerprintCandidate,
) {
	workers = normalizeFingerprintWorkers(workers)
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	endpoints := fingerprintEndpoints(targets)
	total := len(endpoints) * len(candidates)
	reporter := newProgressReporter(stderr, "[scan] fingerprinting", quiet)
	coverageKey := envelope.Meta.Collection.CoverageKeys[0]
	if total == 0 {
		envelope.Meta.Collection.Outcomes = append(envelope.Meta.Collection.Outcomes, ingest.CollectionOutcome{
			Collector: "scan", CoverageKey: coverageKey, Target: scopeTarget,
			Method: "fingerprint", State: ingest.OutcomeComplete,
		})
		return
	}

	window := max(1, workers*2)
	jobs := make(chan fingerprintTask, workers)
	results := make(chan fingerprintTaskResult, workers)
	slots := make(chan struct{}, window)
	var workerWG sync.WaitGroup
	for range workers {
		workerWG.Add(1)
		go func() {
			defer workerWG.Done()
			for task := range jobs {
				if err := ctx.Err(); err != nil {
					results <- fingerprintTaskResult{task: task, err: err}
					continue
				}
				probeCtx, cancel := context.WithTimeout(ctx, timeout)
				result, err := task.candidate.fp.Fingerprint(probeCtx, action.Target{
					Kind: "host", Address: fmt.Sprintf("%s:%d", task.host, task.port),
					Meta: maps.Clone(task.meta),
				})
				cancel()
				results <- fingerprintTaskResult{task: task, result: result, err: err}
			}
		}()
	}

	producerDone := make(chan int, 1)
	go func() {
		sequence := 0
	producer:
		for _, endpoint := range endpoints {
			for _, candidate := range orderedFingerprinters(endpoint.port, candidates) {
				select {
				case slots <- struct{}{}:
				case <-ctx.Done():
					break producer
				}
				task := fingerprintTask{
					sequence: sequence, host: endpoint.host, port: endpoint.port,
					meta: endpoint.meta, candidate: candidate,
				}
				select {
				case jobs <- task:
					sequence++
				case <-ctx.Done():
					<-slots
					break producer
				}
			}
		}
		close(jobs)
		producerDone <- sequence
	}()
	go func() {
		workerWG.Wait()
		close(results)
	}()

	next := 0
	completed := 0
	matched := 0
	failures := 0
	pending := make(map[int]fingerprintTaskResult)
	flush := func(item fingerprintTaskResult) {
		completed++
		reporter.update(completed, total)
		if item.err != nil {
			failures++
			slog.Debug("fingerprint error", "module", item.task.candidate.id,
				"host", item.task.host, "port", item.task.port, "error", item.err)
			return
		}
		if item.result == nil {
			failures++
			slog.Debug("fingerprint returned nil result", "module", item.task.candidate.id,
				"host", item.task.host, "port", item.task.port)
			return
		}
		if !item.result.Matched {
			return
		}
		if item.result.IngestData == nil {
			failures++
			slog.Debug("matched fingerprint returned no ingest data", "module", item.task.candidate.id,
				"host", item.task.host, "port", item.task.port)
			return
		}
		matched++
		if !quiet {
			reporter.clear()
			_, _ = fmt.Fprintf(stderr, "[fingerprint] %s:%d → %s (version=%s, auth=%s)\n",
				item.task.host, item.task.port, item.result.ServiceKind,
				item.result.Version, item.result.AuthMethod)
		}
		envelope.Graph.Nodes = append(envelope.Graph.Nodes, item.result.IngestData.Graph.Nodes...)
		envelope.Graph.Edges = append(envelope.Graph.Edges, item.result.IngestData.Graph.Edges...)
	}
	for item := range results {
		pending[item.task.sequence] = item
		for {
			ready, ok := pending[next]
			if !ok {
				break
			}
			delete(pending, next)
			flush(ready)
			next++
			<-slots
		}
	}
	scheduled := <-producerDone
	unstarted := total - scheduled
	state := ingest.OutcomeComplete
	errorText := ""
	if failures > 0 || unstarted > 0 || ctx.Err() != nil {
		state = ingest.OutcomePartial
		errorText = fmt.Sprintf("%d probe(s) failed, %d not started", failures, max(0, unstarted))
	}
	envelope.Meta.Collection.Outcomes = append(envelope.Meta.Collection.Outcomes, ingest.CollectionOutcome{
		Collector: "scan", CoverageKey: coverageKey, Target: scopeTarget,
		Method: "fingerprint", State: state, Items: completed - failures, Error: errorText,
	})
	reporter.clear()
	if !quiet {
		_, _ = fmt.Fprintf(stderr, "[scan] fingerprint summary: %d probe(s), %d match(es)\n", completed, matched)
	}
}

// splitCSV is the no-op-on-empty companion of strings.Split. Returns nil
// for "" rather than [""], so callers can range without a special case.
func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}
