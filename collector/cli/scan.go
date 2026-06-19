package cli

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	a2acollector "github.com/adithyan-ak/agenthound/modules/a2a"
	configcollector "github.com/adithyan-ak/agenthound/modules/config"
	mcpcollector "github.com/adithyan-ak/agenthound/modules/mcp"
	"github.com/adithyan-ak/agenthound/modules/networkscan"
	"github.com/adithyan-ak/agenthound/sdk/action"
	icollector "github.com/adithyan-ak/agenthound/sdk/collector"
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

	scanCmd.Flags().Int("scan-concurrency", 5, "Max parallel connections")
	scanCmd.Flags().Duration("timeout", 120*time.Second, "Timeout per server/agent")
	scanCmd.Flags().Bool("insecure", false, "Skip TLS verification")

	scanCmd.Flags().String("scan-output", "", "Write scan JSON to this path. Use '-' for stdout. Defaults to ./scan-<scan_id>.json in CWD.")

	// Network-scan mode flags (Phase 1).
	scanCmd.Flags().IntSlice("ports", nil, "Override the default AI-service port set (network mode only). Default: 11434, 8000, 6333, 5000, 4000, 8888, 3000.")
	scanCmd.Flags().Int("network-scan-concurrency", networkscan.DefaultConcurrency, "Max parallel TCP connect probes (network mode only)")
	scanCmd.Flags().Bool("allow-public-targets", false, "Allow scanning public (non-RFC1918) IP space. Requires interactive AUTHORIZED confirmation.")
	scanCmd.Flags().Bool("allow-large-cidr", false, "Allow scanning CIDRs larger than /16 (IPv4) or /112 (IPv6).")
	scanCmd.Flags().String("authorization-file", "", "Path to a written-authorization document. The path and SHA-256 are recorded in the scan-output watermark.")

	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	// Network-mode dispatch: when a positional CIDR/host/@file is supplied,
	// the scanner runs instead of the legacy collector flow. v0.2 Phase 1
	// emits target descriptors only; Phase 2 wires fingerprint dispatch
	// after the port sweep.
	if len(args) == 1 {
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

	merged, enabled, failed := collectAll(ctx, runConfig, runMCP, runA2A,
		path, paths, projectDir, includeCredValues,
		url, target, targets, targetsFile, authToken,
		concurrency, timeout, insecure)

	// Default behavior: if no --output set, auto-name to scan-<scan_id>.json in CWD.
	if output == "" {
		output = fmt.Sprintf("scan-%s.json", merged.Meta.ScanID)
	}

	_, _ = fmt.Fprintf(os.Stderr, "Collected %d nodes, %d edges\n", len(merged.Graph.Nodes), len(merged.Graph.Edges))

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

// collectAll runs each enabled collector and merges its output. It returns
// the merged envelope plus the count of enabled collectors and how many of
// them failed, so the caller can decide the exit code (total failure → non-
// zero, partial/empty success → zero).
func collectAll(ctx context.Context, runConfig, runMCP, runA2A bool,
	path string, paths []string, projectDir string, includeCredValues bool,
	url, target string, targets []string, targetsFile, authToken string,
	concurrency int, timeout time.Duration, insecure bool) (data *ingest.IngestData, enabled, failed int) {

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
		enabled++
		data, err := collectConfig(ctx, path, paths, projectDir, includeCredValues)
		if err != nil {
			failed++
			slog.Error("config collector failed", "error", err)
		} else {
			merged.Graph.Nodes = append(merged.Graph.Nodes, data.Graph.Nodes...)
			merged.Graph.Edges = append(merged.Graph.Edges, data.Graph.Edges...)
		}
	}

	if runMCP {
		enabled++
		data, err := collectMCP(ctx, url, concurrency, timeout, insecure)
		if err != nil {
			failed++
			slog.Error("mcp collector failed", "error", err)
		} else {
			merged.Graph.Nodes = append(merged.Graph.Nodes, data.Graph.Nodes...)
			merged.Graph.Edges = append(merged.Graph.Edges, data.Graph.Edges...)
		}
	}

	if runA2A {
		enabled++
		data, err := collectA2A(ctx, target, targets, targetsFile, authToken, concurrency, timeout, insecure)
		if err != nil {
			failed++
			slog.Error("a2a collector failed", "error", err)
		} else {
			merged.Graph.Nodes = append(merged.Graph.Nodes, data.Graph.Nodes...)
			merged.Graph.Edges = append(merged.Graph.Edges, data.Graph.Edges...)
		}
	}

	return merged, enabled, failed
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

// runNetworkScan handles `agenthound scan <CIDR|host|@file>`. v0.2 Phase 1
// runs the port sweep and writes the discovered targets to the scan-output
// JSON envelope. Fingerprint dispatch lands in Phase 2.
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

	// AUTHORIZED prompt — required when --allow-public-targets is set, before
	// any network IO. Skipped when the spec is a private/loopback host
	// because the public guard wouldn't block it anyway.
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
	if ns, ok := mod.(*networkscan.Scanner); ok {
		if len(ports) > 0 {
			ns.Ports = ports
		}
		ns.Concurrency = concurrency
		ns.ExpandOpts = networkscan.ExpandOptions{
			AllowLargeCIDR:     allowLarge,
			AllowPublicTargets: allowPublic,
		}
		if timeout > 0 {
			ns.Timeout = timeout
		}
	}

	ctx := context.Background()
	_, _ = fmt.Fprintf(cmd.OutOrStderr(), "[scan] expanding targets: %s\n", spec)
	targets, err := scanner.Scan(ctx, spec)
	if err != nil && !errors.Is(err, context.Canceled) {
		return fmt.Errorf("scan: %w", err)
	}

	_, _ = fmt.Fprintf(cmd.OutOrStderr(),
		"[scan] discovered %d host(s) with at least one open port\n", len(targets))
	for _, t := range targets {
		_, _ = fmt.Fprintf(cmd.OutOrStderr(),
			"[scan]   %s — open: %s — candidates: %s\n",
			t.Address, t.Meta["open_ports"], t.Meta["candidate_kinds"])
	}

	// Phase 2: fingerprint each target against its candidate kinds. The
	// scanner already classified open ports into candidate service kinds
	// (e.g. 11434 → "ollama"); we look up the registered fingerprinter
	// per kind, dispatch, and merge any matched ingest data into the
	// envelope. Targets with no fingerprinter (vLLM, Qdrant, MLflow,
	// Jupyter, LangServe, OpenWebUI in v0.2 — fingerprinters land in
	// v0.3/v0.4) emit no node; this is intentional per design F.
	envelope := buildNetworkScanEnvelope(spec, targets, authzFile, authzHash, allowPublic)
	dispatchFingerprints(ctx, cmd.OutOrStderr(), targets, envelope)

	if output == "" {
		output = fmt.Sprintf("scan-%s.json", envelope.Meta.ScanID)
	}
	if output == "-" {
		return writeCollectorOutputStdout(envelope)
	}
	return writeCollectorOutput(envelope, output)
}

// buildNetworkScanEnvelope constructs the v0.2 Phase 1 ingest envelope.
// Phase 1 emits no nodes — Phase 2 fingerprinters populate them based on
// the targets recorded here. The authorization block is the v0.2 watermark
// described in design doc 9.6: it lets downstream analysis tools refuse
// to operate on watermark-less public-target scans.
func buildNetworkScanEnvelope(spec string, targets []action.Target, authzFile, authzHash string, allowPublic bool) *ingest.IngestData {
	scanID := uuid.New().String()
	env := &ingest.IngestData{
		Meta: ingest.IngestMeta{
			Version:          1,
			Type:             "agenthound-ingest",
			Collector:        "scan",
			CollectorVersion: "0.2.0-dev",
			Timestamp:        time.Now().UTC().Format(time.RFC3339),
			ScanID:           scanID,
		},
	}
	// Authorization watermark is recorded as a top-level Meta extension via
	// a property on the envelope. Phase 2 fingerprinters append nodes/edges
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

// dispatchFingerprints walks the scanner's per-host targets, dispatches
// to each registered fingerprinter for the candidate kinds the scanner
// identified, and appends matched nodes/edges into envelope.Graph.
//
// Address for the fingerprinter is constructed as host:port — the
// scanner records open ports in t.Meta["open_ports"] and the candidate
// kind set in t.Meta["candidate_kinds"]. For each (host, port) where
// the kind has a registered fingerprinter, we run one probe.
//
// Failures are logged but never fatal: a misbehaving fingerprinter
// against one target should not block the rest of the scan.
func dispatchFingerprints(ctx context.Context, stderr io.Writer, targets []action.Target, envelope *ingest.IngestData) {
	matched := 0
	probed := 0
	for _, t := range targets {
		host := t.Address
		// open_ports is the authoritative per-host port list. We derive
		// the candidate kind per port here via networkscan.PortToKind
		// rather than trusting candidate_kinds, which only lists ports
		// that HAVE a kind mapping — for custom --ports with unmapped
		// ports the two lists desync by index, which would dispatch a
		// fingerprinter at the wrong port.
		ports := splitCSV(t.Meta["open_ports"])

		// Fingerprint each open port whose kind has a registered
		// fingerprinter. Ports with no PortToKind mapping (custom --ports)
		// or whose kind has no v0.2 fingerprinter (vLLM, Qdrant, MLflow,
		// Jupyter, LangServe, OpenWebUI) silently skip.
		for _, portStr := range ports {
			port, err := strconv.Atoi(portStr)
			if err != nil {
				continue
			}
			kind, ok := networkscan.PortToKind[port]
			if !ok {
				continue
			}
			mod, ok := module.GetByTarget(kind, action.Fingerprint)
			if !ok {
				continue
			}
			fp, ok := mod.(action.Fingerprinter)
			if !ok {
				continue
			}
			probed++
			result, err := fp.Fingerprint(ctx, action.Target{
				Kind:    "host",
				Address: fmt.Sprintf("%s:%s", host, portStr),
				Meta:    t.Meta,
			})
			if err != nil {
				slog.Debug("fingerprint error", "kind", kind, "host", host, "port", portStr, "error", err)
				continue
			}
			if !result.Matched || result.IngestData == nil {
				continue
			}
			matched++
			_, _ = fmt.Fprintf(stderr,
				"[fingerprint] %s:%s → %s (version=%s, auth=%s)\n",
				host, portStr, result.ServiceKind, result.Version, result.AuthMethod)
			envelope.Graph.Nodes = append(envelope.Graph.Nodes, result.IngestData.Graph.Nodes...)
			envelope.Graph.Edges = append(envelope.Graph.Edges, result.IngestData.Graph.Edges...)
		}
	}
	_, _ = fmt.Fprintf(stderr,
		"[scan] fingerprint summary: %d probe(s), %d match(es)\n", probed, matched)
}

// splitCSV is the no-op-on-empty companion of strings.Split. Returns nil
// for "" rather than [""], so callers can range without a special case.
func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}
