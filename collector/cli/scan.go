package cli

import (
	"context"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	configcollector "github.com/adithyan-ak/agenthound/modules/config"
	"github.com/adithyan-ak/agenthound/modules/jupyterfp"
	"github.com/adithyan-ak/agenthound/modules/networkscan"
	"github.com/adithyan-ak/agenthound/sdk/action"
	icollector "github.com/adithyan-ak/agenthound/sdk/collector"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/sdk/module"
	"github.com/adithyan-ak/agenthound/sdk/rules"
	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan [CIDR|host|@targets-file]",
	Short: "Collect, verify, and preserve AI infrastructure evidence in one pass",
	Long: `Run the autonomous collector. Local configuration and credentials are
always collected; an optional host, CIDR, or targets file adds network scope.
Active verification is the default. --stealth retains read-only collection and
exact configured authentication while disabling cross-target credential reuse,
model invocation, and mutation. The scan continuously checkpoints one JSON
artifact for later manual server ingestion.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runScan,
}

func init() {
	scanCmd.Flags().Bool("deep", false, "Collect bounded recursive and high-cost evidence")
	scanCmd.Flags().Bool("stealth", false, "Keep the scan read-only and disable credential reuse and active probes")
	scanCmd.Flags().Duration("timeout", 15*time.Minute, "Overall scan deadline")
	scanCmd.Flags().StringSlice("exclude", nil, "Never contact this exact hostname, IP, or CIDR (repeatable)")
	scanCmd.Flags().Bool("insecure", false, "Skip TLS certificate verification")
	scanCmd.Flags().String("output", "", "Write the scan to this file (default scan-<scan_id>.json)")
	scanCmd.Flags().Bool("quiet", false, "Suppress non-error progress and discovered-secret output")
	rootCmd.AddCommand(scanCmd)
}

func loadEffectiveRules() (*rules.Engine, *ingest.RulesetManifest) {
	var failures []string
	engine, err := rules.NewEngine(rules.LoadOptions{})
	if err != nil {
		manifest := ingest.EmptyRulesetManifest()
		manifest.LoadState = ingest.OutcomeFailed
		manifest.Errors = []string{"load builtin text rules: " + err.Error()}
		return nil, manifest
	}
	failures = append(failures, engine.LoadFailures()...)
	fingerprints, fingerprintErr := rules.LoadFingerprints()
	failures = append(failures, rules.FingerprintLoadFailures()...)
	if fingerprintErr != nil {
		failures = append(failures, "load fingerprint rules: "+fingerprintErr.Error())
	}
	effective, detectors, dispatchFailures := effectiveFingerprintSemantics(fingerprints)
	failures = append(failures, dispatchFailures...)
	manifest := rules.BuildManifestWithDetectors(engine.Rules(), effective, detectors, failures...)
	return engine, &manifest
}

func effectiveFingerprintSemantics(fingerprints []rules.FingerprintRule) ([]rules.FingerprintRule, []rules.CodeDetector, []string) {
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
				fingerprint.ID, jupyterfp.BundleOverrideID,
			))
		default:
			effective = append(effective, fingerprint)
		}
	}
	if jupyterOverridePresent {
		return effective, nil, failures
	}
	return effective, []rules.CodeDetector{jupyterfp.NativeDetectorDefinition()}, failures
}

func resolveInstructionRecursion(deep bool) (root string, isDeep bool, err error) {
	if !deep {
		return "", false, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", false, fmt.Errorf("--deep needs a home directory: %w", err)
	}
	absolute, err := filepath.Abs(home)
	if err != nil {
		return "", false, fmt.Errorf("resolve --deep home directory: %w", err)
	}
	return filepath.Clean(absolute), true, nil
}

func collectConfig(
	ctx context.Context,
	path string,
	paths []string,
	projectDir string,
	instructionRoot string,
	instructionDeep bool,
	scanID string,
	engine *rules.Engine,
) (*ingest.IngestData, error) {
	return configcollector.NewConfigCollector().Collect(ctx, icollector.CollectOptions{
		Discover: path == "" && len(paths) == 0, ConfigPath: path, ConfigPaths: paths,
		ProjectDir: projectDir, InstructionRecursiveRoot: instructionRoot,
		InstructionDeep: instructionDeep,
		ScanID:          scanID, RulesEngine: engine,
	})
}

type fingerprintCandidate struct {
	id      string
	target  string
	version string
	fp      action.Fingerprinter
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
		fingerprinter, ok := mod.(action.Fingerprinter)
		if !ok {
			continue
		}
		candidates = append(candidates, fingerprintCandidate{
			id: mod.ID(), target: mod.Target(), version: mod.Version(), fp: fingerprinter,
		})
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
			endpoints = append(endpoints, fingerprintEndpoint{host: target.Address, port: port, meta: target.Meta})
		}
	}
	return endpoints
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
	coverageKey := ingest.CollectorRootCoverageKey("scan")
	if len(endpoints) == 0 {
		envelope.Meta.Collection.Outcomes = append(envelope.Meta.Collection.Outcomes, ingest.CollectionOutcome{
			Collector: "scan", CoverageKey: coverageKey, Target: scopeTarget,
			Method: "fingerprint", State: ingest.OutcomeNotApplicable,
		})
		return
	}
	if len(candidates) == 0 {
		envelope.Meta.Collection.Outcomes = append(envelope.Meta.Collection.Outcomes, ingest.CollectionOutcome{
			Collector: "scan", CoverageKey: coverageKey, Target: scopeTarget,
			Method: "fingerprint", State: ingest.OutcomeFailed,
			Error: "no registered fingerprinters; zero probes scheduled",
		})
		return
	}

	jobs := make(chan fingerprintTask, workers)
	results := make(chan fingerprintTaskResult, workers)
	slots := make(chan struct{}, max(1, workers*2))
	var workerGroup sync.WaitGroup
	for range workers {
		workerGroup.Add(1)
		go func() {
			defer workerGroup.Done()
			for task := range jobs {
				if err := ctx.Err(); err != nil {
					results <- fingerprintTaskResult{task: task, err: err}
					continue
				}
				probeCtx, cancel := context.WithTimeout(ctx, timeout)
				result, err := task.candidate.fp.Fingerprint(probeCtx, action.Target{
					Kind: "host", Address: fmt.Sprintf("%s:%d", task.host, task.port), Meta: maps.Clone(task.meta),
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
				task := fingerprintTask{sequence: sequence, host: endpoint.host, port: endpoint.port, meta: endpoint.meta, candidate: candidate}
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
		workerGroup.Wait()
		close(results)
	}()

	next, completed, matched, failures := 0, 0, 0, 0
	pending := make(map[int]fingerprintTaskResult)
	flush := func(item fingerprintTaskResult) {
		completed++
		reporter.update(completed, total)
		if item.err != nil || item.result == nil {
			failures++
			return
		}
		if !item.result.Matched {
			return
		}
		if item.result.IngestData == nil {
			failures++
			return
		}
		matched++
		if !quiet {
			reporter.clear()
			_, _ = fmt.Fprintf(stderr, "[fingerprint] %s:%d → %s (version=%s, auth=%s)\n",
				item.task.host, item.task.port, item.result.ServiceKind, item.result.Version, item.result.AuthMethod)
		}
		graph := item.result.IngestData.Graph
		ingest.TagObservationDomain(&graph, coverageKey)
		envelope.Graph.Nodes = append(envelope.Graph.Nodes, graph.Nodes...)
		envelope.Graph.Edges = append(envelope.Graph.Edges, graph.Edges...)
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
	conclusive := completed - failures
	state := ingest.ProbeOutcomeState(total, conclusive)
	errorText := ""
	if state != ingest.OutcomeComplete {
		errorText = fmt.Sprintf("%d of %d probe(s) inconclusive (%d failed, %d not started)",
			total-conclusive, total, failures, max(0, total-scheduled))
	}
	envelope.Meta.Collection.Outcomes = append(envelope.Meta.Collection.Outcomes, ingest.CollectionOutcome{
		Collector: "scan", CoverageKey: coverageKey, Target: scopeTarget,
		Method: "fingerprint", State: state, Items: conclusive, Error: errorText,
	})
	reporter.clear()
	if !quiet {
		_, _ = fmt.Fprintf(stderr, "[scan] fingerprint summary: %d probe(s), %d match(es)\n", completed, matched)
	}
}

func splitCSV(value string) []string {
	if value == "" {
		return nil
	}
	return strings.Split(value, ",")
}
