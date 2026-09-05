package cli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	a2acollector "github.com/adithyan-ak/agenthound/modules/a2a"
	mcpcollector "github.com/adithyan-ak/agenthound/modules/mcp"
	"github.com/adithyan-ak/agenthound/modules/mcppoison"
	"github.com/adithyan-ak/agenthound/modules/networkscan"
	"github.com/adithyan-ak/agenthound/modules/protoscan"
	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/checkpoint"
	icollector "github.com/adithyan-ak/agenthound/sdk/collector"
	"github.com/adithyan-ak/agenthound/sdk/common"
	"github.com/adithyan-ak/agenthound/sdk/contact"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
	sharedinstruction "github.com/adithyan-ak/agenthound/sdk/instruction"
	"github.com/spf13/cobra"
)

type scanRuntime struct {
	cmd             *cobra.Command
	ctx             context.Context
	policy          *contact.Policy
	artifact        *ingest.IngestData
	execution       *ingest.ScanExecution
	journal         *ingest.ScanJournal
	output          string
	rootKey         string
	targets         []action.Target
	configuredSeeds []string
	completed       map[string]bool
	printed         map[string]bool
	deep            bool
	stealth         bool
	insecure        bool
	quiet           bool
	explicitSpec    string
}

func runScan(cmd *cobra.Command, args []string) error {
	deep, _ := cmd.Flags().GetBool("deep")
	stealth, _ := cmd.Flags().GetBool("stealth")
	timeout, _ := cmd.Flags().GetDuration("timeout")
	exclusions, _ := cmd.Flags().GetStringSlice("exclude")
	insecure, _ := cmd.Flags().GetBool("insecure")
	output, _ := cmd.Flags().GetString("output")
	quiet := quietEnabled(cmd)
	if timeout <= 0 {
		return fmt.Errorf("--timeout must be greater than zero")
	}
	policy, err := contact.NewPolicy(exclusions)
	if err != nil {
		return fmt.Errorf("--exclude: %w", err)
	}

	signalCtx, stopSignals := signalContext()
	defer stopSignals()
	deadlineCtx, cancel := context.WithTimeout(signalCtx, timeout)
	defer cancel()
	ctx := contact.WithPolicy(deadlineCtx, policy)

	scanID := uuid.NewString()
	if strings.TrimSpace(output) == "" {
		if cfg != nil && strings.TrimSpace(cfg.Output) != "" {
			output = cfg.Output
		} else {
			output = "scan-" + scanID + ".json"
		}
	}
	if output == "-" {
		return fmt.Errorf("--output accepts a file path; stdout cannot provide recoverable checkpoints")
	}
	if info, statErr := os.Stat(output); statErr == nil && info.IsDir() {
		return fmt.Errorf("--output must be a file, got directory %s", output)
	} else if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return fmt.Errorf("inspect --output: %w", statErr)
	}
	if filepath.Base(output) == "." || filepath.Base(output) == string(filepath.Separator) {
		return fmt.Errorf("--output must name a file")
	}

	mode := ingest.ScanModeActive
	if stealth {
		mode = ingest.ScanModeStealth
	}
	now := time.Now().UTC()
	execution := ingest.NewScanExecution(mode, deep, now)
	execution.Exclusions = normalizedExclusions(exclusions)
	artifact := common.NewIngestData("scan", scanID)
	rootKey := ingest.CollectorRootCoverageKey("scan")
	artifact.Meta.Collection = &ingest.CollectionReport{
		State: ingest.OutcomePartial, CoverageKeys: []string{rootKey},
		Outcomes: []ingest.CollectionOutcome{{
			Collector: "scan", CoverageKey: rootKey, Target: "scan",
			Method: "autonomous_scan", State: ingest.OutcomePartial,
		}},
	}
	runtime := &scanRuntime{
		cmd: cmd, ctx: ctx, policy: policy, artifact: artifact, execution: execution,
		output: output, rootKey: rootKey, completed: make(map[string]bool),
		printed: make(map[string]bool), deep: deep, stealth: stealth,
		insecure: insecure, quiet: quiet,
	}
	journal, err := ingest.NewJournal(execution, func(*ingest.ScanExecution) error {
		return runtime.checkpoint()
	})
	if err != nil {
		return err
	}
	runtime.journal = journal
	if err := runtime.checkpoint(); err != nil {
		return fmt.Errorf("initial checkpoint: %w", err)
	}

	collectorTimeout := minDuration(120*time.Second, timeout)
	if err := runtime.collectLocal(collectorTimeout); err != nil {
		return runtime.finish(err)
	}
	if err := runtime.preflightExplicitTarget(args); err != nil {
		return runtime.finish(err)
	}
	if err := runtime.collectConfiguredMCP(collectorTimeout); err != nil {
		return runtime.finish(err)
	}
	if err := runtime.discoverAndFingerprint(); err != nil {
		return runtime.finish(err)
	}
	if err := runtime.collectDiscoveredProtocols(collectorTimeout); err != nil {
		return runtime.finish(err)
	}
	plannerErr := runtime.runPlanner(collectorTimeout)
	recoveryErr := runtime.retryUnresolvedRecovery()
	if recoveryErr != nil {
		return runtime.finish(errors.Join(plannerErr, recoveryErr))
	}
	if errors.Is(plannerErr, errCleanupUnresolved) {
		// A recovered cleanup failure still terminates this planner pass; later
		// observations must not be mixed with the uncertain mutation window.
		return runtime.finish(nil)
	}
	if plannerErr != nil {
		return runtime.finish(plannerErr)
	}
	return runtime.finish(nil)
}

func (r *scanRuntime) collectLocal(timeout time.Duration) error {
	root, recursive, err := resolveInstructionRecursion(r.deep)
	if err != nil {
		return err
	}
	engine, ruleset := loadEffectiveRules()
	r.artifact.Meta.Ruleset = ruleset
	data, collectErr := collectConfig(
		r.ctx, "", nil, "", root, recursive,
		r.artifact.Meta.ScanID, engine,
	)
	if collectErr != nil {
		r.addFailure("config", "local_collection", "local", collectErr)
	} else {
		r.merge(data)
	}
	if err := r.checkpoint(); err != nil {
		return fmt.Errorf("checkpoint local collection: %w", err)
	}
	r.printNewCredentials()
	r.printNewInstructionSignals()
	return nil
}

func (r *scanRuntime) collectConfiguredMCP(timeout time.Duration) error {
	specs, _, err := mcpcollector.DiscoverServerSpecs(r.ctx, "")
	if err != nil {
		r.addFailure("mcp", "discover_configs", "local", err)
		return r.checkpoint()
	}
	admitted := make([]mcpcollector.ServerSpec, 0, len(specs))
	for _, spec := range specs {
		if spec.Transport != "http" {
			admitted = append(admitted, spec)
			continue
		}
		if err := r.policy.AdmitAddress(spec.URL); err != nil {
			r.addOutcome(ingest.CollectionOutcome{
				Collector: "mcp", CoverageKey: ingest.CanonicalCoverageKey("mcp", "target", ingest.CanonicalURLScope(spec.URL)),
				Target: ingest.SanitizeHTTPEndpoint(spec.URL).Display, Method: "excluded",
				State: ingest.OutcomeNotApplicable, Error: "skipped by --exclude",
			})
			continue
		}
		admitted = append(admitted, spec)
		if seed, ok := configuredNetworkSeed(spec.URL); ok {
			r.configuredSeeds = append(r.configuredSeeds, seed)
		}
	}
	if len(admitted) > 0 {
		engine, _ := loadEffectiveRules()
		collector := mcpcollector.NewMCPCollector(
			mcpcollector.WithTimeout(timeout), mcpcollector.WithServerSpecs(admitted),
		)
		data, collectErr := collector.Collect(r.ctx, icollector.CollectOptions{
			ScanID: r.artifact.Meta.ScanID, Insecure: r.insecure, RulesEngine: engine,
		})
		if collectErr != nil {
			r.addFailure("mcp", "configured_enumeration", "configured", collectErr)
		} else {
			r.merge(data)
		}
	}
	if err := r.checkpoint(); err != nil {
		return fmt.Errorf("checkpoint configured MCP enumeration: %w", err)
	}
	r.printNewCredentials()
	return nil
}

func (r *scanRuntime) preflightExplicitTarget(args []string) error {
	if len(args) != 1 {
		return nil
	}
	r.explicitSpec = strings.TrimSpace(args[0])
	_, err := networkscan.Expand(r.explicitSpec, networkscan.ExpandOptions{
		AllowLargeCIDR: true, AllowPublicTargets: true,
	})
	if err == nil {
		return nil
	}
	rejection := fmt.Errorf("explicit target %q was rejected: %w", r.explicitSpec, err)
	r.addFailure("scan", "target_validation", r.explicitSpec, rejection)
	return rejection
}

func (r *scanRuntime) discoverAndFingerprint() error {
	specs := localScanSeeds()
	specs = append(specs, r.configuredSeeds...)
	if r.explicitSpec != "" {
		specs = append(specs, r.explicitSpec)
	}
	specs = uniqueSortedStrings(specs)
	candidates := registeredFingerprinters()
	for _, spec := range specs {
		if err := r.ctx.Err(); err != nil {
			return err
		}
		if isDirectDiscoverySpec(spec) {
			if err := r.policy.AdmitAddress(spec); errors.Is(err, contact.ErrExcluded) {
				r.recordExcludedDiscovery(spec)
				if checkpointErr := r.checkpoint(); checkpointErr != nil {
					return checkpointErr
				}
				continue
			}
		}
		explicit := r.explicitSpec != "" && spec == r.explicitSpec
		scanner := &networkscan.Scanner{
			Concurrency: networkscan.DefaultConcurrency,
			Timeout:     networkscan.DefaultProbeTimeout,
			ExpandOpts: networkscan.ExpandOptions{
				AllowLargeCIDR: true, AllowPublicTargets: true,
			},
			ContactPolicy: r.policy,
		}
		targets, err := scanner.Scan(r.ctx, spec)
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			r.addFailure("scan", "port_scan", spec, err)
			if checkpointErr := r.checkpoint(); checkpointErr != nil {
				return checkpointErr
			}
			if explicit {
				return fmt.Errorf("explicit target %q was rejected: %w", spec, err)
			}
			continue
		}
		report := scanner.LastReport()
		state := report.State()
		errorText := ""
		if state == ingest.OutcomeNotApplicable {
			errorText = "skipped by --exclude"
		} else if report.Unknown() > 0 {
			errorText = fmt.Sprintf("%d of %d TCP probes inconclusive", report.Unknown(), report.Total)
		}
		r.artifact.Meta.Collection.Outcomes = append(r.artifact.Meta.Collection.Outcomes, ingest.CollectionOutcome{
			Collector: "scan", CoverageKey: r.rootKey, Target: spec, Method: "port_scan",
			State: state, Items: len(targets), Error: errorText,
		})
		for _, target := range targets {
			r.addTarget(target.Kind, target.Address, target.Meta)
		}
		if err := r.checkpoint(); err != nil {
			return fmt.Errorf("checkpoint network discovery: %w", err)
		}
		dispatchFingerprintCandidates(
			r.ctx, r.cmd.ErrOrStderr(), targets, r.artifact, r.quiet,
			normalizeFingerprintWorkers(networkscan.DefaultConcurrency), 5*time.Second,
			spec, candidates,
		)
		if err := r.checkpoint(); err != nil {
			return fmt.Errorf("checkpoint fingerprints: %w", err)
		}

		protocolScanner := &protoscan.Scanner{
			Mode: protoscan.ModeBoth, Concurrency: protoscan.DefaultConcurrency,
			Timeout: protoscan.DefaultProbeTimeout, Insecure: r.insecure,
			ExpandOpts:    networkscan.ExpandOptions{AllowLargeCIDR: true, AllowPublicTargets: true},
			ContactPolicy: r.policy,
		}
		protocolTargets, protocolErr := protocolScanner.Scan(r.ctx, spec)
		if protocolErr != nil && !errors.Is(protocolErr, context.Canceled) && !errors.Is(protocolErr, context.DeadlineExceeded) {
			r.addFailure("scan", "protocol_discovery", spec, protocolErr)
			if explicit {
				if checkpointErr := r.checkpoint(); checkpointErr != nil {
					return checkpointErr
				}
				return fmt.Errorf("explicit target %q was rejected: %w", spec, protocolErr)
			}
		} else {
			report := protocolScanner.LastReport()
			errorText := ""
			if report.State() == ingest.OutcomeNotApplicable {
				errorText = "skipped by --exclude"
			}
			r.artifact.Meta.Collection.Outcomes = append(r.artifact.Meta.Collection.Outcomes, ingest.CollectionOutcome{
				Collector: "scan", CoverageKey: r.rootKey, Target: spec,
				Method: "protocol_discovery", State: report.State(), Items: len(protocolTargets), Error: errorText,
			})
			r.recordProtocolDiscoveries(protocolTargets)
		}
		if err := r.checkpoint(); err != nil {
			return fmt.Errorf("checkpoint protocol discovery: %w", err)
		}
	}
	return nil
}

func (r *scanRuntime) recordExcludedDiscovery(spec string) {
	for _, method := range []string{"port_scan", "protocol_discovery"} {
		r.addOutcome(ingest.CollectionOutcome{
			Collector: "scan", CoverageKey: r.rootKey, Target: spec, Method: method,
			State: ingest.OutcomeNotApplicable, Error: "skipped by --exclude",
		})
	}
}

func isDirectDiscoverySpec(spec string) bool {
	spec = strings.TrimSpace(spec)
	if strings.HasPrefix(spec, "@") || strings.HasPrefix(spec, "file://") {
		return false
	}
	_, err := netip.ParsePrefix(spec)
	return err != nil
}

func (r *scanRuntime) collectDiscoveredProtocols(timeout time.Duration) error {
	engine, _ := loadEffectiveRules()
	var mcpSpecs []mcpcollector.ServerSpec
	var a2aTargets []string
	for _, target := range r.targets {
		url := strings.TrimSpace(target.Meta["url"])
		if url == "" || r.policy.AdmitAddress(url) != nil {
			continue
		}
		switch target.Meta["protocol"] {
		case "mcp":
			mcpSpecs = append(mcpSpecs, mcpcollector.ServerSpec{Name: url, Transport: "http", URL: url})
		case "a2a":
			a2aTargets = append(a2aTargets, url)
		}
	}
	if len(mcpSpecs) > 0 {
		collector := mcpcollector.NewMCPCollector(
			mcpcollector.WithTimeout(timeout), mcpcollector.WithServerSpecs(mcpSpecs),
		)
		data, err := collector.Collect(r.ctx, icollector.CollectOptions{
			ScanID: r.artifact.Meta.ScanID, Insecure: r.insecure, RulesEngine: engine,
		})
		if err != nil {
			r.addFailure("mcp", "discovered_enumeration", "network", err)
		} else {
			r.merge(data)
		}
		if err := r.checkpoint(); err != nil {
			return fmt.Errorf("checkpoint discovered MCP enumeration: %w", err)
		}
	}
	if len(a2aTargets) > 0 {
		collector := a2acollector.NewA2ACollector(
			a2acollector.WithTimeout(timeout), a2acollector.WithInsecure(r.insecure),
		)
		data, err := collector.Collect(r.ctx, icollector.CollectOptions{
			TargetURLs: uniqueSortedStrings(a2aTargets), ScanID: r.artifact.Meta.ScanID,
			Insecure: r.insecure, RulesEngine: engine,
		})
		if err != nil {
			r.addFailure("a2a", "discovered_enumeration", "network", err)
		} else {
			r.merge(data)
		}
		if err := r.checkpoint(); err != nil {
			return fmt.Errorf("checkpoint discovered A2A enumeration: %w", err)
		}
	}
	r.printNewCredentials()
	return nil
}

func (r *scanRuntime) runPlanner(timeout time.Duration) error {
	actions := []PlannerAction{
		serviceCollectAction{timeout: minDuration(timeout, 30*time.Second)},
		a2aCredentialAction{insecure: r.insecure, timeout: minDuration(timeout, 30*time.Second)},
		credentialReachAction{insecure: r.insecure, timeout: minDuration(timeout, 30*time.Second)},
		contextForgeRoundTripAction{insecure: r.insecure, policy: r.policy},
		ollamaEmbeddingAction{timeout: minDuration(timeout, 30*time.Second)},
	}
	for {
		if err := r.ctx.Err(); err != nil {
			return err
		}
		view := buildPlannerView(r.artifact.Graph, r.publicTargets(), r.completed, r.deep, r.stealth)
		plannerAction, candidate, ok := nextPlannerCandidate(actions, view)
		if !ok {
			return nil
		}
		actionID := common.HashSHA256(candidate.Key)
		stamp := time.Now().UTC().Format(time.RFC3339Nano)
		targetID := candidate.Target.Meta["node_id"]
		if targetID == "" {
			targetID = canonicalTarget(candidate.Target.Address)
		}
		r.execution.Actions = append(r.execution.Actions, ingest.ActionRecord{
			ID: actionID, Action: plannerAction.ID(), TargetID: targetID,
			CredentialID: candidate.CredentialID, ResourceID: candidate.ResourceID,
			PathNodeIDs: append([]string(nil), candidate.PathNodeIDs...),
			Status:      ingest.ActionRunning, StartedAt: stamp,
		})
		if err := r.checkpoint(); err != nil {
			return fmt.Errorf("checkpoint action start: %w", err)
		}
		candidate.Inputs = cloneStringMap(candidate.Inputs)
		candidate.Inputs["action_id"] = actionID
		candidate.Inputs["scan_id"] = r.artifact.Meta.ScanID
		result, executeErr := plannerAction.Execute(r.ctx, candidate, r.journal)
		r.completed[candidate.Key] = true
		for _, outcome := range result.InventoryOutcomes {
			r.mergeInventoryOutcome(outcome)
		}
		r.artifact.Graph.Nodes = append(r.artifact.Graph.Nodes, result.Graph.Nodes...)
		r.artifact.Graph.Edges = append(r.artifact.Graph.Edges, result.Graph.Edges...)
		for _, target := range result.NewTargets {
			r.addTarget(target.Kind, target.Address, target.Meta)
		}
		record := &r.execution.Actions[len(r.execution.Actions)-1]
		record.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
		if executeErr != nil {
			record.Status = ingest.ActionFailed
			record.Error = executeErr.Error()
			record.Outcome = result.Outcome
			if record.Outcome == "" {
				record.Outcome = "failed"
			}
		} else {
			record.Status = ingest.ActionSucceeded
			record.Outcome = result.Outcome
		}
		if err := r.checkpoint(); err != nil {
			return fmt.Errorf("checkpoint action completion: %w", err)
		}
		r.printNewCredentials()
		if plannerMustStop(executeErr) {
			return executeErr
		}
	}
}

func plannerMustStop(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, errCleanupUnresolved) {
		return true
	}
	var checkpointErr *checkpoint.CheckpointError
	return errors.As(err, &checkpointErr)
}

func (r *scanRuntime) retryUnresolvedRecovery() error {
	var unresolved int
	for index := len(r.execution.Recovery) - 1; index >= 0; index-- {
		record := &r.execution.Recovery[index]
		if record.Status == ingest.RecoveryRestored {
			continue
		}
		if err := r.recoverRecord(record); err != nil {
			unresolved++
		}
		if err := r.checkpoint(); err != nil {
			return fmt.Errorf("checkpoint recovery attempt: %w", err)
		}
	}
	if unresolved > 0 {
		return fmt.Errorf("%d mutation recovery record(s) remain unresolved", unresolved)
	}
	return nil
}

func (r *scanRuntime) recoverRecord(record *ingest.RecoveryRecord) error {
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	record.UpdatedAt = stamp
	if record.Action != contextForgeActionID {
		record.Status = ingest.RecoveryFailed
		record.Error = "unsupported recovery action " + record.Action
		return errors.New(record.Error)
	}
	data, err := decodeContextForgeRecovery(*record)
	if err != nil {
		record.Status = ingest.RecoveryFailed
		record.Error = err.Error()
		return err
	}
	view := buildPlannerView(r.artifact.Graph, nil, r.completed, r.deep, r.stealth)
	token := ""
	for _, credentialID := range record.CredentialIDs {
		if value := normalizeBearer(view.Credentials[credentialID]); value != "" {
			token = value
			break
		}
	}
	if token == "" {
		err = errors.New("referenced ContextForge credential is unavailable")
		record.Status = ingest.RecoveryFailed
		record.Error = err.Error()
		return err
	}
	base := contact.WithPolicy(context.Background(), r.policy)
	base = mcppoison.WithToken(base, token)
	if data.Insecure {
		base = context.WithValue(base, action.RevertInsecureKey{}, true)
	}
	ctx, cancel := context.WithTimeout(base, perReceiptRevertTimeout)
	err = mcppoison.New().Revert(ctx, contextForgeReceiptFromRecovery(data))
	cancel()
	record.Status = recoveryStatus(err)
	switch record.Status {
	case ingest.RecoveryRestored:
		record.Error = ""
		return nil
	}
	record.Error = err.Error()
	return err
}

func recoveryStatus(err error) ingest.RecoveryStatus {
	switch {
	case err == nil:
		return ingest.RecoveryRestored
	case errors.Is(err, action.ErrRevertConflict):
		return ingest.RecoveryConflict
	case errors.Is(err, action.ErrRevertPartiallyVerified),
		errors.Is(err, action.ErrRevertIndeterminate),
		errors.Is(err, context.DeadlineExceeded),
		errors.Is(err, context.Canceled):
		return ingest.RecoveryIndeterminate
	default:
		return ingest.RecoveryFailed
	}
}

func (r *scanRuntime) finish(runErr error) error {
	now := time.Now().UTC()
	stamp := now.Format(time.RFC3339Nano)
	r.execution.UpdatedAt = stamp
	r.execution.CompletedAt = &stamp
	switch {
	case errors.Is(runErr, context.Canceled), errors.Is(runErr, context.DeadlineExceeded):
		r.execution.Status = ingest.ScanExecutionInterrupted
	case runErr != nil:
		r.execution.Status = ingest.ScanExecutionFailed
	default:
		r.execution.Status = ingest.ScanExecutionCompleted
	}
	if len(r.artifact.Meta.Collection.Outcomes) > 0 {
		switch {
		case runErr == nil && r.inventoryCoverageComplete():
			r.artifact.Meta.Collection.Outcomes[0].State = ingest.OutcomeComplete
			r.artifact.Meta.Collection.Outcomes[0].Error = ""
		case runErr == nil:
			r.artifact.Meta.Collection.Outcomes[0].State = ingest.OutcomePartial
			r.artifact.Meta.Collection.Outcomes[0].Error = "one or more service inventories were incomplete"
		case errors.Is(runErr, context.Canceled), errors.Is(runErr, context.DeadlineExceeded):
			r.artifact.Meta.Collection.Outcomes[0].State = ingest.OutcomePartial
		default:
			r.artifact.Meta.Collection.Outcomes[0].State = ingest.OutcomeFailed
			r.artifact.Meta.Collection.Outcomes[0].Error = runErr.Error()
		}
	}
	r.artifact.Meta.Collection.State = ingest.AggregateOutcomeState(r.artifact.Meta.Collection.Outcomes)
	checkpointErr := r.checkpoint()
	if !r.quiet {
		_, _ = fmt.Fprintf(r.cmd.ErrOrStderr(),
			"[scan] %s: %d nodes, %d edges, actions %d/%d, cleanup unresolved %d\n",
			r.execution.Status, len(r.artifact.Graph.Nodes), len(r.artifact.Graph.Edges),
			r.execution.Summary.ActionsSucceeded, r.execution.Summary.ActionsAttempted,
			r.execution.Summary.CleanupFailures,
		)
		_, _ = fmt.Fprintf(r.cmd.ErrOrStderr(), "[scan] artifact: %s\n", r.output)
		_, _ = fmt.Fprintf(r.cmd.ErrOrStderr(), "Next: agenthound-server ingest %s\n", r.output)
	}
	if checkpointErr != nil {
		return fmt.Errorf("final checkpoint: %w", checkpointErr)
	}
	if runErr != nil {
		return runErr
	}
	if r.execution.Summary.CleanupFailures > 0 {
		return fmt.Errorf("%d mutation recovery record(s) remain unresolved; run agenthound revert %s", r.execution.Summary.CleanupFailures, r.output)
	}
	return nil
}

func (r *scanRuntime) checkpoint() error {
	r.execution.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if err := ingest.SetScanExecution(&r.artifact.Meta, r.execution); err != nil {
		return err
	}
	document, err := marshalCollectorArtifact(r.artifact)
	if err != nil {
		return err
	}
	return checkpoint.Write(r.output, document)
}

func (r *scanRuntime) merge(data *ingest.IngestData) {
	if data == nil {
		return
	}
	r.artifact.Graph.Nodes = append(r.artifact.Graph.Nodes, data.Graph.Nodes...)
	r.artifact.Graph.Edges = append(r.artifact.Graph.Edges, data.Graph.Edges...)
	r.artifact.Meta.Collection = ingest.MergeCollectionReports(r.artifact.Meta.Collection, data.Meta.Collection)
}

func (r *scanRuntime) addFailure(collector, method, target string, err error) {
	r.addOutcome(ingest.CollectionOutcome{
		Collector: collector, CoverageKey: ingest.CanonicalCoverageKey(collector, method, target), Target: target, Method: method,
		State: ingest.OutcomeFailed, Error: err.Error(),
	})

}

func (r *scanRuntime) addOutcome(outcome ingest.CollectionOutcome) {
	if r.artifact.Meta.Collection == nil {
		r.artifact.Meta.Collection = &ingest.CollectionReport{}
	}
	declared := false
	for _, key := range r.artifact.Meta.Collection.CoverageKeys {
		if key == outcome.CoverageKey {
			declared = true
			break
		}
	}
	if !declared {
		r.artifact.Meta.Collection.CoverageKeys = append(
			r.artifact.Meta.Collection.CoverageKeys,
			outcome.CoverageKey,
		)
		sort.Strings(r.artifact.Meta.Collection.CoverageKeys)
	}
	r.artifact.Meta.Collection.Outcomes = append(r.artifact.Meta.Collection.Outcomes, outcome)
	r.artifact.Meta.Collection.State = ingest.AggregateOutcomeState(r.artifact.Meta.Collection.Outcomes)
}

// mergeInventoryOutcome keeps one finalized outcome per service inventory.
// A complete authoritative attempt wins over failed credential guesses; until
// then, partial/truncated evidence remains non-authoritative.
func (r *scanRuntime) mergeInventoryOutcome(outcome ingest.CollectionOutcome) {
	if r.artifact.Meta.Collection == nil {
		r.artifact.Meta.Collection = &ingest.CollectionReport{}
	}
	defer func() {
		r.artifact.Meta.Collection.State = ingest.AggregateOutcomeState(
			r.artifact.Meta.Collection.Outcomes,
		)
	}()
	declared := false
	for _, key := range r.artifact.Meta.Collection.CoverageKeys {
		if key == outcome.CoverageKey {
			declared = true
			break
		}
	}
	if !declared {
		r.artifact.Meta.Collection.CoverageKeys = append(
			r.artifact.Meta.Collection.CoverageKeys,
			outcome.CoverageKey,
		)
		sort.Strings(r.artifact.Meta.Collection.CoverageKeys)
	}
	for index := range r.artifact.Meta.Collection.Outcomes {
		current := &r.artifact.Meta.Collection.Outcomes[index]
		if current.CoverageKey != outcome.CoverageKey {
			continue
		}
		if current.State == ingest.OutcomeComplete {
			return
		}
		if outcome.State == ingest.OutcomeComplete {
			*current = outcome
			return
		}
		state := ingest.AggregateOutcomeState([]ingest.CollectionOutcome{*current, outcome})
		current.State = state
		if outcome.Items > current.Items {
			current.Items = outcome.Items
		}
		if outcome.Error != "" && !strings.Contains(current.Error, outcome.Error) {
			if current.Error != "" {
				current.Error += "; "
			}
			current.Error += outcome.Error
		}
		return
	}
	r.artifact.Meta.Collection.Outcomes = append(r.artifact.Meta.Collection.Outcomes, outcome)
}

func (r *scanRuntime) inventoryCoverageComplete() bool {
	if r.artifact.Meta.Collection == nil {
		return true
	}
	for _, outcome := range r.artifact.Meta.Collection.Outcomes {
		if !strings.HasPrefix(outcome.Method, "service_inventory:") {
			continue
		}
		if outcome.State != ingest.OutcomeComplete {
			return false
		}
	}
	return true
}

func (r *scanRuntime) recordProtocolDiscoveries(targets []action.Target) {
	targets = append([]action.Target(nil), targets...)
	sort.Slice(targets, func(i, j int) bool {
		left := targets[i].Meta["protocol"] + "\x00" + targets[i].Meta["url"] + "\x00" + targets[i].Address
		right := targets[j].Meta["protocol"] + "\x00" + targets[j].Meta["url"] + "\x00" + targets[j].Address
		return left < right
	})
	graph := protoscan.EmitDiscoveryNodes(targets)
	ingest.TagObservationDomain(&graph, r.rootKey)
	r.artifact.Graph.Nodes = append(r.artifact.Graph.Nodes, graph.Nodes...)
	r.artifact.Graph.Edges = append(r.artifact.Graph.Edges, graph.Edges...)
	for _, target := range targets {
		r.addTarget(target.Kind, target.Address, target.Meta)
	}
}

func (r *scanRuntime) addTarget(kind, address string, metadata map[string]string) {
	contactAddress := strings.TrimSpace(metadata["url"])
	if contactAddress == "" {
		contactAddress = strings.TrimSpace(address)
	}
	if contactAddress != "" && r.policy != nil {
		if err := r.policy.AdmitAddress(contactAddress); err != nil {
			return
		}
	}
	target := action.Target{Kind: kind, Address: address, Meta: cloneStringMap(metadata)}
	key := kind + "\x00" + metadata["protocol"] + "\x00" + canonicalTarget(metadata["url"]+address)
	for _, existing := range r.targets {
		existingKey := existing.Kind + "\x00" + existing.Meta["protocol"] + "\x00" + canonicalTarget(existing.Meta["url"]+existing.Address)
		if existingKey == key {
			return
		}
	}
	r.targets = append(r.targets, target)
}

func (r *scanRuntime) publicTargets() []action.Target {
	out := make([]action.Target, 0, len(r.targets))
	for _, target := range r.targets {
		out = append(out, action.Target{Kind: target.Kind, Address: target.Address, Meta: cloneStringMap(target.Meta)})
	}
	return out
}

func (r *scanRuntime) printNewCredentials() {
	if r.quiet {
		return
	}
	view := buildPlannerView(r.artifact.Graph, nil, r.completed, r.deep, r.stealth)
	ids := make([]string, 0, len(view.Credentials))
	for id := range view.Credentials {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		value := view.Credentials[id]
		hash := common.HashCredentialValue(value)
		if r.printed[hash] {
			continue
		}
		r.printed[hash] = true
		_, _ = fmt.Fprintf(r.cmd.OutOrStdout(), "[credential] %s\n", value)
	}
}

func (r *scanRuntime) printNewInstructionSignals() {
	if r.quiet {
		return
	}
	type printable struct {
		id       string
		path     string
		verdict  sharedinstruction.Verdict
		scope    sharedinstruction.Scope
		evidence sharedinstruction.Evidence
	}
	var findings []printable
	for _, node := range r.artifact.Graph.Nodes {
		if !containsString(node.Kinds, "InstructionFile") {
			continue
		}
		rawEvidence, _ := node.Properties["instruction_evidence_json"].(string)
		evidence, err := sharedinstruction.ParseEvidenceJSON(rawEvidence)
		if err != nil || evidence.Verdict == sharedinstruction.VerdictClean || len(evidence.Signals) == 0 {
			continue
		}
		findings = append(findings, printable{
			id: node.ID, path: stringProperty(node.Properties, "path"), verdict: evidence.Verdict,
			scope: sharedinstruction.Scope(stringProperty(node.Properties, "instruction_scope")), evidence: evidence,
		})
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].path < findings[j].path })
	for _, finding := range findings {
		key := "instruction:" + finding.id
		if r.printed[key] {
			continue
		}
		r.printed[key] = true
		primary := finding.evidence.Signals[0]
		kind := "instruction-signal"
		if finding.verdict == sharedinstruction.VerdictPoisoning && finding.scope != sharedinstruction.ScopeDeep {
			kind = "instruction-poisoning"
		}
		excerpt := strings.Join(strings.Fields(primary.Match), " ")
		if len(excerpt) > 120 {
			excerpt = excerpt[:120] + "…"
		}
		additional := ""
		if finding.evidence.TotalSignals > 1 {
			additional = fmt.Sprintf(" +%d", finding.evidence.TotalSignals-1)
		}
		_, _ = fmt.Fprintf(r.cmd.OutOrStdout(), "[%s] %s:%d %s %q%s\n",
			kind, finding.path, primary.Line, primary.RuleID, excerpt, additional)
	}
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func localScanSeeds() []string {
	seeds := []string{"127.0.0.1", "::1"}
	interfaces, err := net.Interfaces()
	if err != nil {
		return seeds
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			ip, _, err := net.ParseCIDR(address.String())
			if err != nil || ip == nil || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
				continue
			}
			seeds = append(seeds, ip.String())
		}
	}
	return uniqueSortedStrings(seeds)
}

func configuredNetworkSeed(rawURL string) (string, bool) {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" {
		return "", false
	}
	return parsed.Hostname(), true
}

func uniqueSortedStrings(values []string) []string {
	seen := make(map[string]bool, len(values))
	var out []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func normalizedExclusions(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if prefix, err := netip.ParsePrefix(value); err == nil {
			value = prefix.Masked().String()
		} else if address, err := netip.ParseAddr(strings.Trim(value, "[]")); err == nil {
			value = address.Unmap().String()
		} else {
			value = contact.NormalizeHostname(value)
		}
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func minDuration(left, right time.Duration) time.Duration {
	if left <= 0 {
		return right
	}
	if right <= 0 || left < right {
		return left
	}
	return right
}
