// Package mcproundtrip implements the reversible mcppoison round-trip
// campaign scenario — a STANDALONE target-mutation validation.
//
// It reuses modules/mcppoison (Poison + the conflict-aware, no-blind-write
// Revert) through the sdk/campaign Scenario interface to prove the reversible
// mutation machinery works end to end against a real target:
//
//  1. apply the operator-authorized mutation (Poison, committed);
//  2. re-read the exact live state and compare it to the receipt — the ORACLE
//     (did the mutation land?);
//  3. issue the conflict-aware revert;
//  4. re-read again and confirm the original is restored — the CLEANUP.
//
// The oracle and cleanup outcomes are reported SEPARATELY and are computed
// independently: a verified mutation that then fails to clean up (for example a
// third party edits the target between the oracle re-read and the revert) is
// reported honestly rather than masked.
//
// Scope and honesty. This scenario is explicitly NOT an attack finding and makes
// NO claim about any predicted credential path — it validates only reversible
// mutation. Representation choice: it emits NO new graph edge kind. A dedicated
// MCPServer->MCPTool edge would cascade churn across kinds/graphmeta/generated.ts
// /model_test/dto/styles/semantics/lens/parity for a validation that must never
// become a finding, so the round-trip evidence stays in the campaign transport
// (campaign.RunReport). Rollback reuses Phase A (per-file LIFO +
// conflict-aware revert): the mutation persists a receipt under the shared
// mcp.poison state dir, so a revert that cannot complete inline is retried later
// by `agenthound revert <engagement>`.
//
// The scenario self-registers under ID "mcp-poison-roundtrip"; the collector
// binary blank-imports this package (collector/cmd/agenthound/main.go).
package mcproundtrip

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/adithyan-ak/agenthound/modules/mcppoison"
	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/campaign"
)

const (
	scenarioID      = "mcp-poison-roundtrip"
	scenarioVersion = 2
)

// Scenario is the reversible mcppoison round-trip validation.
type Scenario struct {
	// newRoundTrip builds the round-trip primitives for a run. Nil selects the
	// real mcppoison-backed implementation; tests override it with a fake to
	// drive the oracle/cleanup matrix deterministically.
	newRoundTrip func(in campaign.RunInput, cfg config) (roundTrip, error)
}

func init() { campaign.Register(&Scenario{}) }

func (s *Scenario) ID() string   { return scenarioID }
func (s *Scenario) Version() int { return scenarioVersion }
func (s *Scenario) Description() string {
	return "Reversible ContextForge MCP round-trip (STANDALONE target-mutation validation): " +
		"generated inert marker, MCP-visible oracle, conflict-aware revert, " +
		"restored-state cleanup — oracle and cleanup reported separately. Not an attack finding."
}

// RequiresWitness reports that this scenario does NOT consume a credential-reach
// witness (it validates reversible mutation, not a predicted credential path).
// The campaign CLI reads this optional capability so it neither demands a
// witness nor reads out-of-band credential material for a mutation round-trip;
// it takes its mutation parameters from RunInput.Params instead.
func (s *Scenario) RequiresWitness() bool { return false }

// RequiresMutationConsent marks this scenario for the CLI's distinct
// poison/destructive acknowledgement gate.
func (s *Scenario) RequiresMutationConsent() bool { return true }

// config is the parsed ContextForge adapter configuration read from
// RunInput.Params. The adapter derives and validates all endpoint paths and
// generates the inert round-trip marker internally.
type config struct {
	targetID      string
	adapter       string
	managementURL string
}

// Run executes the round-trip. On a dry run it plans only and never mutates.
// Precondition failures (missing target-id or unsupported adapter) return an error
// before anything is touched.
func (s *Scenario) Run(ctx context.Context, in campaign.RunInput) (*campaign.RunResult, error) {
	cfg, err := parseConfig(in)
	if err != nil {
		return nil, err
	}

	if !in.Commit {
		return &campaign.RunResult{DryRun: true, Plan: planText(in, cfg)}, nil
	}

	runID := strings.TrimSpace(in.RunID)
	if runID == "" {
		runID = uuid.NewString()
	}
	// The run ID exists before mutator construction. The orchestrator assigns
	// StepSequence immediately before each mutator invocation.
	in.RunID = runID
	factory := s.newRoundTrip
	if factory == nil {
		factory = newMCPRoundTrip
	}
	rt, err := factory(in, cfg)
	if err != nil {
		return nil, fmt.Errorf("mcp-poison-roundtrip: build round-trip: %w", err)
	}

	report, runErr := runRoundtrip(ctx, in, cfg, rt)
	return &campaign.RunResult{Report: report}, runErr
}

// runRoundtrip performs the mutate -> oracle -> revert -> cleanup sequence and
// classifies the oracle and cleanup INDEPENDENTLY.
func runRoundtrip(
	ctx context.Context,
	in campaign.RunInput,
	cfg config,
	rt roundTrip,
) (*campaign.RunReport, error) {
	elapsedLimit := in.Timeout
	if elapsedLimit <= 0 {
		elapsedLimit = 30 * time.Second
	}
	runCtx, cancel, budget := campaign.NewBudgetContext(ctx, campaign.RunLimits{
		RequestLimit: 64, MutationLimit: 2, ElapsedLimit: elapsedLimit,
	})
	defer cancel()
	now := in.Clock()
	runStarted := now().UTC()
	report := &campaign.RunReport{
		ReportVersion:    campaign.RunReportVersion,
		ScenarioID:       scenarioID,
		ScenarioVersion:  scenarioVersion,
		CampaignRunID:    in.RunID,
		EngagementID:     in.EngagementID,
		Standalone:       true,
		MutationTargetID: cfg.targetID,
		TargetRef:        campaign.SanitizedTargetReference(in.Host),
		StartedAt:        runStarted.Format(time.RFC3339Nano),
		Steps:            []campaign.StepObservation{},
		Cleanup: campaign.CleanupReport{
			Status: campaign.CleanupIndeterminate, Postcondition: "unconfirmed",
		},
	}
	report.AddStepAt(
		campaign.StepAuthorizeMutation,
		campaign.OperationAuthorization,
		"authorized",
		runStarted,
		now(),
	)

	mutateStarted := now()
	if err := campaign.ConsumeMutation(runCtx); err != nil {
		report.AddStepAt(
			campaign.StepMutate,
			campaign.OperationTargetMutation,
			"budget_exhausted",
			mutateStarted,
			now(),
		)
		addInstantStep(report, now, campaign.StepVerifyInjected, campaign.OperationTargetVerification, "not_run")
		addInstantStep(report, now, campaign.StepRevert, campaign.OperationCleanup, "not_run")
		addInstantStep(report, now, campaign.StepVerifyOriginal, campaign.OperationTargetVerification, "unconfirmed")
		report.Oracle = campaign.OracleReport{
			Type:        campaign.OracleTypeReversibleMutationRoundtrip,
			Observation: "budget_exhausted", Outcome: string(campaign.OracleIndeterminate),
		}
		forwardBudget, _ := budget.FreezeForward(runCtx)
		cancel()
		finishReport(report, forwardBudget, now)
		return report, err
	}

	// StepSequence is assigned by this single run orchestrator immediately
	// before invoking the mutator that persists the receipt.
	receipt, mutateErr := rt.Mutate(runCtx, 1)
	mutateCompleted := now()
	if errors.Is(mutateErr, mcppoison.ErrNoMutation) && receipt == nil {
		report.AddStepAt(
			campaign.StepMutate,
			campaign.OperationTargetMutation,
			string(campaign.OracleMutationNotApplied),
			mutateStarted,
			mutateCompleted,
		)
	} else if mutateErr != nil {
		report.AddStepAt(
			campaign.StepMutate,
			campaign.OperationTargetMutation,
			"failed",
			mutateStarted,
			mutateCompleted,
		)
	} else {
		report.AddStepAt(
			campaign.StepMutate,
			campaign.OperationTargetMutation,
			"applied",
			mutateStarted,
			mutateCompleted,
		)
	}
	report.Cleanup.ReceiptRetained = receipt != nil
	if receipt != nil {
		report.LinkReceipt(receipt.ReceiptID)
	}

	if errors.Is(mutateErr, mcppoison.ErrNoMutation) && receipt == nil {
		addInstantStep(
			report,
			now,
			campaign.StepVerifyInjected,
			campaign.OperationTargetVerification,
			string(campaign.OracleMutationNotApplied),
		)
		report.Oracle = campaign.OracleReport{
			Type:        campaign.OracleTypeReversibleMutationRoundtrip,
			Observation: string(campaign.OracleMutationNotApplied),
			Outcome:     string(campaign.OracleMutationNotApplied),
		}
		forwardBudget, forwardErr := budget.FreezeForward(runCtx)
		cancel()
		addInstantStep(
			report,
			now,
			campaign.StepRevert,
			campaign.OperationCleanup,
			string(campaign.CleanupNotApplicable),
		)
		addInstantStep(
			report,
			now,
			campaign.StepVerifyOriginal,
			campaign.OperationTargetVerification,
			"not_applicable",
		)
		report.Cleanup = campaign.CleanupReport{
			Status: campaign.CleanupNotApplicable, Postcondition: "not_applicable",
			ReceiptRetained: false,
		}
		finishReport(report, forwardBudget, now)
		if forwardErr != nil {
			return report, forwardErr
		}
		return report, mcppoison.ErrNoMutation
	}
	if mutateErr != nil && receipt == nil {
		addInstantStep(
			report,
			now,
			campaign.StepVerifyInjected,
			campaign.OperationTargetVerification,
			string(campaign.OracleMutationNotApplied),
		)
		report.Oracle = campaign.OracleReport{
			Type:        campaign.OracleTypeReversibleMutationRoundtrip,
			Observation: string(campaign.OracleMutationNotApplied),
			Outcome:     string(campaign.OracleMutationNotApplied),
		}
		forwardBudget, forwardErr := budget.FreezeForward(runCtx)
		cancel()
		addInstantStep(report, now, campaign.StepRevert, campaign.OperationCleanup, string(campaign.CleanupNotApplicable))
		addInstantStep(report, now, campaign.StepVerifyOriginal, campaign.OperationTargetVerification, "mutation_not_applied")
		report.Cleanup = campaign.CleanupReport{
			Status: campaign.CleanupNotApplicable, Postcondition: "mutation_not_applied",
			ReceiptRetained: false,
		}
		finishReport(report, forwardBudget, now)
		if forwardErr != nil {
			return report, forwardErr
		}
		return report, fmt.Errorf("%w: %v", campaign.ErrMutationFailed, mutateErr)
	}

	verifyInjectedStarted := now()
	oracle := campaign.OracleIndeterminate
	if receipt != nil && mutateErr == nil {
		oracle = classifyOracle(runCtx, rt, receipt)
	}
	report.AddStepAt(
		campaign.StepVerifyInjected,
		campaign.OperationTargetVerification,
		string(oracle),
		verifyInjectedStarted,
		now(),
	)
	report.Oracle = campaign.OracleReport{
		Type:        campaign.OracleTypeReversibleMutationRoundtrip,
		Observation: string(oracle),
		Outcome:     string(oracle),
	}

	// Freeze every forward-run counter and the exhaustion decision before
	// creating the separately bounded cleanup context. Cleanup duration and
	// requests cannot consume or flip the forward budget.
	forwardBudget, forwardErr := budget.FreezeForward(runCtx)
	cancel()
	cleanupCtx, cleanupCancel := budget.CleanupContext(90 * time.Second)
	defer cleanupCancel()
	revertStarted := now()
	cleanup := executeRunCleanup(cleanupCtx, in, rt, receipt)
	report.AddStepAt(
		campaign.StepRevert,
		campaign.OperationCleanup,
		string(cleanup.Status),
		revertStarted,
		now(),
	)

	verifyOriginalStarted := now()
	postcondition := "unconfirmed"
	if cleanup.Status == campaign.CleanupRestored &&
		(cleanup.ReceiptsSelected < 1 || receipt == nil) {
		cleanup.Status = campaign.CleanupIndeterminate
	}
	if cleanup.Status == campaign.CleanupRestored {
		observation, err := rt.Observe(cleanupCtx, receipt)
		switch {
		case err != nil:
			cleanup.Status = campaign.CleanupFailed
			postcondition = "reread_failed"
		case !restorationConfirmed(observation, receipt):
			cleanup.Status = campaign.CleanupFailed
			postcondition = "original_mismatch"
		case !observation.Associated:
			postcondition = "original_management_confirmed_mcp_unavailable"
		default:
			postcondition = "original_confirmed"
		}
	}
	report.AddStepAt(
		campaign.StepVerifyOriginal,
		campaign.OperationTargetVerification,
		postcondition,
		verifyOriginalStarted,
		now(),
	)
	report.Cleanup = campaign.CleanupReport{
		Status:          cleanup.Status,
		Postcondition:   postcondition,
		ReceiptRetained: cleanup.ReceiptsRetained || receipt != nil,
	}
	finishReport(report, forwardBudget, now)

	if cleanup.Status != campaign.CleanupRestored {
		return report, campaign.ErrUnsafeCleanup
	}
	if mutateErr != nil {
		return report, campaign.ErrMutationFailed
	}
	if oracle != campaign.OracleMutationVerified {
		return report, campaign.ErrMutationFailed
	}
	if forwardErr != nil {
		return report, forwardErr
	}
	return report, nil
}

func executeRunCleanup(
	ctx context.Context,
	in campaign.RunInput,
	rt roundTrip,
	receipt *action.PoisonReceipt,
) campaign.CleanupExecution {
	if in.CleanupRun != nil {
		return in.CleanupRun(ctx, in.EngagementID, in.RunID)
	}
	// Test-only/local fallback. The production CLI always supplies the
	// authoritative cross-module cleanup orchestrator.
	if receipt == nil {
		return campaign.CleanupExecution{
			Status: campaign.CleanupIndeterminate, FailureCode: "receipt_missing",
		}
	}
	if err := campaign.ConsumeMutation(ctx); err != nil {
		return campaign.CleanupExecution{
			Status: campaign.CleanupIndeterminate, ReceiptsSelected: 1,
			ReceiptsRetained: true, FailureCode: "mutation_budget",
		}
	}
	status := classifyCleanup(ctx, rt, receipt)
	return campaign.CleanupExecution{
		Status: status, ReceiptsSelected: 1, ReceiptsRetained: true,
	}
}

func finishReport(report *campaign.RunReport, budget campaign.BudgetReport, now func() time.Time) {
	report.CompletedAt = now().UTC().Format(time.RFC3339Nano)
	report.Budget = budget
}

func addInstantStep(
	report *campaign.RunReport,
	now func() time.Time,
	step campaign.StepName,
	operationClass campaign.OperationClass,
	observation string,
) {
	at := now()
	report.AddStepAt(step, operationClass, observation, at, at)
}

// classifyOracle re-reads the live state after the mutation and decides whether
// the injection landed, comparing against the receipt.
func classifyOracle(ctx context.Context, rt roundTrip, r *action.PoisonReceipt) campaign.RoundtripOracle {
	if r.OriginalContent == r.InjectedContent {
		return campaign.OracleMutationNotApplied
	}
	observation, err := rt.Observe(ctx, r)
	if err != nil {
		return campaign.OracleIndeterminate
	}
	state := r.ContextForge
	if state == nil || observation.ToolID != state.Management.ToolID ||
		observation.ServerID != state.Management.ServerID || !observation.Associated ||
		!observation.ManagementObserved || !observation.MCPObserved {
		return campaign.OracleIndeterminate
	}
	if observation.ManagementDescription == r.OriginalContent &&
		observation.MCPDescription == r.OriginalContent {
		if observation.ManagementVersion == state.Management.OriginalVersion &&
			matchesOriginalUserAgent(observation.ManagementModifiedUserAgent, state.Management.OriginalModifiedUserAgent) {
			return campaign.OracleMutationNotApplied
		}
		return campaign.OracleMutationConflict
	}
	if observation.ManagementVersion == state.Management.OriginalVersion+1 &&
		observation.ManagementModifiedUserAgent == state.Management.ForwardUserAgent &&
		observation.ManagementDescription != r.OriginalContent &&
		observation.MCPDescription == observation.ManagementDescription {
		return campaign.OracleMutationVerified
	}
	if observation.ManagementVersion != state.Management.OriginalVersion+1 ||
		observation.ManagementModifiedUserAgent != state.Management.ForwardUserAgent {
		return campaign.OracleMutationConflict
	}
	return campaign.OracleIndeterminate
}

func matchesOriginalUserAgent(observed string, original *string) bool {
	if original == nil {
		return observed == ""
	}
	return observed == *original
}

func restorationConfirmed(observation mcppoison.Observation, r *action.PoisonReceipt) bool {
	if r == nil || r.ContextForge == nil {
		return false
	}
	state := r.ContextForge
	if !observation.ManagementObserved || observation.ToolID != state.Management.ToolID ||
		observation.ServerID != state.Management.ServerID ||
		observation.ManagementDescription != r.OriginalContent {
		return false
	}
	restoredByAgent := observation.ManagementVersion == state.Management.OriginalVersion+2 &&
		observation.ManagementModifiedUserAgent == state.Management.RestoreUserAgent
	neverChanged := observation.ManagementVersion == state.Management.OriginalVersion &&
		matchesOriginalUserAgent(observation.ManagementModifiedUserAgent, state.Management.OriginalModifiedUserAgent)
	if !restoredByAgent && !neverChanged {
		return false
	}
	return !observation.Associated ||
		(observation.MCPObserved && observation.MCPDescription == r.OriginalContent)
}

// classifyCleanup issues the conflict-aware revert and classifies that dispatch.
// The run orchestrator performs the separate post-revert re-read before the
// final report is allowed to retain CleanupRestored.
func classifyCleanup(ctx context.Context, rt roundTrip, r *action.PoisonReceipt) campaign.RoundtripCleanup {
	if err := rt.Revert(ctx, r); err != nil {
		switch {
		case errors.Is(err, mcppoison.ErrRevertPartiallyVerified):
			return campaign.CleanupRestored
		case errors.Is(err, mcppoison.ErrRevertIndeterminate):
			return campaign.CleanupIndeterminate
		case errors.Is(err, mcppoison.ErrRevertConflict):
			return campaign.CleanupConflict
		default:
			return campaign.CleanupFailed
		}
	}
	return campaign.CleanupRestored
}

// parseConfig reads and validates the provider-specific round-trip contract.
// ContextForge is intentionally the only adapter: MCP itself defines no tool
// metadata mutation API.
func parseConfig(in campaign.RunInput) (config, error) {
	p := in.Params
	targetID := strings.TrimSpace(param(p, "target-id"))
	if targetID == "" {
		return config{}, errors.New(`mcp-poison-roundtrip: params["target-id"] is required (the MCP tool whose description is mutated)`)
	}
	adapter := strings.TrimSpace(param(p, "adapter"))
	if adapter != action.ContextForgeProfile {
		return config{}, fmt.Errorf(
			`mcp-poison-roundtrip: params["adapter"] must be %q (MCP defines no generic mutation endpoint)`,
			action.ContextForgeProfile,
		)
	}
	managementURL := strings.TrimSpace(param(p, "management-url"))
	if err := mcppoison.ValidateContextForgeEndpoints(in.Host, managementURL); err != nil {
		return config{}, fmt.Errorf("mcp-poison-roundtrip: %w", err)
	}
	return config{
		targetID:      targetID,
		adapter:       adapter,
		managementURL: managementURL,
	}, nil
}

func param(m map[string]string, k string) string {
	if m == nil {
		return ""
	}
	return m[k]
}

// planText renders the round-trip plan without probing either surface.
func planText(in campaign.RunInput, cfg config) string {
	var b strings.Builder
	fmt.Fprintf(&b, "scenario:      %s (v%d)\n", scenarioID, scenarioVersion)
	fmt.Fprintf(&b, "oracle:        %s\n", campaign.OracleTypeReversibleMutationRoundtrip)
	fmt.Fprintf(&b, "target:        %s\n", campaign.SanitizedTargetReference(in.Host))
	fmt.Fprintf(&b, "target tool:   %s\n", cfg.targetID)
	fmt.Fprintf(&b, "adapter:       %s\n", cfg.adapter)
	if cfg.managementURL == "" {
		b.WriteString("management:    derive ContextForge /v1 from the server-scoped MCP URL\n")
	} else {
		fmt.Fprintf(&b, "management:    %s\n", campaign.SanitizedTargetReference(cfg.managementURL))
	}
	b.WriteString("plan (STANDALONE target-mutation validation; NOT an attack finding):\n")
	b.WriteString("  1. bind the MCP name to the exact ContextForge server/tool UUID and prove permissions\n")
	b.WriteString("  2. append one generated inert marker and prove an MCP-visible intermediate change (ORACLE)\n")
	b.WriteString("  3. restore once only when ContextForge version and operation attribution match\n")
	b.WriteString("  4. re-read management and MCP state and confirm the original (CLEANUP)\n")
	b.WriteString("  oracle and cleanup are reported SEPARATELY.\n")
	return b.String()
}
