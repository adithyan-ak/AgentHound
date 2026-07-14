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
	scenarioVersion = 1
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
	return "Reversible mcppoison round-trip (STANDALONE target-mutation validation): " +
		"operator-authorized mutation, injected-state oracle, conflict-aware revert, " +
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

// config is the parsed per-run mutation configuration read from
// RunInput.Params. Empty method/path/list fields fall back to mcppoison's
// defaults at execution time.
type config struct {
	targetID     string
	inject       string
	mode         string
	updateMethod string
	updatePath   string
	listPath     string
	authToken    string
}

// Run executes the round-trip. On a dry run it plans only and never mutates.
// Precondition failures (missing target-id/inject, bad mode) return an error
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
		RequestLimit: 16, MutationLimit: 2, ElapsedLimit: elapsedLimit,
	})
	defer cancel()
	now := in.Clock()
	report := &campaign.RunReport{
		ReportVersion:    campaign.RunReportVersion,
		ScenarioID:       scenarioID,
		ScenarioVersion:  scenarioVersion,
		CampaignRunID:    in.RunID,
		EngagementID:     in.EngagementID,
		Standalone:       true,
		MutationTargetID: cfg.targetID,
		TargetRef:        campaign.SanitizedTargetReference(in.Host),
		StartedAt:        now().UTC().Format(time.RFC3339),
		Steps:            []campaign.StepObservation{},
		Cleanup: campaign.CleanupReport{
			Status: campaign.CleanupIndeterminate, Postcondition: "unconfirmed",
		},
	}
	report.AddStep(campaign.StepAuthorizeMutation, "authorized")

	if err := campaign.ConsumeMutation(runCtx); err != nil {
		report.AddStep(campaign.StepMutate, "budget_exhausted")
		report.AddStep(campaign.StepVerifyInjected, "not_run")
		report.AddStep(campaign.StepRevert, "not_run")
		report.AddStep(campaign.StepVerifyOriginal, "unconfirmed")
		report.Oracle = campaign.OracleReport{
			Type:        campaign.OracleTypeReversibleMutationRoundtrip,
			Observation: "budget_exhausted", Outcome: string(campaign.OracleIndeterminate),
		}
		finishReport(report, budget, now)
		return report, err
	}

	// StepSequence is assigned by this single run orchestrator immediately
	// before invoking the mutator that persists the receipt.
	receipt, mutateErr := rt.Mutate(runCtx, 1)
	if mutateErr != nil {
		report.AddStep(campaign.StepMutate, "failed")
	} else {
		report.AddStep(campaign.StepMutate, "applied")
	}
	report.Cleanup.ReceiptRetained = receipt != nil

	oracle := campaign.OracleIndeterminate
	if receipt != nil && mutateErr == nil {
		oracle = classifyOracle(runCtx, rt, receipt)
	}
	report.AddStep(campaign.StepVerifyInjected, string(oracle))
	report.Oracle = campaign.OracleReport{
		Type:        campaign.OracleTypeReversibleMutationRoundtrip,
		Observation: string(oracle),
		Outcome:     string(oracle),
	}

	cleanupCtx, cleanupCancel := budget.CleanupContext(90 * time.Second)
	defer cleanupCancel()
	cleanup := executeRunCleanup(cleanupCtx, in, rt, receipt)
	report.AddStep(campaign.StepRevert, string(cleanup.Status))

	postcondition := "unconfirmed"
	if cleanup.Status == campaign.CleanupRestored &&
		(cleanup.ReceiptsSelected < 1 || receipt == nil) {
		cleanup.Status = campaign.CleanupIndeterminate
	}
	if cleanup.Status == campaign.CleanupRestored {
		current, err := rt.ReadCurrent(cleanupCtx)
		switch {
		case err != nil:
			cleanup.Status = campaign.CleanupFailed
			postcondition = "reread_failed"
		case current != receipt.OriginalContent:
			cleanup.Status = campaign.CleanupFailed
			postcondition = "original_mismatch"
		default:
			postcondition = "original_confirmed"
		}
	}
	report.AddStep(campaign.StepVerifyOriginal, postcondition)
	report.Cleanup = campaign.CleanupReport{
		Status:          cleanup.Status,
		Postcondition:   postcondition,
		ReceiptRetained: cleanup.ReceiptsRetained || receipt != nil,
	}
	finishReport(report, budget, now)

	if cleanup.Status != campaign.CleanupRestored {
		return report, campaign.ErrUnsafeCleanup
	}
	if mutateErr != nil {
		return report, campaign.ErrMutationFailed
	}
	if exhausted := budget.Exhaustion(runCtx); exhausted != nil {
		return report, exhausted
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

func finishReport(report *campaign.RunReport, budget *campaign.Budget, now func() time.Time) {
	report.CompletedAt = now().UTC().Format(time.RFC3339)
	report.Budget = budget.Snapshot()
}

// classifyOracle re-reads the live state after the mutation and decides whether
// the injection landed, comparing against the receipt.
func classifyOracle(ctx context.Context, rt roundTrip, r *action.PoisonReceipt) campaign.RoundtripOracle {
	current, err := rt.ReadCurrent(ctx)
	if err != nil {
		return campaign.OracleIndeterminate
	}
	switch current {
	case r.InjectedContent:
		return campaign.OracleMutationVerified
	case r.OriginalContent:
		return campaign.OracleMutationNotApplied
	default:
		return campaign.OracleMutationConflict
	}
}

// classifyCleanup issues the conflict-aware revert and classifies that dispatch.
// The run orchestrator performs the separate post-revert re-read before the
// final report is allowed to retain CleanupRestored.
func classifyCleanup(ctx context.Context, rt roundTrip, r *action.PoisonReceipt) campaign.RoundtripCleanup {
	if err := rt.Revert(ctx, r); err != nil {
		switch {
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

// parseConfig reads and validates the mutation configuration from
// RunInput.Params. target-id and inject are required; mode, when set, must be
// one of replace/append/prepend.
func parseConfig(in campaign.RunInput) (config, error) {
	p := in.Params
	targetID := strings.TrimSpace(param(p, "target-id"))
	if targetID == "" {
		return config{}, errors.New(`mcp-poison-roundtrip: params["target-id"] is required (the MCP tool whose description is mutated)`)
	}
	inject := param(p, "inject")
	if strings.TrimSpace(inject) == "" {
		return config{}, errors.New(`mcp-poison-roundtrip: params["inject"] is required (the injection content)`)
	}
	mode := strings.TrimSpace(param(p, "mode"))
	switch mode {
	case "", "replace", "append", "prepend":
	default:
		return config{}, fmt.Errorf("mcp-poison-roundtrip: unsupported mode %q (use replace/append/prepend)", mode)
	}
	return config{
		targetID:     targetID,
		inject:       inject,
		mode:         mode,
		updateMethod: strings.TrimSpace(param(p, "update-method")),
		updatePath:   strings.TrimSpace(param(p, "update-path")),
		listPath:     strings.TrimSpace(param(p, "list-path")),
		authToken:    param(p, "auth-token"),
	}, nil
}

func param(m map[string]string, k string) string {
	if m == nil {
		return ""
	}
	return m[k]
}

// planText renders the round-trip plan for a dry run. It names the exact write
// surface without revealing the injection content.
func planText(in campaign.RunInput, cfg config) string {
	var b strings.Builder
	fmt.Fprintf(&b, "scenario:      %s (v%d)\n", scenarioID, scenarioVersion)
	fmt.Fprintf(&b, "oracle:        %s\n", campaign.OracleTypeReversibleMutationRoundtrip)
	fmt.Fprintf(&b, "target:        %s\n", campaign.SanitizedTargetReference(in.Host))
	fmt.Fprintf(&b, "target tool:   %s\n", cfg.targetID)
	fmt.Fprintf(&b, "mode:          %s\n", orDefault(cfg.mode, "replace"))
	fmt.Fprintf(&b, "write:         %s %s\n", orDefault(cfg.updateMethod, "PUT"), orDefault(cfg.updatePath, "/admin/tools/{id}"))
	fmt.Fprintf(&b, "list path:     %s\n", orDefault(cfg.listPath, "/"))
	b.WriteString("plan (STANDALONE target-mutation validation; NOT an attack finding):\n")
	b.WriteString("  1. apply the operator-authorized mutation (mcppoison Poison)\n")
	b.WriteString("  2. re-read the exact injected state and compare to the receipt (ORACLE)\n")
	b.WriteString("  3. conflict-aware revert (mcppoison Revert; never a blind write)\n")
	b.WriteString("  4. re-read and confirm the original is restored (CLEANUP)\n")
	b.WriteString("  oracle and cleanup are reported SEPARATELY.\n")
	return b.String()
}

func orDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}
