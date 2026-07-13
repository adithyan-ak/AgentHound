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
// (campaign.RoundtripReport). Rollback reuses Phase A (per-file LIFO +
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

	factory := s.newRoundTrip
	if factory == nil {
		factory = newMCPRoundTrip
	}
	rt, err := factory(in, cfg)
	if err != nil {
		return nil, fmt.Errorf("mcp-poison-roundtrip: build round-trip: %w", err)
	}

	report := runRoundtrip(ctx, in, cfg, rt)
	return &campaign.RunResult{Roundtrip: report}, nil
}

// runRoundtrip performs the mutate -> oracle -> revert -> cleanup sequence and
// classifies the oracle and cleanup INDEPENDENTLY.
func runRoundtrip(ctx context.Context, in campaign.RunInput, cfg config, rt roundTrip) *campaign.RoundtripReport {
	runID := strings.TrimSpace(in.RunID)
	if runID == "" {
		runID = uuid.NewString()
	}
	report := &campaign.RoundtripReport{
		ScenarioID:      scenarioID,
		ScenarioVersion: scenarioVersion,
		RunID:           runID,
		EngagementID:    in.EngagementID,
		OracleType:      campaign.OracleTypeReversibleMutationRoundtrip,
		Standalone:      true,
		TargetID:        cfg.targetID,
		VerifiedAt:      in.Clock()().UTC().Format(time.RFC3339),
	}

	receipt, err := rt.Mutate(ctx)
	if err != nil {
		// The mutation failed. mcppoison persists the receipt BEFORE the write,
		// so any partial change is recoverable via `agenthound revert`. We never
		// established a known injected state and hold no receipt to revert inline,
		// so both outcomes are indeterminate — never claim the target is clean.
		report.Oracle = campaign.OracleIndeterminate
		report.Cleanup = campaign.CleanupIndeterminate
		report.Detail = "mutation failed before a known injected state was established; run `agenthound revert`"
		return report
	}

	// ORACLE: did the mutation land? Re-read the exact live state and compare it
	// to the receipt. Computed from this re-read alone.
	report.Oracle = classifyOracle(ctx, rt, receipt)

	// CLEANUP: conflict-aware revert, then verify the original was restored.
	// Computed from the revert result plus a post-revert re-read — INDEPENDENT of
	// the oracle above.
	report.Cleanup = classifyCleanup(ctx, rt, receipt)
	return report
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

// classifyCleanup issues the conflict-aware revert and verifies the original was
// restored. It maps the reverter's no-blind-write outcomes onto the cleanup
// vocabulary and never reports "restored" without a confirming re-read.
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
	// Revert reported success (a restore or a no-op). Confirm the live state is
	// actually back at the original before claiming the target is clean.
	current, err := rt.ReadCurrent(ctx)
	if err != nil {
		return campaign.CleanupFailed
	}
	if current == r.OriginalContent {
		return campaign.CleanupRestored
	}
	return campaign.CleanupFailed
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
	fmt.Fprintf(&b, "target host:   %s\n", in.Host)
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
