package mcproundtrip

import (
	"context"

	"github.com/google/uuid"

	"github.com/adithyan-ak/agenthound/modules/mcppoison"
	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/campaign"
)

// roundTrip abstracts the three primitives the scenario composes so the
// oracle/cleanup decision logic is unit-testable with a fake, while the real
// path delegates to modules/mcppoison. It is deliberately narrow.
type roundTrip interface {
	// Mutate applies the operator-authorized mutation and returns the receipt
	// (OriginalContent + InjectedContent captured; persisted before the write
	// per mcppoison's crash-safety gate).
	Mutate(ctx context.Context, stepSequence uint64) (*action.PoisonReceipt, error)
	// Observe re-reads the exact persisted ContextForge row and, when it remains
	// associated, the server-scoped MCP projection.
	Observe(ctx context.Context, receipt *action.PoisonReceipt) (mcppoison.Observation, error)
	// Revert applies the conflict-aware, no-blind-write reversion.
	Revert(ctx context.Context, receipt action.Receipt) error
}

// mcpRoundTrip is the real implementation. It delegates to modules/mcppoison
// for the provider-specific mutation, conflict-aware restoration, and dual-
// surface ContextForge/MCP observations.
// It uses a fresh file-backed Poisoner, so the mutation persists a receipt under
// the shared mcp.poison state dir — the same receipts `agenthound revert` walks
// per-file LIFO if the inline revert cannot complete (Phase A reuse).
type mcpRoundTrip struct {
	poisoner *mcppoison.Poisoner
	target   action.Target
	payload  action.PoisonPayload
}

// newMCPRoundTrip builds the real round-trip from the run input and parsed
// ContextForge adapter configuration. The adapter owns every management route;
// no operator-supplied or MCP-defined mutation endpoint exists.
func newMCPRoundTrip(in campaign.RunInput, cfg config) (roundTrip, error) {
	marker := "\n\nAgentHound authorized roundtrip validation " + uuid.NewString()
	extras := map[string]any{
		"adapter":  cfg.adapter,
		"insecure": in.Insecure,
	}
	if cfg.managementURL != "" {
		extras["management-url"] = cfg.managementURL
	}
	return &mcpRoundTrip{
		// The scenario supplies separately bounded forward and cleanup contexts,
		// so it must not inherit the standalone client's blanket timeout.
		poisoner: mcppoison.NewForCampaign(),
		target:   action.Target{Kind: "url", Address: in.Host},
		payload: action.PoisonPayload{
			InjectionContent: marker,
			TargetID:         cfg.targetID,
			Mode:             "append",
			EngagementID:     in.EngagementID,
			CampaignRunID:    in.RunID,
			// Committed round-trip; the dry-run branch is handled upstream in Run.
			DryRun: false,
			Extras: extras,
		},
	}, nil
}

func (m *mcpRoundTrip) Mutate(ctx context.Context, stepSequence uint64) (*action.PoisonReceipt, error) {
	m.payload.StepSequence = stepSequence
	return m.poisoner.Poison(ctx, m.target, m.payload)
}

func (m *mcpRoundTrip) Observe(ctx context.Context, receipt *action.PoisonReceipt) (mcppoison.Observation, error) {
	if insecure, _ := m.payload.Extras["insecure"].(bool); insecure {
		ctx = context.WithValue(ctx, action.RevertInsecureKey{}, true)
	}
	return m.poisoner.ObserveReceipt(ctx, receipt)
}

func (m *mcpRoundTrip) Revert(ctx context.Context, receipt action.Receipt) error {
	if insecure, _ := m.payload.Extras["insecure"].(bool); insecure {
		ctx = context.WithValue(ctx, action.RevertInsecureKey{}, true)
	}
	return m.poisoner.Revert(ctx, receipt)
}
