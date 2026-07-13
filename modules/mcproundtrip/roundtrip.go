package mcproundtrip

import (
	"context"

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
	Mutate(ctx context.Context) (*action.PoisonReceipt, error)
	// ReadCurrent re-reads the exact live target state. It is the oracle read
	// (after Mutate) and the cleanup verification read (after Revert).
	ReadCurrent(ctx context.Context) (string, error)
	// Revert applies the conflict-aware, no-blind-write reversion.
	Revert(ctx context.Context, receipt action.Receipt) error
}

// mcpRoundTrip is the real implementation. It delegates to modules/mcppoison
// (Poison + conflict-aware Revert) plus mcppoison.ReadDescription for the
// oracle/cleanup re-reads, reusing exactly one tools/list read implementation.
// It uses a fresh file-backed Poisoner, so the mutation persists a receipt under
// the shared mcp.poison state dir — the same receipts `agenthound revert` walks
// per-file LIFO if the inline revert cannot complete (Phase A reuse).
type mcpRoundTrip struct {
	poisoner  *mcppoison.Poisoner
	target    action.Target
	payload   action.PoisonPayload
	listPath  string
	authToken string
}

// newMCPRoundTrip builds the real round-trip from the run input and parsed
// config. Empty method/path/list values are passed through so mcppoison applies
// its own defaults (PUT /admin/tools/{id}, list "/").
func newMCPRoundTrip(in campaign.RunInput, cfg config) (roundTrip, error) {
	extras := map[string]any{}
	if cfg.updateMethod != "" {
		extras["update-method"] = cfg.updateMethod
	}
	if cfg.updatePath != "" {
		extras["update-path"] = cfg.updatePath
	}
	if cfg.listPath != "" {
		extras["list-path"] = cfg.listPath
	}
	if cfg.authToken != "" {
		extras["auth-token"] = cfg.authToken
	}
	return &mcpRoundTrip{
		poisoner: mcppoison.New(),
		target:   action.Target{Kind: "host", Address: in.Host},
		payload: action.PoisonPayload{
			InjectionContent: cfg.inject,
			TargetID:         cfg.targetID,
			Mode:             cfg.mode,
			EngagementID:     in.EngagementID,
			// Committed round-trip; the dry-run branch is handled upstream in Run.
			DryRun: false,
			Extras: extras,
		},
		listPath:  cfg.listPath,
		authToken: cfg.authToken,
	}, nil
}

func (m *mcpRoundTrip) Mutate(ctx context.Context) (*action.PoisonReceipt, error) {
	return m.poisoner.Poison(ctx, m.target, m.payload)
}

func (m *mcpRoundTrip) ReadCurrent(ctx context.Context) (string, error) {
	return m.poisoner.ReadDescription(ctx, m.target, m.payload.TargetID, m.listPath, m.authToken)
}

func (m *mcpRoundTrip) Revert(ctx context.Context, receipt action.Receipt) error {
	// mcppoison.Revert reads the optional auth token from the context (it is
	// never stored on the receipt), mirroring `agenthound revert --auth-token`.
	if m.authToken != "" {
		ctx = context.WithValue(ctx, action.RevertAuthTokenKey{}, m.authToken)
	}
	return m.poisoner.Revert(ctx, receipt)
}
