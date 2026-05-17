package action

import (
	"context"
	"time"
)

// Poisoner injects content into an upstream artifact a Target consumes
// (config file, instruction file, tool description, etc.). Composes
// Reverter so every poison can be undone — this is non-negotiable for
// red-team safety.
//
// Implementations also implement sdk/module.Module.
//
// v0.4 wires this concretely. Every Poisoner emits a PoisonReceipt that
// carries the original content (so revert is byte-identical) plus
// engagement metadata. Receipts are persisted by the StatefulModule
// sidecar (sdk/module/stateful.go) keyed on engagement-id so
// `agenthound revert <engagement-id>` walks all module state dirs and
// dispatches per-module Revert.
type Poisoner interface {
	Reverter
	Poison(ctx context.Context, t Target, payload PoisonPayload) (*PoisonReceipt, error)
}

// PoisonPayload describes one Poison invocation.
//
// TargetID is the per-module logical address of what is being poisoned —
// for the MCP tool Poisoner this is the MCPTool.objectid. For an
// instruction-file Poisoner (v4-phase 2) it is the absolute file path.
//
// Mode controls how InjectionContent combines with existing content:
//
//	"append"   — add InjectionContent at the end of the original
//	"prepend"  — add InjectionContent at the start of the original
//	"replace"  — overwrite the original entirely
//
// EngagementID is recorded on the receipt and on every emitted edge's
// evidence map. DryRun=true makes the Poisoner run end-to-end without
// any mutating HTTP/file write — receipt is written with DryRun=true so
// `agenthound revert` knows to skip it.
type PoisonPayload struct {
	InjectionContent string
	TargetID         string
	Mode             string
	EngagementID     string
	DryRun           bool

	// Extras carries per-Poisoner flag values populated by the CLI dispatch
	// from the Poisoner's FlagsModule.RegisterFlags surface. Mirrors
	// LootOptions.Extras — same pattern, different action.
	Extras map[string]any
}

// PoisonReceipt is what every Poisoner returns and what Revert consumes.
// OriginalContent is mandatory — without it, revert is impossible. The
// CLI persists the receipt via StatefulModule before declaring the
// poison "applied", so a crash between the HTTP write and the receipt
// write would leave a tampered target without a revert path.
type PoisonReceipt struct {
	ModuleID        string
	EngagementID    string
	Target          Target
	TargetID        string
	OriginalContent string
	InjectedContent string
	Mode            string
	AppliedAt       time.Time
	DryRun          bool

	// Extra carries per-Poisoner state the Reverter needs to undo this
	// poison cleanly (e.g. content-type, transport metadata). Optional —
	// receipts that don't need it leave it nil.
	Extra map[string]any
}
