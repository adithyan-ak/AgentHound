package action

import (
	"context"
	"time"
)

// Implanter installs a persistent payload (cron entry, hook, modified
// binary, scheduled task, MCP-config entry) on or adjacent to a Target.
// Composes Reverter for the same reason Poisoner does — every implant
// must be undoable.
//
// Implementations also implement sdk/module.Module.
type Implanter interface {
	Reverter
	Implant(ctx context.Context, t Target, payload ImplantPayload) (*ImplantReceipt, error)
}

// ImplantPayload describes one Implant invocation.
//
// TargetID is the per-module logical address. For the v0.4 file-based
// Implanters this is the absolute path to the file being modified
// (CLAUDE.md, ~/.cursor/mcp.json). For a future cron / systemd / hook
// Implanter it would be the unit / job identifier.
//
// EngagementID is recorded on the receipt and on every emitted edge's
// evidence map. DryRun=true makes the Implanter run end-to-end without
// any mutating write; the receipt is persisted with DryRun=true so
// `agenthound revert` knows to skip it.
//
// Sentinel-bracketed insertions are the v0.4 default: every implant
// writes its content between two sentinel comment markers so the
// Reverter can regex-strip the bracketed block instead of needing to
// preserve the entire pre-state file. This is friendlier than the
// Poisoner pattern — instruction files and MCP configs are both
// expected to grow over the engagement, and a full pre-state replay
// would clobber legitimate concurrent edits.
type ImplantPayload struct {
	InjectionContent string
	TargetID         string
	EngagementID     string
	DryRun           bool

	// Extras carries per-Implanter flag values populated by the CLI
	// dispatch from the Implanter's FlagsModule.RegisterFlags surface.
	Extras map[string]any
}

// ImplantReceipt is what every Implanter returns and what Revert consumes.
//
// SentinelStart and SentinelEnd are the bracket markers the Implanter
// wrote around its injected content; the Reverter strips everything
// between them. PreSHA256 is the pre-write hash of the file contents
// — Reverter logs an explicit warning if the post-revert hash doesn't
// match (operator concurrent-edit detection).
type ImplantReceipt struct {
	ModuleID         string
	EngagementID     string
	Target           Target
	TargetID         string
	InjectionContent string
	SentinelStart    string
	SentinelEnd      string
	PreSHA256        string
	PostSHA256       string
	AppliedAt        time.Time
	DryRun           bool

	// Extra carries per-Implanter state the Reverter needs (e.g. the
	// JSON pointer that was modified for an MCP-config Implanter).
	Extra map[string]any
}
