package model

import (
	"time"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

type Scan struct {
	ID          string         `json:"id"`
	Collector   string         `json:"collector"`
	Status      string         `json:"status"`
	StartedAt   time.Time      `json:"started_at"`
	CompletedAt *time.Time     `json:"completed_at,omitempty"`
	NodeCount   int            `json:"node_count"`
	EdgeCount   int            `json:"edge_count"`
	Error       string         `json:"error,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`

	// Truth-contract fields (migration 004). Populated by the generation-aware
	// ingest pipeline in a later phase; omitempty keeps legacy responses stable
	// until then.

	// GenerationID identifies the graph generation this scan materialized.
	GenerationID string `json:"generation_id,omitempty"`
	// Scope is the comparable-scope key the current-generation pointer,
	// coverage-aware retention, and the rematerializing delete are keyed on.
	// It is decoupled from Collector so a merged local `scan` bundle and a
	// network sweep (both collector = "scan") occupy independent scopes
	// (scan:local vs scan:network) and cannot demote or retire each other.
	// Empty falls back to Collector for rows that predate the scope column.
	Scope string `json:"scope,omitempty"`
	// IsCurrent marks the promoted (default-read) generation.
	IsCurrent bool `json:"is_current,omitempty"`
	// SchemaVersion / IdentityVersion pin the contract this scan was produced
	// against (see ingest.CurrentSchemaVersion / CurrentIdentityVersion).
	SchemaVersion   int `json:"schema_version,omitempty"`
	IdentityVersion int `json:"identity_version,omitempty"`
	// CoverageStatus is the roll-up collection status; absence is only clean
	// when StatusComplete.
	CoverageStatus ingest.CollectionStatus `json:"coverage_status,omitempty"`
	// Coverage is the full per-target/per-method/rule coverage manifest.
	Coverage *ingest.CollectionCoverage `json:"coverage,omitempty"`
	// StageStates records each ingest stage's independent outcome.
	StageStates map[string]ingest.StageState `json:"stage_states,omitempty"`
	// NodeInventory / EdgeInventory report accurate created/updated/unchanged/
	// retired counts with before/after totals.
	NodeInventory *ingest.InventoryDelta `json:"node_inventory,omitempty"`
	EdgeInventory *ingest.InventoryDelta `json:"edge_inventory,omitempty"`
	// CapturedAt is the collection-capture completion time, distinct from
	// CompletedAt (server ingest completion).
	CapturedAt *time.Time `json:"captured_at,omitempty"`
	// DeleteState is the deletion lifecycle for durable, recoverable scan
	// deletion (migration 007): "" (not being deleted), DeleteStateDeleting
	// (delete in progress — persisted BEFORE the graph mutation so an
	// interrupted delete is recoverable), or DeleteStateFailed (a delete
	// attempt errored and can be retried idempotently).
	DeleteState string `json:"delete_state,omitempty"`
}

const (
	ScanStatusPending   = "pending"
	ScanStatusRunning   = "running"
	ScanStatusCompleted = "completed"
	// ScanStatusCompletedWithErrors means node/edge collection succeeded
	// (real counts persisted) but analysis post-processing returned an
	// error. Distinct from ScanStatusFailed, which is reserved for the
	// collection/write failure path (counts 0,0).
	ScanStatusCompletedWithErrors = "completed_with_errors"
	ScanStatusFailed              = "failed"
)

// Scan deletion lifecycle states (migration 007). Persisted so a scan delete
// interrupted between the Neo4j graph mutation and the Postgres row removal is
// durably recoverable by an idempotent retry.
const (
	// DeleteStateDeleting is set BEFORE the graph is mutated: a scan carrying
	// it has an in-progress (or interrupted) delete that must be retried to
	// completion.
	DeleteStateDeleting = "deleting"
	// DeleteStateFailed marks a delete attempt that errored; it is retryable.
	DeleteStateFailed = "delete_failed"
)
