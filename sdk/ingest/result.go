package ingest

import "time"

type IngestResult struct {
	ScanID              string               `json:"scan_id"`
	NodesWritten        int                  `json:"nodes_written"`
	EdgesWritten        int                  `json:"edges_written"`
	Warnings            []string             `json:"warnings,omitempty"`
	PostProcessingStats []PostProcessingStat `json:"post_processing_stats,omitempty"`
	Duration            time.Duration        `json:"duration"`

	// GenerationID identifies the graph generation this ingest wrote. Reads
	// scoped to a generation see a consistent, fully-materialized snapshot;
	// partial writes remain non-current and are never exposed by default.
	GenerationID string `json:"generation_id,omitempty"`
	// Status is the roll-up outcome for this ingest run. It is derived from
	// the per-stage StageResults, NOT from row counts — a MERGE that touched
	// zero rows is not a failure, and a partial write is not a success.
	Status CollectionStatus `json:"status,omitempty"`
	// Stages records the independent outcome of each ingest stage (write,
	// post-processing, snapshot, promotion) so a failure in one stage is not
	// masked by success in another and is not recorded as 0/0 success-like
	// history.
	Stages []StageResult `json:"stages,omitempty"`
	// NodeInventory / EdgeInventory report accurate created/updated/unchanged/
	// retired counts plus before/after totals, so callers stop mislabeling
	// MERGE row counts as discoveries or growth.
	NodeInventory *InventoryDelta `json:"node_inventory,omitempty"`
	EdgeInventory *InventoryDelta `json:"edge_inventory,omitempty"`
}

type PostProcessingStat struct {
	ProcessorName string        `json:"processor_name"`
	EdgesCreated  int           `json:"edges_created"`
	NodesUpdated  int           `json:"nodes_updated"`
	Duration      time.Duration `json:"duration"`
	Error         string        `json:"error,omitempty"`
}

// StageState is the independent outcome of a single ingest stage.
type StageState string

const (
	StageSucceeded StageState = "succeeded"
	StagePartial   StageState = "partial"
	StageFailed    StageState = "failed"
	// StageSkipped means the stage did not run because a prerequisite stage
	// did not succeed. Distinct from failed: the stage itself never executed.
	StageSkipped StageState = "skipped"
)

// AllStageStates is the canonical ordered set of stage states.
var AllStageStates = []StageState{
	StageSucceeded, StagePartial, StageFailed, StageSkipped,
}

// Valid reports whether s is one of the defined stage states.
func (s StageState) Valid() bool {
	switch s {
	case StageSucceeded, StagePartial, StageFailed, StageSkipped:
		return true
	default:
		return false
	}
}

// Canonical stage names. Callers should use these constants so the persisted
// stage_states map has a stable, queryable key set.
const (
	StageWrite          = "write"
	StagePostProcessing = "post_processing"
	StageSnapshot       = "snapshot"
	StagePromotion      = "promotion"
)

// StageResult is the outcome of one named ingest stage.
type StageResult struct {
	Name     string        `json:"name"`
	State    StageState    `json:"state"`
	Error    string        `json:"error,omitempty"`
	Duration time.Duration `json:"duration,omitempty"`
}

// InventoryDelta reports the exact effect of an ingest run on one entity class
// (nodes or edges). Created/Updated/Unchanged/Retired are mutually exclusive
// per entity; BeforeTotal + Created - Retired == AfterTotal must hold for a
// complete, promoted generation.
type InventoryDelta struct {
	Created     int `json:"created"`
	Updated     int `json:"updated"`
	Unchanged   int `json:"unchanged"`
	Retired     int `json:"retired"`
	BeforeTotal int `json:"before_total"`
	AfterTotal  int `json:"after_total"`
}
