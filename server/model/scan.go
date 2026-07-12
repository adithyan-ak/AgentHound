package model

import (
	"encoding/json"
	"fmt"
	"time"
)

type Scan struct {
	ID                    string         `json:"id"`
	Collector             string         `json:"collector"`
	Status                string         `json:"status"`
	StartedAt             time.Time      `json:"started_at"`
	CompletedAt           *time.Time     `json:"completed_at,omitempty"`
	ArtifactObservedAt    *time.Time     `json:"artifact_observed_at,omitempty"`
	NodeWriteRows         int            `json:"-"`
	EdgeWriteRows         int            `json:"-"`
	Error                 string         `json:"error,omitempty"`
	CollectionStatus      string         `json:"collection_status"`
	GraphStatus           string         `json:"graph_status"`
	AnalysisStatus        string         `json:"analysis_status"`
	SnapshotStatus        string         `json:"snapshot_status"`
	ProjectionStatus      string         `json:"projection_status"`
	PublicationStatus     string         `json:"publication_status"`
	ComparisonKey         string         `json:"comparison_key,omitempty"`
	GraphTotalNodesBefore *int64         `json:"-"`
	GraphTotalEdgesBefore *int64         `json:"-"`
	GraphTotalNodesAfter  *int64         `json:"-"`
	GraphTotalEdgesAfter  *int64         `json:"-"`
	ComparableToScanID    string         `json:"comparable_to_scan_id,omitempty"`
	PublishedRevision     *int64         `json:"published_revision,omitempty"`
	PublishedAt           *time.Time     `json:"published_at,omitempty"`
	LifecycleUpdatedAt    *time.Time     `json:"lifecycle_updated_at,omitempty"`
	Metadata              map[string]any `json:"metadata,omitempty"`
}

type ScanCounts struct {
	Nodes int `json:"nodes"`
	Edges int `json:"edges"`
}

type ScanGraphTotal struct {
	TotalNodes int64 `json:"total_nodes"`
	TotalEdges int64 `json:"total_edges"`
}

type ScanGraphTotals struct {
	Before *ScanGraphTotal `json:"before"`
	After  *ScanGraphTotal `json:"after"`
}

func (s Scan) MarshalJSON() ([]byte, error) {
	type scanAlias Scan
	submitted, err := scanSubmittedCounts(s.Metadata)
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		scanAlias
		Submitted   ScanCounts      `json:"submitted"`
		WriteRows   ScanCounts      `json:"write_rows"`
		GraphTotals ScanGraphTotals `json:"graph_totals"`
	}{
		scanAlias: scanAlias(s),
		Submitted: submitted,
		WriteRows: ScanCounts{Nodes: s.NodeWriteRows, Edges: s.EdgeWriteRows},
		GraphTotals: ScanGraphTotals{
			Before: scanGraphTotal(s.GraphTotalNodesBefore, s.GraphTotalEdgesBefore),
			After:  scanGraphTotal(s.GraphTotalNodesAfter, s.GraphTotalEdgesAfter),
		},
	})
}

func scanGraphTotal(nodes, edges *int64) *ScanGraphTotal {
	if nodes == nil || edges == nil {
		return nil
	}
	return &ScanGraphTotal{TotalNodes: *nodes, TotalEdges: *edges}
}

func scanSubmittedCounts(metadata map[string]any) (ScanCounts, error) {
	value, ok := metadata["submitted"]
	if !ok {
		return ScanCounts{}, nil
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return ScanCounts{}, fmt.Errorf("encode submitted scan counts: %w", err)
	}
	var counts ScanCounts
	if err := json.Unmarshal(encoded, &counts); err != nil {
		return ScanCounts{}, fmt.Errorf("decode submitted scan counts: %w", err)
	}
	if counts.Nodes < 0 || counts.Edges < 0 {
		return ScanCounts{}, fmt.Errorf("submitted scan counts must be non-negative")
	}
	return counts, nil
}

const (
	ScanStatusPending   = "pending"
	ScanStatusRunning   = "running"
	ScanStatusCompleted = "completed"
	// ScanStatusCompletedWithErrors means graph writes completed but coverage
	// or a required analysis/publication stage was degraded.
	ScanStatusCompletedWithErrors = "completed_with_errors"
	ScanStatusFailed              = "failed"
)

const (
	LifecycleUnknown       = "unknown"
	LifecyclePending       = "pending"
	LifecycleRunning       = "running"
	LifecycleComplete      = "complete"
	LifecyclePartial       = "partial"
	LifecycleFailed        = "failed"
	LifecycleNotApplicable = "not_applicable"

	ProjectionUnknown    = "unknown"
	ProjectionUpdating   = "updating"
	ProjectionIncomplete = "incomplete"
	ProjectionComplete   = "complete"

	PublicationUnpublished = "unpublished"
	PublicationPublished   = "published"
	PublicationSuperseded  = "superseded"
)
