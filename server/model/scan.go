package model

import "time"

type Scan struct {
	ID                    string         `json:"id"`
	Collector             string         `json:"collector"`
	Status                string         `json:"status"`
	StartedAt             time.Time      `json:"started_at"`
	CompletedAt           *time.Time     `json:"completed_at,omitempty"`
	ArtifactObservedAt    *time.Time     `json:"artifact_observed_at,omitempty"`
	NodeCount             int            `json:"node_count"`
	EdgeCount             int            `json:"edge_count"`
	Error                 string         `json:"error,omitempty"`
	CollectionStatus      string         `json:"collection_status"`
	GraphStatus           string         `json:"graph_status"`
	AnalysisStatus        string         `json:"analysis_status"`
	SnapshotStatus        string         `json:"snapshot_status"`
	ProjectionStatus      string         `json:"projection_status"`
	PublicationStatus     string         `json:"publication_status"`
	ComparisonKey         string         `json:"comparison_key,omitempty"`
	GraphTotalNodesBefore *int64         `json:"graph_total_nodes_before,omitempty"`
	GraphTotalEdgesBefore *int64         `json:"graph_total_edges_before,omitempty"`
	GraphTotalNodesAfter  *int64         `json:"graph_total_nodes_after,omitempty"`
	GraphTotalEdgesAfter  *int64         `json:"graph_total_edges_after,omitempty"`
	ComparableToScanID    string         `json:"comparable_to_scan_id,omitempty"`
	PublishedRevision     *int64         `json:"published_revision,omitempty"`
	PublishedAt           *time.Time     `json:"published_at,omitempty"`
	LifecycleUpdatedAt    *time.Time     `json:"lifecycle_updated_at,omitempty"`
	Metadata              map[string]any `json:"metadata,omitempty"`
}

const (
	ScanStatusPending   = "pending"
	ScanStatusRunning   = "running"
	ScanStatusCompleted = "completed"
	// ScanStatusCompletedWithErrors means graph writes completed but coverage
	// or a required analysis/publication stage was degraded. NodeCount and
	// EdgeCount retain legacy write-row semantics.
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
