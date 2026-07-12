package model

import (
	"time"

	sdkingest "github.com/adithyan-ak/agenthound/sdk/ingest"
)

// GraphSnapshot is a frozen public-inventory count captured in one Neo4j read
// transaction. It is intentionally distinct from scan write-row counts.
type GraphSnapshot struct {
	NodeCounts map[string]int64 `json:"node_counts"`
	EdgeCounts map[string]int64 `json:"edge_counts"`
	TotalNodes int64            `json:"total_nodes"`
	TotalEdges int64            `json:"total_edges"`
}

type PostureScope struct {
	ScanID             string   `json:"scan_id"`
	Revision           int64    `json:"revision"`
	CoverageKeys       []string `json:"coverage_keys"`
	ActiveCoverageKeys []string `json:"active_coverage_keys"`
	DirtyCoverage      []string `json:"dirty_coverage"`
	ComparisonKey      string   `json:"comparison_key,omitempty"`
	ProjectionState    string   `json:"projection_state"`
}

type PostureCompleteness struct {
	Collection         string                           `json:"collection"`
	Normalization      sdkingest.NormalizationStatus    `json:"normalization"`
	Observation        string                           `json:"observation"`
	ObservationDetails PostureObservationCompleteness   `json:"observation_details"`
	Rules              string                           `json:"rules"`
	Identity           string                           `json:"identity"`
	Graph              string                           `json:"graph"`
	Analysis           string                           `json:"analysis"`
	Snapshot           string                           `json:"snapshot"`
	Projection         string                           `json:"projection"`
	Publication        string                           `json:"publication"`
	Warnings           []sdkingest.NormalizationWarning `json:"warnings"`
	Stages             []sdkingest.StageResult          `json:"stages"`
}

type PostureObservationCompleteness struct {
	IncompletePropertyNodes         int64 `json:"incomplete_property_nodes"`
	IncompletePropertyRelationships int64 `json:"incomplete_property_relationships"`
}

type PostureObservationTimes struct {
	ArtifactObservedAt  *time.Time `json:"artifact_observed_at,omitempty"`
	IngestStartedAt     time.Time  `json:"ingest_started_at"`
	AnalysisCompletedAt time.Time  `json:"analysis_completed_at"`
	PublishedAt         time.Time  `json:"published_at"`
}

type PostureSuppression struct {
	Policy             string    `json:"policy"`
	SuppressedStatuses []string  `json:"suppressed_statuses"`
	TriageObservedAt   time.Time `json:"triage_observed_at"`
}

type PostureHealthObservation struct {
	State      string     `json:"state"`
	Captured   bool       `json:"captured"`
	ObservedAt *time.Time `json:"observed_at,omitempty"`
}

type PostureExportCardinality struct {
	Returned int  `json:"returned"`
	Total    int  `json:"total"`
	Complete bool `json:"complete"`
}

type PostureExportLimits struct {
	Findings PostureExportCardinality `json:"findings"`
}

type PostureComparison struct {
	Comparable     bool           `json:"comparable"`
	PreviousScanID string         `json:"previous_scan_id,omitempty"`
	Previous       *GraphSnapshot `json:"previous,omitempty"`
	NodeDelta      *int64         `json:"node_delta,omitempty"`
	EdgeDelta      *int64         `json:"edge_delta,omitempty"`
}

// PostureExport is persisted verbatim with a publication revision. Serving an
// export never re-reads mutable Neo4j state or silently applies current triage.
type PostureExport struct {
	SchemaVersion   int                         `json:"schema_version"`
	Scope           PostureScope                `json:"scope"`
	Completeness    PostureCompleteness         `json:"completeness"`
	Observations    PostureObservationTimes     `json:"observations"`
	Health          PostureHealthObservation    `json:"health"`
	Limits          PostureExportLimits         `json:"limits"`
	Suppression     PostureSuppression          `json:"suppression"`
	GraphBefore     *GraphSnapshot              `json:"graph_before,omitempty"`
	GraphAfter      GraphSnapshot               `json:"graph_after"`
	Comparison      PostureComparison           `json:"comparison"`
	Collection      *sdkingest.CollectionReport `json:"collection,omitempty"`
	Ruleset         *sdkingest.RulesetManifest  `json:"ruleset,omitempty"`
	IdentitySchemes []sdkingest.IdentityScheme  `json:"identity_schemes,omitempty"`
	Findings        []Finding                   `json:"findings"`
}

type ProjectionState struct {
	Status            string     `json:"status"`
	ScanID            string     `json:"scan_id,omitempty"`
	Error             string     `json:"error,omitempty"`
	DirtyCoverage     []string   `json:"dirty_coverage"`
	UpdatedAt         time.Time  `json:"updated_at"`
	PublishedScanID   string     `json:"published_scan_id,omitempty"`
	PublishedRevision *int64     `json:"published_revision,omitempty"`
	PublishedAt       *time.Time `json:"published_at,omitempty"`
}
