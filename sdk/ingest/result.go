package ingest

import "time"

type NormalizationStatus string

const (
	NormalizationStatusUnknown  NormalizationStatus = "unknown"
	NormalizationStatusComplete NormalizationStatus = "complete"
	NormalizationStatusWarning  NormalizationStatus = "warning"
	NormalizationStatusDegraded NormalizationStatus = "degraded"
)

type NormalizationWarning struct {
	Code              string              `json:"code"`
	Status            NormalizationStatus `json:"status"`
	Message           string              `json:"message"`
	Context           string              `json:"context,omitempty"`
	Property          string              `json:"property,omitempty"`
	PublicationUnsafe bool                `json:"publication_unsafe"`
}

type IngestResult struct {
	ScanID                string                 `json:"scan_id"`
	Outcome               OutcomeState           `json:"outcome"`
	ProjectionStatus      string                 `json:"projection_status"`
	Submitted             FactCounts             `json:"submitted"`
	WriteRows             FactCounts             `json:"write_rows"`
	Findings              int                    `json:"findings"`
	GraphTotals           FrozenGraphTotals      `json:"graph_totals"`
	Warnings              []string               `json:"warnings,omitempty"`
	NormalizationStatus   NormalizationStatus    `json:"normalization_status"`
	NormalizationWarnings []NormalizationWarning `json:"normalization_warnings,omitempty"`
	Collection            CollectionReport       `json:"collection"`
	Identity              IngestIdentityResult   `json:"identity"`
	Stages                []StageResult          `json:"stages,omitempty"`
	PostProcessingStats   []PostProcessingStat   `json:"post_processing_stats,omitempty"`
	PublishedRevision     *int64                 `json:"published_revision,omitempty"`
	Duration              time.Duration          `json:"duration"`
}

type IngestIdentityResult struct {
	CollectionPointID string                  `json:"collection_point_id"`
	NetworkContextID  string                  `json:"network_context_id"`
	Quality           IdentityQuality         `json:"quality"`
	NetworkQuality    IdentityQuality         `json:"network_quality"`
	NetworkClass      NetworkClass            `json:"network_class"`
	Display           CollectionDisplayLabels `json:"display,omitempty"`
	Recognition       string                  `json:"recognition"`
}

type FactCounts struct {
	Nodes int `json:"nodes"`
	Edges int `json:"edges"`
}

type FrozenGraphTotals struct {
	Before *GraphTotals `json:"before"`
	After  *GraphTotals `json:"after"`
}

type GraphTotals struct {
	NodeCounts map[string]int64 `json:"node_counts"`
	EdgeCounts map[string]int64 `json:"edge_counts"`
	TotalNodes int64            `json:"total_nodes"`
	TotalEdges int64            `json:"total_edges"`
}

type StageResult struct {
	Name     string        `json:"name"`
	State    OutcomeState  `json:"state"`
	Required bool          `json:"required"`
	Duration time.Duration `json:"duration"`
	Error    string        `json:"error,omitempty"`
}

type PostProcessingStat struct {
	ProcessorName string        `json:"processor_name"`
	EdgesCreated  int           `json:"edges_created"`
	NodesUpdated  int           `json:"nodes_updated"`
	Duration      time.Duration `json:"duration"`
	Error         string        `json:"error,omitempty"`
}
