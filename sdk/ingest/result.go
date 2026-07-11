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
	NodesWritten          int                    `json:"nodes_written"`
	EdgesWritten          int                    `json:"edges_written"`
	NodesSubmitted        int                    `json:"nodes_submitted"`
	EdgesSubmitted        int                    `json:"edges_submitted"`
	CountSemantics        string                 `json:"count_semantics"`
	Warnings              []string               `json:"warnings,omitempty"`
	NormalizationStatus   NormalizationStatus    `json:"normalization_status"`
	NormalizationWarnings []NormalizationWarning `json:"normalization_warnings,omitempty"`
	Collection            *CollectionReport      `json:"collection,omitempty"`
	Stages                []StageResult          `json:"stages,omitempty"`
	PostProcessingStats   []PostProcessingStat   `json:"post_processing_stats,omitempty"`
	GraphBefore           *GraphTotals           `json:"graph_before,omitempty"`
	GraphAfter            *GraphTotals           `json:"graph_after,omitempty"`
	PublishedRevision     *int64                 `json:"published_revision,omitempty"`
	Duration              time.Duration          `json:"duration"`
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
