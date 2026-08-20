package ingest

const (
	CurrentVersion = 1
	IngestType     = "agenthound-ingest"
)

type IngestData struct {
	Meta  IngestMeta `json:"meta"`
	Graph GraphData  `json:"graph"`
}

type IngestMeta struct {
	Version          int                `json:"version"`
	Type             string             `json:"type"`
	Collector        string             `json:"collector"`
	CollectorVersion string             `json:"collector_version"`
	Timestamp        string             `json:"timestamp"`
	ScanID           string             `json:"scan_id"`
	Identity         CollectionIdentity `json:"identity"`
	Collection       *CollectionReport  `json:"collection,omitempty"`
	Ruleset          *RulesetManifest   `json:"ruleset,omitempty"`
	IdentitySchemes  []IdentityScheme   `json:"identity_schemes,omitempty"`

	// Extra carries scan-mode metadata that does not fit the shared envelope.
	// Unified scans store their strictly validated action and recovery record
	// under scan_execution. Other keys remain structured opaque data and pass
	// through normalization unchanged.
	Extra map[string]any `json:"extra,omitempty"`
}

type GraphData struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
}
