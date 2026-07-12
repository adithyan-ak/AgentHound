package ingest

const (
	CurrentVersion = 2
	IngestType     = "agenthound-ingest"
)

type IngestData struct {
	Meta  IngestMeta `json:"meta"`
	Graph GraphData  `json:"graph"`
}

type IngestMeta struct {
	Version          int               `json:"version"`
	Type             string            `json:"type"`
	Collector        string            `json:"collector"`
	CollectorVersion string            `json:"collector_version"`
	Timestamp        string            `json:"timestamp"`
	ScanID           string            `json:"scan_id"`
	Collection       *CollectionReport `json:"collection,omitempty"`
	Ruleset          *RulesetManifest  `json:"ruleset,omitempty"`
	IdentitySchemes  []IdentityScheme  `json:"identity_schemes,omitempty"`

	// Extra carries collector-specific or scan-mode-specific metadata that
	// doesn't fit the structured fields above. v0.2 introduces this for the
	// network-scan watermark (authorization_file_path, authorization_file_sha256,
	// allow_public_targets, network_scan_spec). Downstream tooling
	// can refuse to operate on watermark-less public-IP scans by inspecting
	// these fields.
	//
	// The validator at server/internal/ingest/validator.go does not
	// constrain Extra's contents — it is structured opaque data. The
	// normalizer passes it through unchanged.
	Extra map[string]any `json:"extra,omitempty"`
}

type GraphData struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
}
