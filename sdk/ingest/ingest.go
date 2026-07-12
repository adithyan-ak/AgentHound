package ingest

type IngestData struct {
	Meta  IngestMeta `json:"meta"`
	Graph GraphData  `json:"graph"`
}

type IngestMeta struct {
	Version          int    `json:"version"`
	Type             string `json:"type"`
	Collector        string `json:"collector"`
	CollectorVersion string `json:"collector_version"`
	Timestamp        string `json:"timestamp"`
	ScanID           string `json:"scan_id"`

	// SchemaVersion is the canonical artifact/graph contract version this
	// artifact was produced against (CurrentSchemaVersion). A reader whose
	// SchemaVersion differs MUST require a coordinated reset/re-ingest rather
	// than attempt a backward-compatible merge. Zero means "unversioned"
	// (pre-contract producers); the server treats zero as CurrentSchemaVersion
	// only during the prelaunch reset window.
	SchemaVersion int `json:"schema_version,omitempty"`
	// IdentityVersion is the node-identity derivation scheme (see
	// CurrentIdentityVersion). Collectors that must merge on a shared ID
	// (config + mcp on MCPServer) MUST agree on this value; a mismatch means
	// the graph must be rebuilt.
	IdentityVersion int `json:"identity_version,omitempty"`
	// Coverage records what this scan attempted and achieved so absence can be
	// distinguished from failure. Nil means the producer emitted no coverage
	// manifest (legacy/third-party); the server treats a nil manifest as
	// StatusUnknown, never as clean.
	Coverage *CollectionCoverage `json:"coverage,omitempty"`

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
