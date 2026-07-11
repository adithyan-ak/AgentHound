package ingest

type Edge struct {
	Source             string         `json:"source"`
	Target             string         `json:"target"`
	Kind               string         `json:"kind"`
	SourceKind         string         `json:"source_kind,omitempty"`
	TargetKind         string         `json:"target_kind,omitempty"`
	Properties         map[string]any `json:"properties"`
	ObservationDomains []string       `json:"observation_domains,omitempty"`
}
