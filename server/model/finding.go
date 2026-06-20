package model

import "time"

// Finding represents a security finding derived from a composite edge.
type Finding struct {
	ID          string       `json:"id"`
	Severity    string       `json:"severity"`
	Category    string       `json:"category"`
	Title       string       `json:"title"`
	Description string       `json:"description"`
	EdgeKind    string       `json:"edge_kind"`
	SourceID    string       `json:"source_id"`
	SourceName  string       `json:"source_name"`
	SourceKind  string       `json:"source_kind"`
	TargetID    string       `json:"target_id"`
	TargetName  string       `json:"target_name"`
	TargetKind  string       `json:"target_kind"`
	Confidence  float64      `json:"confidence"`
	OWASPMap    []string     `json:"owasp_map,omitempty"`
	ATLASMap    []string     `json:"atlas_map,omitempty"`
	Triage      *TriageState `json:"triage,omitempty"`
}

// TriageState is the cross-scan analyst decision attached to a finding,
// keyed by the finding's 16-char fingerprint. Persisted in the
// finding_triage table; co-located here so all finding-shaped types stay
// together.
type TriageState struct {
	Status    string    `json:"status"`
	Note      string    `json:"note"`
	UpdatedAt time.Time `json:"updated_at"`
}
