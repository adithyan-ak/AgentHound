package model

import "time"

type FindingVariant string

const (
	FindingVariantUnknown                      FindingVariant = "unknown"
	FindingVariantDefault                      FindingVariant = "default"
	FindingVariantCredentialObservedMaterial   FindingVariant = "credential_chain_observed_material"
	FindingVariantCredentialReference          FindingVariant = "credential_chain_reference"
	FindingVariantCredentialNodeReference      FindingVariant = "credential_node_reference"
	FindingVariantCrossProtocolHostCorrelation FindingVariant = "cross_protocol_host_correlation"
)

type FindingEvidenceState string

const (
	FindingEvidenceUnknown       FindingEvidenceState = "unknown"
	FindingEvidenceObserved      FindingEvidenceState = "observed_signal"
	FindingEvidenceInferred      FindingEvidenceState = "inferred"
	FindingEvidenceHypothesis    FindingEvidenceState = "hypothesis"
	FindingEvidenceReferenceOnly FindingEvidenceState = "reference_only"
)

// FindingEvidence records the detector facts used to classify a finding.
// Legacy rows default to State=unknown rather than inheriting reassuring
// semantics from a later live projection.
type FindingEvidence struct {
	State          FindingEvidenceState `json:"state"`
	Detector       string               `json:"detector,omitempty"`
	MatchType      string               `json:"match_type,omitempty"`
	Channels       []string             `json:"channels,omitempty"`
	MaterialStatus string               `json:"material_status,omitempty"`
	ExposureStatus string               `json:"exposure_status,omitempty"`
	Correlation    string               `json:"correlation,omitempty"`
}

// ExactFindingEvidence is the detector-selected witness snapshot captured
// before publication. It is persisted with the finding so detail responses do
// not re-run a similar-but-different graph query against a mutable projection.
type ExactFindingEvidence struct {
	Version  int                        `json:"version"`
	Nodes    []ExactFindingEvidenceNode `json:"nodes"`
	Edges    []ExactFindingEvidenceEdge `json:"edges"`
	Complete bool                       `json:"complete"`
	Reasons  []string                   `json:"reasons"`
}

type ExactFindingEvidenceNode struct {
	ID         string         `json:"id"`
	Kinds      []string       `json:"kinds"`
	Properties map[string]any `json:"properties"`
}

type ExactFindingEvidenceEdge struct {
	Source     string         `json:"source"`
	Target     string         `json:"target"`
	Kind       string         `json:"kind"`
	Properties map[string]any `json:"properties"`
	Synthetic  bool           `json:"synthetic"`
	Provenance map[string]any `json:"provenance,omitempty"`
}

// Finding represents a security finding derived from a composite edge.
type Finding struct {
	ID            string                `json:"id"`
	ScanID        string                `json:"scan_id,omitempty"`
	CapturedAt    *time.Time            `json:"captured_at,omitempty"`
	Severity      string                `json:"severity"`
	Category      string                `json:"category"`
	Title         string                `json:"title"`
	Description   string                `json:"description"`
	EdgeKind      string                `json:"edge_kind"`
	SourceID      string                `json:"source_id"`
	SourceName    string                `json:"source_name"`
	SourceKind    string                `json:"source_kind"`
	TargetID      string                `json:"target_id"`
	TargetName    string                `json:"target_name"`
	TargetKind    string                `json:"target_kind"`
	Confidence    float64               `json:"confidence"`
	Variant       FindingVariant        `json:"variant"`
	Evidence      FindingEvidence       `json:"evidence"`
	ExactEvidence *ExactFindingEvidence `json:"-"`
	OWASPMap      []string              `json:"owasp_map,omitempty"`
	ATLASMap      []string              `json:"atlas_map,omitempty"`
	Triage        *TriageState          `json:"triage,omitempty"`
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
