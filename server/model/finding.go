package model

import (
	"time"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

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

	// Truth-contract fields (migration 004). Populated by the rebuilt detector
	// and finding-detail layer in a later phase; omitempty keeps legacy
	// responses stable until then.

	// GenerationID scopes the finding to the graph generation it was derived
	// from.
	GenerationID string `json:"generation_id,omitempty"`
	// DetectionSubtype / DetectionVersion identify the detector variant and
	// semantics version, so a finding's derivation is reconstructable.
	DetectionSubtype string `json:"detection_subtype,omitempty"`
	DetectionVersion string `json:"detection_version,omitempty"`
	// EvidenceDAG is the typed evidence graph (observed/synthetic/reversed
	// joins, connected components) backing the finding. Shape is refined by
	// the analysis layer in a later phase.
	EvidenceDAG map[string]any `json:"evidence_dag,omitempty"`
	// CompositeProps is the immutable snapshot of the composite relationship
	// properties used by impact/remediation rendering (sensitivity, channel,
	// blast radius, gateway evidence, and confidence metadata).
	CompositeProps map[string]any `json:"composite_props,omitempty"`
	// ConfidenceBasis explains how Confidence was derived.
	ConfidenceBasis string `json:"confidence_basis,omitempty"`
	// AttackCost / WeightTotal are NULLABLE: nil means "unknown" (a required
	// weight was absent), never a benign zero. WeightMissingCount records how
	// many weights were missing.
	AttackCost         *float64 `json:"attack_cost,omitempty"`
	WeightTotal        *float64 `json:"weight_total,omitempty"`
	WeightMissingCount int      `json:"weight_missing_count,omitempty"`
	// Lifecycle is the finding lifecycle state (active/resolved/...).
	Lifecycle string `json:"lifecycle,omitempty"`
	// RuleManifest pins the rules that produced this finding.
	RuleManifest []ingest.RuleManifestEntry `json:"rule_manifest,omitempty"`
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
