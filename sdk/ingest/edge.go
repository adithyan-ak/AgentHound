package ingest

type ObservationSemantics string

const (
	// ObservationSemanticsAnyOwner is the ordinary shared-fact model: a fact
	// remains current while any observation domain still owns it.
	ObservationSemanticsAnyOwner ObservationSemantics = "any_owner"

	// ObservationSemanticsAllDependencies marks a fact whose validity depends
	// on every listed observation domain. Completing any dependency domain
	// without re-observing the fact retires it.
	ObservationSemanticsAllDependencies ObservationSemantics = "all_dependencies"
)

type Edge struct {
	Source               string               `json:"source"`
	Target               string               `json:"target"`
	Kind                 string               `json:"kind"`
	SourceKind           string               `json:"source_kind,omitempty"`
	TargetKind           string               `json:"target_kind,omitempty"`
	Properties           map[string]any       `json:"properties"`
	ObservationDomains   []string             `json:"observation_domains,omitempty"`
	ObservationSemantics ObservationSemantics `json:"observation_semantics,omitempty"`
}
