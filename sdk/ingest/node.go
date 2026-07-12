package ingest

type NodePropertySemantics string

const (
	// NodePropertySemanticsReferenceOnly marks an ownership observation that
	// asserts only the node's ID and kinds. It does not author or replace the
	// node's managed properties.
	NodePropertySemanticsReferenceOnly NodePropertySemantics = "reference_only"
)

type Node struct {
	ID                 string                `json:"id"`
	Kinds              []string              `json:"kinds"`
	Properties         map[string]any        `json:"properties"`
	ObservationDomains []string              `json:"observation_domains,omitempty"`
	PropertySemantics  NodePropertySemantics `json:"property_semantics,omitempty"`
}
