package ingest

type NodePropertySemantics string

const (
	// NodePropertySemanticsReferenceOnly marks an ownership observation that
	// asserts only the node's ID and kinds. It does not author or replace the
	// node's managed properties.
	NodePropertySemanticsReferenceOnly NodePropertySemantics = "reference_only"
	// NodePropertySemanticsPreserveOmissions marks an authoritative node
	// observation whose supplied properties are valid but incomplete. The
	// writer may add or update supplied values, but a complete owning domain
	// must not remove properties omitted by this observation.
	NodePropertySemanticsPreserveOmissions NodePropertySemantics = "preserve_omissions"
)

type Node struct {
	ID                 string                `json:"id"`
	Kinds              []string              `json:"kinds"`
	Properties         map[string]any        `json:"properties"`
	ObservationDomains []string              `json:"observation_domains,omitempty"`
	PropertySemantics  NodePropertySemantics `json:"property_semantics,omitempty"`
}
