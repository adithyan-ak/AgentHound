package ingest

import (
	"fmt"
	"strings"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

type FieldError struct {
	Path    string `json:"path"`
	Message string `json:"message"`
}

type ValidationError struct {
	Errors []FieldError `json:"errors"`
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("validation failed: %d errors", len(e.Errors))
}

type Validator struct{}

func NewValidator() *Validator {
	return &Validator{}
}

func (v *Validator) Validate(data *ingest.IngestData) error {
	var errs []FieldError
	declaredCoverage := make(map[string]bool)
	if data.Meta.Collection != nil {
		for i, key := range data.Meta.Collection.CoverageKeys {
			if err := validateCoverageKey(key); err != "" {
				errs = append(errs, FieldError{
					Path:    fmt.Sprintf("meta.collection.coverage_keys[%d]", i),
					Message: err,
				})
				continue
			}
			declaredCoverage[key] = true
		}
	}
	nodeKindsByID := make(map[string][]string, len(data.Graph.Nodes))
	for _, node := range data.Graph.Nodes {
		if node.ID == "" {
			continue
		}
		for _, kind := range node.Kinds {
			if !hasKind(nodeKindsByID[node.ID], kind) {
				nodeKindsByID[node.ID] = append(nodeKindsByID[node.ID], kind)
			}
		}
	}

	if data.Meta.Version != 1 {
		errs = append(errs, FieldError{Path: "meta.version", Message: fmt.Sprintf("must be 1, got %d", data.Meta.Version)})
	}
	if data.Meta.Type != "agenthound-ingest" {
		errs = append(errs, FieldError{Path: "meta.type", Message: fmt.Sprintf("must be 'agenthound-ingest', got %q", data.Meta.Type)})
	}
	if !ingest.AllowedCollectors[data.Meta.Collector] {
		errs = append(errs, FieldError{Path: "meta.collector", Message: fmt.Sprintf("must be one of mcp/a2a/config, got %q", data.Meta.Collector)})
	}
	if data.Meta.ScanID == "" {
		errs = append(errs, FieldError{Path: "meta.scan_id", Message: "must not be empty"})
	}

	for i, node := range data.Graph.Nodes {
		if node.ID == "" {
			errs = append(errs, FieldError{
				Path:    fmt.Sprintf("graph.nodes[%d].id", i),
				Message: "must not be empty",
			})
		}
		if len(node.Kinds) == 0 {
			errs = append(errs, FieldError{
				Path:    fmt.Sprintf("graph.nodes[%d].kinds", i),
				Message: "must have at least one kind",
			})
		}
		for j, kind := range node.Kinds {
			if !ingest.AllowedNodeKinds[kind] {
				errs = append(errs, FieldError{
					Path:    fmt.Sprintf("graph.nodes[%d].kinds[%d]", i, j),
					Message: fmt.Sprintf("invalid node kind %q", kind),
				})
			}
		}
		errs = append(errs, validateObservationDomains(
			node.ObservationDomains,
			declaredCoverage,
			fmt.Sprintf("graph.nodes[%d].observation_domains", i),
		)...)
		if hasKind(node.Kinds, "Credential") {
			valueHash, _ := node.Properties["value_hash"].(string)
			if valueHash == "" {
				errs = append(errs, FieldError{
					Path:    fmt.Sprintf("graph.nodes[%d].properties.value_hash", i),
					Message: "Credential nodes must include non-empty value_hash",
				})
			}
		}
	}

	for i, edge := range data.Graph.Edges {
		if edge.Source == "" {
			errs = append(errs, FieldError{
				Path:    fmt.Sprintf("graph.edges[%d].source", i),
				Message: "must not be empty",
			})
		}
		if edge.Target == "" {
			errs = append(errs, FieldError{
				Path:    fmt.Sprintf("graph.edges[%d].target", i),
				Message: "must not be empty",
			})
		}
		if !ingest.RawEdgeKinds[edge.Kind] {
			errs = append(errs, FieldError{
				Path:    fmt.Sprintf("graph.edges[%d].kind", i),
				Message: fmt.Sprintf("invalid edge kind %q", edge.Kind),
			})
		}
		errs = append(errs, validateObservationDomains(
			edge.ObservationDomains,
			declaredCoverage,
			fmt.Sprintf("graph.edges[%d].observation_domains", i),
		)...)
		// source_kind/target_kind are interpolated as Neo4j labels in the graph
		// writer's MATCH clause (labels cannot be query-parameterized), so any
		// non-empty value MUST be an allowed node kind. This mirrors the node
		// kind check above and the analysis handlers' validNodeKind guard,
		// closing the same Cypher-injection class on the ingest path.
		if edge.SourceKind != "" && !ingest.AllowedNodeKinds[edge.SourceKind] {
			errs = append(errs, FieldError{
				Path:    fmt.Sprintf("graph.edges[%d].source_kind", i),
				Message: fmt.Sprintf("invalid source_kind %q", edge.SourceKind),
			})
		} else if edge.SourceKind != "" && !ingest.SourceKindAllowed(edge.Kind, edge.SourceKind) {
			// The label is a valid node kind but is not a permitted source for
			// this edge kind. Accepting it would let a malformed import write a
			// direction-correct but semantically impossible relationship (e.g.
			// MCPTool-PROVIDES_TOOL-MCPServer), which the UI would then render
			// as an authoritative graph fact with inverted roles.
			errs = append(errs, FieldError{
				Path:    fmt.Sprintf("graph.edges[%d].source_kind", i),
				Message: fmt.Sprintf("source_kind %q is not a valid source for edge kind %q", edge.SourceKind, edge.Kind),
			})
		}
		if edge.TargetKind != "" && !ingest.AllowedNodeKinds[edge.TargetKind] {
			errs = append(errs, FieldError{
				Path:    fmt.Sprintf("graph.edges[%d].target_kind", i),
				Message: fmt.Sprintf("invalid target_kind %q", edge.TargetKind),
			})
		} else if edge.TargetKind != "" && !ingest.TargetKindAllowed(edge.Kind, edge.TargetKind) {
			errs = append(errs, FieldError{
				Path:    fmt.Sprintf("graph.edges[%d].target_kind", i),
				Message: fmt.Sprintf("target_kind %q is not a valid target for edge kind %q", edge.TargetKind, edge.Kind),
			})
		}

		// Validate against the labels on the referenced nodes. Omitted endpoint
		// kinds must have an allowed intersection with the actual node labels;
		// the normalizer then materializes that actual label before write.
		if ingest.RawEdgeKinds[edge.Kind] {
			endpoints, ok := ingest.EdgeKindEndpoints[edge.Kind]
			if !ok {
				errs = append(errs, FieldError{
					Path:    fmt.Sprintf("graph.edges[%d].kind", i),
					Message: fmt.Sprintf("edge kind %q has no endpoint schema", edge.Kind),
				})
			} else {
				errs = append(errs, validateReferencedEndpoint(
					nodeKindsByID, i, "source", edge.Source, edge.SourceKind, endpoints.SourceKinds,
				)...)
				errs = append(errs, validateReferencedEndpoint(
					nodeKindsByID, i, "target", edge.Target, edge.TargetKind, endpoints.TargetKinds,
				)...)
			}
		}
	}

	if len(errs) > 0 {
		return &ValidationError{Errors: errs}
	}
	return nil
}

func validateCoverageKey(key string) string {
	switch {
	case strings.TrimSpace(key) == "":
		return "must not be empty"
	case key != strings.TrimSpace(key):
		return "must not have leading or trailing whitespace"
	case len(key) > 256:
		return "must be at most 256 bytes"
	case strings.Contains(key, "\x1f"):
		return "must not contain reserved separator"
	default:
		return ""
	}
}

func validateObservationDomains(
	domains []string,
	declaredCoverage map[string]bool,
	path string,
) []FieldError {
	var errs []FieldError
	for i, domain := range domains {
		if err := validateCoverageKey(domain); err != "" {
			errs = append(errs, FieldError{
				Path:    fmt.Sprintf("%s[%d]", path, i),
				Message: err,
			})
			continue
		}
		if !declaredCoverage[domain] {
			errs = append(errs, FieldError{
				Path:    fmt.Sprintf("%s[%d]", path, i),
				Message: fmt.Sprintf("domain %q is not declared in meta.collection.coverage_keys", domain),
			})
		}
	}
	return errs
}

func validateReferencedEndpoint(
	nodeKindsByID map[string][]string,
	edgeIndex int,
	role, nodeID, declaredKind string,
	allowedKinds []string,
) []FieldError {
	if nodeID == "" {
		return nil
	}
	kinds, ok := nodeKindsByID[nodeID]
	if !ok {
		return []FieldError{{
			Path:    fmt.Sprintf("graph.edges[%d].%s", edgeIndex, role),
			Message: fmt.Sprintf("%s node %q is not present in graph.nodes", role, nodeID),
		}}
	}
	if declaredKind != "" {
		if hasKind(kinds, declaredKind) {
			return nil
		}
		return []FieldError{{
			Path: fmt.Sprintf("graph.edges[%d].%s_kind", edgeIndex, role),
			Message: fmt.Sprintf(
				"declared %s_kind %q does not match referenced node %q kinds %v",
				role, declaredKind, nodeID, kinds,
			),
		}}
	}

	for _, actualKind := range kinds {
		if hasKind(allowedKinds, actualKind) {
			return nil
		}
	}

	return []FieldError{{
		Path: fmt.Sprintf("graph.edges[%d].%s_kind", edgeIndex, role),
		Message: fmt.Sprintf(
			"referenced %s node %q kinds %v do not match allowed kinds %v",
			role, nodeID, kinds, allowedKinds,
		),
	}}
}

func hasKind(kinds []string, want string) bool {
	for _, kind := range kinds {
		if kind == want {
			return true
		}
	}
	return false
}
