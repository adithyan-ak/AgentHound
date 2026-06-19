package ingest

import (
	"fmt"

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
		}
		if edge.TargetKind != "" && !ingest.AllowedNodeKinds[edge.TargetKind] {
			errs = append(errs, FieldError{
				Path:    fmt.Sprintf("graph.edges[%d].target_kind", i),
				Message: fmt.Sprintf("invalid target_kind %q", edge.TargetKind),
			})
		}
	}

	if len(errs) > 0 {
		return &ValidationError{Errors: errs}
	}
	return nil
}

func hasKind(kinds []string, want string) bool {
	for _, kind := range kinds {
		if kind == want {
			return true
		}
	}
	return false
}
