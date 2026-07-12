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
	// Identity-version enforcement. Node IDs are content hashes whose derivation
	// scheme is versioned (ingest.CurrentIdentityVersion). An artifact produced
	// under a different scheme would compute non-matching IDs and silently fail
	// to merge with the current graph (e.g. config + MCP observations of the
	// same MCPServer landing as two nodes). Rather than accept it and corrupt
	// the merge, reject any explicit identity_version the server cannot honor;
	// re-collect with a current collector after a clean re-ingest. A zero value
	// (absent) means "unset" and defers to the current scheme for pre-contract
	// fixtures — collectors always stamp the real version.
	if data.Meta.IdentityVersion != 0 && data.Meta.IdentityVersion != ingest.CurrentIdentityVersion {
		errs = append(errs, FieldError{
			Path:    "meta.identity_version",
			Message: fmt.Sprintf("unsupported identity version %d; server requires %d — re-collect and re-ingest with a current collector", data.Meta.IdentityVersion, ingest.CurrentIdentityVersion),
		})
	}

	// Index node kinds by ID so edge endpoint-compatibility can resolve the
	// kind of an endpoint that is present in this payload. Edges whose
	// endpoints reference already-stored nodes (not in this payload) rely on
	// the explicit source_kind/target_kind instead.
	nodeKinds := make(map[string][]string, len(data.Graph.Nodes))
	for _, node := range data.Graph.Nodes {
		if node.ID != "" {
			nodeKinds[node.ID] = node.Kinds
		}
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

		// Endpoint-kind compatibility. When the edge kind has a declared
		// endpoint contract AND the endpoint's kind is resolvable (explicit
		// source_kind/target_kind, or a node carried in this payload), verify
		// the kind is permitted for that edge. Endpoints that reference
		// already-stored nodes with no explicit kind are deferred (the writer
		// matches them by objectid). This is a soft, resolvable-only check so
		// legitimate cross-collector edges are never rejected for lack of local
		// context, while a structurally impossible edge (e.g. a PROVIDES_TOOL
		// whose source is an MCPTool) is caught.
		if ep, ok := ingest.EdgeKindEndpoints[edge.Kind]; ok {
			if src := resolveEndpointKinds(edge.SourceKind, nodeKinds[edge.Source]); src != nil &&
				!anyKindAllowed(src, ep.SourceKinds) {
				errs = append(errs, FieldError{
					Path:    fmt.Sprintf("graph.edges[%d].source_kind", i),
					Message: fmt.Sprintf("edge %s source kind %v not in allowed %v", edge.Kind, src, ep.SourceKinds),
				})
			}
			if tgt := resolveEndpointKinds(edge.TargetKind, nodeKinds[edge.Target]); tgt != nil &&
				!anyKindAllowed(tgt, ep.TargetKinds) {
				errs = append(errs, FieldError{
					Path:    fmt.Sprintf("graph.edges[%d].target_kind", i),
					Message: fmt.Sprintf("edge %s target kind %v not in allowed %v", edge.Kind, tgt, ep.TargetKinds),
				})
			}
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

// resolveEndpointKinds returns the kind(s) to check an edge endpoint against:
// the explicit kind when set, else the payload node's kinds. Returns nil when
// neither is available (an already-stored node with no explicit kind), which
// signals the caller to defer the check.
func resolveEndpointKinds(explicit string, payloadKinds []string) []string {
	if explicit != "" {
		return []string{explicit}
	}
	if len(payloadKinds) > 0 {
		return payloadKinds
	}
	return nil
}

// anyKindAllowed reports whether any of the candidate kinds is in the allowed
// set. A node may carry multiple labels (e.g. per-service + :AIService
// umbrella); the endpoint is satisfied if any label matches.
func anyKindAllowed(candidates, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, c := range candidates {
		if hasKind(allowed, c) {
			return true
		}
	}
	return false
}
