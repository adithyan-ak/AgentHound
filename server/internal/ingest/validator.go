package ingest

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/adithyan-ak/agenthound/sdk/common"
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
	coverageOutcomes := make(map[string]bool)
	if data.Meta.Collection == nil {
		errs = append(errs, FieldError{
			Path:    "meta.collection",
			Message: "is required for ingest v3",
		})
	} else {
		if !validOutcomeState(data.Meta.Collection.State) {
			errs = append(errs, FieldError{
				Path:    "meta.collection.state",
				Message: fmt.Sprintf("must be an explicit outcome state, got %q", data.Meta.Collection.State),
			})
		}
		if len(data.Meta.Collection.CoverageKeys) == 0 {
			errs = append(errs, FieldError{
				Path:    "meta.collection.coverage_keys",
				Message: "must declare at least one canonical scoped key",
			})
		}
		for i, key := range data.Meta.Collection.CoverageKeys {
			if err := validateCoverageKey(key); err != "" {
				errs = append(errs, FieldError{
					Path:    fmt.Sprintf("meta.collection.coverage_keys[%d]", i),
					Message: err,
				})
				continue
			}
			if declaredCoverage[key] {
				errs = append(errs, FieldError{
					Path:    fmt.Sprintf("meta.collection.coverage_keys[%d]", i),
					Message: fmt.Sprintf("duplicate coverage key %q", key),
				})
			}
			declaredCoverage[key] = true
		}
		errs = append(
			errs,
			validateAuthoritativeRoots(
				data.Meta.Collection.AuthoritativeRoots,
				declaredCoverage,
			)...,
		)
		if len(data.Meta.Collection.Outcomes) == 0 {
			errs = append(errs, FieldError{
				Path:    "meta.collection.outcomes",
				Message: "must contain at least one scoped outcome",
			})
		}
		for i, outcome := range data.Meta.Collection.Outcomes {
			path := fmt.Sprintf("meta.collection.outcomes[%d]", i)
			if !ingest.AllowedCollectors[outcome.Collector] {
				errs = append(errs, FieldError{
					Path:    path + ".collector",
					Message: fmt.Sprintf("invalid collector %q", outcome.Collector),
				})
			}
			if err := validateCoverageKey(outcome.CoverageKey); err != "" {
				errs = append(errs, FieldError{
					Path:    path + ".coverage_key",
					Message: err,
				})
			} else {
				if !declaredCoverage[outcome.CoverageKey] {
					errs = append(errs, FieldError{
						Path:    path + ".coverage_key",
						Message: fmt.Sprintf("key %q is not declared in coverage_keys", outcome.CoverageKey),
					})
				}
				coverageOutcomes[outcome.CoverageKey] = true
				if strings.Split(outcome.CoverageKey, ":")[0] != outcome.Collector {
					errs = append(errs, FieldError{
						Path:    path + ".coverage_key",
						Message: "collector prefix must match outcome.collector",
					})
				}
			}
			if strings.TrimSpace(outcome.Target) == "" {
				errs = append(errs, FieldError{Path: path + ".target", Message: "must not be empty"})
			}
			if strings.TrimSpace(outcome.Method) == "" {
				errs = append(errs, FieldError{Path: path + ".method", Message: "must not be empty"})
			}
			if !validOutcomeState(outcome.State) {
				errs = append(errs, FieldError{
					Path:    path + ".state",
					Message: fmt.Sprintf("must be an explicit outcome state, got %q", outcome.State),
				})
			}
			if outcome.Items < 0 {
				errs = append(errs, FieldError{Path: path + ".items", Message: "must be non-negative"})
			}
		}
		if len(data.Meta.Collection.Outcomes) > 0 {
			aggregate := ingest.AggregateOutcomeState(data.Meta.Collection.Outcomes)
			if aggregate != data.Meta.Collection.State {
				errs = append(errs, FieldError{
					Path: "meta.collection.state",
					Message: fmt.Sprintf(
						"must match aggregate outcome state %q",
						aggregate,
					),
				})
			}
		}
		for key := range declaredCoverage {
			if !coverageOutcomes[key] {
				errs = append(errs, FieldError{
					Path:    "meta.collection.outcomes",
					Message: fmt.Sprintf("missing outcome for coverage key %q", key),
				})
			}
		}
	}
	nodeKindsByID := make(map[string][]string, len(data.Graph.Nodes))
	nodesByID := make(map[string]ingest.Node, len(data.Graph.Nodes))
	concreteKindByID := make(map[string]string, len(data.Graph.Nodes))
	for i, node := range data.Graph.Nodes {
		if node.ID == "" {
			continue
		}
		nodesByID[node.ID] = node
		allKindsAllowed := len(node.Kinds) > 0
		for _, kind := range node.Kinds {
			if !ingest.AllowedNodeKinds[kind] {
				allKindsAllowed = false
			}
			if !hasKind(nodeKindsByID[node.ID], kind) {
				nodeKindsByID[node.ID] = append(nodeKindsByID[node.ID], kind)
			}
		}
		if !allKindsAllowed {
			continue
		}
		concreteKind := ingest.ConcreteNodeKind(node.Kinds)
		if concreteKind == "" {
			errs = append(errs, FieldError{
				Path:    fmt.Sprintf("graph.nodes[%d].kinds", i),
				Message: "must contain exactly one concrete kind first, followed only by documented umbrella companions",
			})
			continue
		}
		if prior := concreteKindByID[node.ID]; prior != "" && prior != concreteKind {
			errs = append(errs, FieldError{
				Path: fmt.Sprintf("graph.nodes[%d].kinds", i),
				Message: fmt.Sprintf(
					"object ID %q has conflicting concrete kinds %q and %q",
					node.ID, prior, concreteKind,
				),
			})
			continue
		}
		concreteKindByID[node.ID] = concreteKind
	}

	if data.Meta.Version != ingest.CurrentVersion {
		errs = append(errs, FieldError{
			Path:    "meta.version",
			Message: fmt.Sprintf("must be %d, got %d", ingest.CurrentVersion, data.Meta.Version),
		})
	}
	if data.Meta.Type != ingest.IngestType {
		errs = append(errs, FieldError{Path: "meta.type", Message: fmt.Sprintf("must be %q, got %q", ingest.IngestType, data.Meta.Type)})
	}
	if !ingest.AllowedCollectors[data.Meta.Collector] {
		errs = append(errs, FieldError{Path: "meta.collector", Message: fmt.Sprintf("must be one of mcp/a2a/config/scan, got %q", data.Meta.Collector)})
	}
	if strings.TrimSpace(data.Meta.CollectorVersion) == "" {
		errs = append(errs, FieldError{Path: "meta.collector_version", Message: "must not be empty"})
	}
	if _, err := time.Parse(time.RFC3339, data.Meta.Timestamp); err != nil {
		errs = append(errs, FieldError{Path: "meta.timestamp", Message: "must be an RFC3339 timestamp"})
	}
	if data.Meta.ScanID == "" {
		errs = append(errs, FieldError{Path: "meta.scan_id", Message: "must not be empty"})
	}
	if err := ingest.ValidateOriginID("host_id", data.Meta.Origin.HostID); err != nil {
		errs = append(errs, FieldError{Path: "meta.origin.host_id", Message: err.Error()})
	}
	if err := ingest.ValidateOriginID(
		"network_realm_id",
		data.Meta.Origin.NetworkRealmID,
	); err != nil {
		errs = append(errs, FieldError{
			Path:    "meta.origin.network_realm_id",
			Message: err.Error(),
		})
	}
	errs = append(errs, validateRuleset(data.Meta.Ruleset)...)
	errs = append(errs, validateIdentitySchemes(data.Meta.IdentitySchemes)...)
	if data.Graph.Nodes == nil {
		errs = append(errs, FieldError{Path: "graph.nodes", Message: "must be a non-null array"})
	}
	if data.Graph.Edges == nil {
		errs = append(errs, FieldError{Path: "graph.edges", Message: "must be a non-null array"})
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
		if node.Properties == nil {
			errs = append(errs, FieldError{
				Path:    fmt.Sprintf("graph.nodes[%d].properties", i),
				Message: "must be a non-null object",
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
		errs = append(errs, validateNodePropertySemantics(node, i)...)
		errs = append(errs, validateCanonicalPropertyKeys(
			node.Properties,
			fmt.Sprintf("graph.nodes[%d].properties", i),
		)...)
		errs = append(errs, validateRemovedGraphProperties(
			node.Properties,
			fmt.Sprintf("graph.nodes[%d].properties", i),
		)...)
		if node.PropertySemantics != ingest.NodePropertySemanticsReferenceOnly {
			errs = append(errs, validateCanonicalNodeProperties(node, i)...)
			if hasKind(node.Kinds, "Credential") {
				errs = append(errs, validateCredentialProperties(node.Properties, i)...)
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
		if edge.Properties == nil {
			errs = append(errs, FieldError{
				Path:    fmt.Sprintf("graph.edges[%d].properties", i),
				Message: "must be a non-null object",
			})
		}
		if edge.SourceKind == "" {
			errs = append(errs, FieldError{
				Path:    fmt.Sprintf("graph.edges[%d].source_kind", i),
				Message: "must not be empty in ingest v3",
			})
		}
		if edge.TargetKind == "" {
			errs = append(errs, FieldError{
				Path:    fmt.Sprintf("graph.edges[%d].target_kind", i),
				Message: "must not be empty in ingest v3",
			})
		}
		errs = append(errs, validateObservationDomains(
			edge.ObservationDomains,
			declaredCoverage,
			fmt.Sprintf("graph.edges[%d].observation_domains", i),
		)...)
		errs = append(errs, validateObservationSemantics(edge, i)...)
		errs = append(errs, validateCanonicalPropertyKeys(
			edge.Properties,
			fmt.Sprintf("graph.edges[%d].properties", i),
		)...)
		errs = append(errs, validateRemovedGraphProperties(
			edge.Properties,
			fmt.Sprintf("graph.edges[%d].properties", i),
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

		// Validate explicit endpoint kinds against the referenced node labels.
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
			// Every raw edge is persisted to Neo4j and is therefore
			// topology-traversable: the topology weighted-path endpoint
			// (Cost=risk_weight) walks EVERY relationship regardless of kind
			// and rejects an edge whose risk_weight is absent, non-numeric,
			// NaN/Inf, or negative (server/internal/analysis/traversal.go
			// traversalEdgeCost). Enforcing the same contract at ingest time —
			// with no default and no compatibility fallback — turns that
			// endpoint-time 500 into a rejected import.
			errs = append(errs, validateEdgeRiskWeight(edge.Properties, i)...)
		}
		errs = append(errs, validateStdioChildID(nodesByID, edge, i)...)
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
	}
	parts := strings.Split(key, ":")
	if len(parts) != 4 ||
		!ingest.AllowedCollectors[parts[0]] ||
		parts[1] == "" ||
		parts[2] != "sha256" {
		return "must be a canonical scoped key (<collector>:<scope>:sha256:<digest>)"
	}
	digest, err := hex.DecodeString(parts[3])
	if err != nil || len(digest) != 32 || parts[3] != strings.ToLower(parts[3]) {
		return "must end with a 64-character SHA-256 digest"
	}
	return ""
}

func validateAuthoritativeRoots(
	roots []ingest.CoverageRoot,
	declaredCoverage map[string]bool,
) []FieldError {
	var errs []FieldError
	seenRoots := make(map[string]bool, len(roots))
	for i, root := range roots {
		path := fmt.Sprintf("meta.collection.authoritative_roots[%d]", i)
		if err := validateCoverageKey(root.CoverageKey); err != "" {
			errs = append(errs, FieldError{
				Path:    path + ".coverage_key",
				Message: err,
			})
			continue
		}
		parts := strings.Split(root.CoverageKey, ":")
		if parts[1] != "root" {
			errs = append(errs, FieldError{
				Path:    path + ".coverage_key",
				Message: "must use the root scope kind",
			})
		}
		if !declaredCoverage[root.CoverageKey] {
			errs = append(errs, FieldError{
				Path:    path + ".coverage_key",
				Message: fmt.Sprintf("key %q is not declared in coverage_keys", root.CoverageKey),
			})
		}
		if seenRoots[root.CoverageKey] {
			errs = append(errs, FieldError{
				Path:    path + ".coverage_key",
				Message: fmt.Sprintf("duplicate authoritative root %q", root.CoverageKey),
			})
		}
		seenRoots[root.CoverageKey] = true

		children := make(map[string]bool, len(root.ChildCoverageKeys))
		for j, child := range root.ChildCoverageKeys {
			childPath := fmt.Sprintf("%s.child_coverage_keys[%d]", path, j)
			if err := validateCoverageKey(child); err != "" {
				errs = append(errs, FieldError{Path: childPath, Message: err})
				continue
			}
			if strings.Split(child, ":")[0] != parts[0] {
				errs = append(errs, FieldError{
					Path:    childPath,
					Message: "collector prefix must match authoritative root",
				})
			}
			if child == root.CoverageKey {
				errs = append(errs, FieldError{
					Path:    childPath,
					Message: "root cannot be its own child",
				})
			}
			if !declaredCoverage[child] {
				errs = append(errs, FieldError{
					Path:    childPath,
					Message: fmt.Sprintf("key %q is not declared in coverage_keys", child),
				})
			}
			if children[child] {
				errs = append(errs, FieldError{
					Path:    childPath,
					Message: fmt.Sprintf("duplicate child coverage key %q", child),
				})
			}
			children[child] = true
		}
		for key := range declaredCoverage {
			keyParts := strings.Split(key, ":")
			if key != root.CoverageKey && keyParts[0] == parts[0] && !children[key] {
				errs = append(errs, FieldError{
					Path: path + ".child_coverage_keys",
					Message: fmt.Sprintf(
						"must include declared child coverage key %q",
						key,
					),
				})
			}
		}
	}
	return errs
}

func validateObservationDomains(
	domains []string,
	declaredCoverage map[string]bool,
	path string,
) []FieldError {
	var errs []FieldError
	if len(domains) == 0 {
		return []FieldError{{
			Path:    path,
			Message: "must contain at least one declared domain in ingest v3",
		}}
	}
	seen := make(map[string]bool, len(domains))
	for i, domain := range domains {
		if err := validateCoverageKey(domain); err != "" {
			errs = append(errs, FieldError{
				Path:    fmt.Sprintf("%s[%d]", path, i),
				Message: err,
			})
			continue
		}
		if seen[domain] {
			errs = append(errs, FieldError{
				Path:    fmt.Sprintf("%s[%d]", path, i),
				Message: fmt.Sprintf("duplicate domain %q", domain),
			})
		}
		seen[domain] = true
		if !declaredCoverage[domain] {
			errs = append(errs, FieldError{
				Path:    fmt.Sprintf("%s[%d]", path, i),
				Message: fmt.Sprintf("domain %q is not declared in meta.collection.coverage_keys", domain),
			})
		}
	}
	return errs
}

func validateNodePropertySemantics(node ingest.Node, index int) []FieldError {
	path := fmt.Sprintf("graph.nodes[%d].property_semantics", index)
	switch node.PropertySemantics {
	case "":
		return nil
	case ingest.NodePropertySemanticsReferenceOnly:
		if len(node.Properties) != 0 {
			return []FieldError{{
				Path:    fmt.Sprintf("graph.nodes[%d].properties", index),
				Message: "must be empty when property_semantics is reference_only",
			}}
		}
		return nil
	default:
		return []FieldError{{
			Path:    path,
			Message: fmt.Sprintf("invalid node property semantics %q", node.PropertySemantics),
		}}
	}
}

func validateObservationSemantics(edge ingest.Edge, index int) []FieldError {
	path := fmt.Sprintf("graph.edges[%d].observation_semantics", index)
	switch edge.ObservationSemantics {
	case "", ingest.ObservationSemanticsAnyOwner:
		return nil
	case ingest.ObservationSemanticsAllDependencies:
		seen := make(map[string]bool, len(edge.ObservationDomains))
		for _, domain := range edge.ObservationDomains {
			if strings.TrimSpace(domain) != "" {
				seen[domain] = true
			}
		}
		if len(seen) < 2 {
			return []FieldError{{
				Path:    path,
				Message: "all_dependencies requires at least two distinct observation domains",
			}}
		}
		return nil
	default:
		return []FieldError{{
			Path:    path,
			Message: fmt.Sprintf("invalid observation semantics %q", edge.ObservationSemantics),
		}}
	}
}

func validOutcomeState(state ingest.OutcomeState) bool {
	switch state {
	case ingest.OutcomeUnknown,
		ingest.OutcomeNotApplicable,
		ingest.OutcomeComplete,
		ingest.OutcomePartial,
		ingest.OutcomeFailed,
		ingest.OutcomeTruncated:
		return true
	default:
		return false
	}
}

func validateRuleset(ruleset *ingest.RulesetManifest) []FieldError {
	if ruleset == nil {
		return []FieldError{{Path: "meta.ruleset", Message: "is required for ingest v3"}}
	}
	var errs []FieldError
	if strings.TrimSpace(ruleset.Digest) == "" {
		errs = append(errs, FieldError{Path: "meta.ruleset.digest", Message: "must not be empty"})
	}
	if !validOutcomeState(ruleset.LoadState) {
		errs = append(errs, FieldError{
			Path:    "meta.ruleset.load_state",
			Message: fmt.Sprintf("must be an explicit outcome state, got %q", ruleset.LoadState),
		})
	}
	if strings.TrimSpace(ruleset.Authenticity) == "" {
		errs = append(errs, FieldError{Path: "meta.ruleset.authenticity", Message: "must not be empty"})
	}
	for i, entry := range ruleset.Entries {
		path := fmt.Sprintf("meta.ruleset.entries[%d]", i)
		if entry.Type == "" || entry.ID == "" || entry.Version <= 0 ||
			entry.SemanticSHA256 == "" || entry.Source == "" {
			errs = append(errs, FieldError{
				Path:    path,
				Message: "must include type, id, positive version, semantic_sha256, and source",
			})
		}
	}
	return errs
}

func validateIdentitySchemes(schemes []ingest.IdentityScheme) []FieldError {
	if len(schemes) == 0 {
		return []FieldError{{
			Path:    "meta.identity_schemes",
			Message: "must declare at least one current identity scheme",
		}}
	}
	var errs []FieldError
	for i, scheme := range schemes {
		path := fmt.Sprintf("meta.identity_schemes[%d]", i)
		if !ingest.AllowedNodeKinds[scheme.EntityKind] {
			errs = append(errs, FieldError{
				Path:    path + ".entity_kind",
				Message: fmt.Sprintf("invalid entity kind %q", scheme.EntityKind),
			})
		}
		if strings.TrimSpace(scheme.Scheme) == "" {
			errs = append(errs, FieldError{Path: path + ".scheme", Message: "must not be empty"})
		}
		if scheme.Version <= 0 {
			errs = append(errs, FieldError{Path: path + ".version", Message: "must be positive"})
		}
		if scheme.EntityKind == "MCPServer" && scheme.Transport == "stdio" &&
			(scheme.Scheme != ingest.MCPStdioIdentitySchemeV3 || scheme.Version != 3) {
			errs = append(errs, FieldError{
				Path:    path,
				Message: "stdio MCPServer identity must use mcp_stdio_v3_hashed_argv version 3",
			})
		}
	}
	return errs
}

var forbiddenPropertyAliases = map[string]string{
	"parameters":      "parameter_size",
	"is_local":        "scope",
	"is_private":      "scope",
	"is_public":       "scope",
	"signature_valid": "signature_verification_status",
	"auth_posture":    "auth_strength",
	"is_exposed":      "exposure_status",
}

var removedGraphProperties = []string{
	"identity_alias_candidates",
	"identity_alias_target",
	"identity_compatibility",
	"identity_quarantined",
	"legacy_alias_state",
	"legacy_identity_quarantined",
	"legacy_objectid",
	"legacy_observation",
	"observation_managed",
}

func validateCanonicalPropertyKeys(properties map[string]any, path string) []FieldError {
	var errs []FieldError
	for key := range properties {
		if !isCanonicalPropertyKey(key) {
			errs = append(errs, FieldError{
				Path:    path + "." + key,
				Message: "property key must be canonical snake_case",
			})
		}
	}
	return errs
}

func isCanonicalPropertyKey(key string) bool {
	if key == "" || key[0] < 'a' || key[0] > 'z' {
		return false
	}
	for i := 1; i < len(key); i++ {
		char := key[i]
		if (char < 'a' || char > 'z') &&
			(char < '0' || char > '9') &&
			char != '_' {
			return false
		}
	}
	return true
}

func validateRemovedGraphProperties(properties map[string]any, path string) []FieldError {
	var errs []FieldError
	for _, property := range removedGraphProperties {
		if _, exists := properties[property]; exists {
			errs = append(errs, FieldError{
				Path:    path + "." + property,
				Message: "removed compatibility property is not allowed",
			})
		}
	}
	return errs
}

func validateCanonicalNodeProperties(node ingest.Node, index int) []FieldError {
	var errs []FieldError
	for alias, canonical := range forbiddenPropertyAliases {
		if _, exists := node.Properties[alias]; exists {
			errs = append(errs, FieldError{
				Path:    fmt.Sprintf("graph.nodes[%d].properties.%s", index, alias),
				Message: fmt.Sprintf("legacy alias is not allowed; use %s", canonical),
			})
		}
	}
	if hasKind(node.Kinds, "Host") {
		scope, _ := node.Properties["scope"].(string)
		switch scope {
		case "local", "private", "public", "unknown":
		default:
			errs = append(errs, FieldError{
				Path:    fmt.Sprintf("graph.nodes[%d].properties.scope", index),
				Message: fmt.Sprintf("Host nodes require canonical scope, got %q", scope),
			})
		}
	}
	if hasKind(node.Kinds, "MCPServer") {
		transport, transportOK := node.Properties["transport"].(string)
		if !transportOK || (transport != "http" && transport != "stdio") {
			errs = append(errs, FieldError{
				Path:    fmt.Sprintf("graph.nodes[%d].properties.transport", index),
				Message: "authoritative MCPServer transport must be the canonical string http or stdio",
			})
		}

		// Transport configuration is executable, credential-bearing input and must
		// never cross the ingest boundary. Enforce this independently of the
		// declared transport so an omitted or malformed discriminator cannot bypass
		// the artifact privacy contract.
		for _, property := range []string{"args", "env", "headers", "url"} {
			if _, exists := node.Properties[property]; exists {
				errs = append(errs, FieldError{
					Path: fmt.Sprintf(
						"graph.nodes[%d].properties.%s",
						index,
						property,
					),
					Message: "raw MCP transport configuration is prohibited",
				})
			}
		}

		endpointValue, endpointPresent := node.Properties["endpoint"]
		if endpointPresent {
			endpoint, endpointOK := endpointValue.(string)
			sanitized := ingest.SanitizeHTTPEndpoint(endpoint)
			if !endpointOK || !sanitized.Valid || endpoint != sanitized.Display {
				errs = append(errs, FieldError{
					Path:    fmt.Sprintf("graph.nodes[%d].properties.endpoint", index),
					Message: "MCPServer endpoint must be its valid canonical sanitized display value",
				})
			}
		} else if transport == "http" {
			errs = append(errs, FieldError{
				Path:    fmt.Sprintf("graph.nodes[%d].properties.endpoint", index),
				Message: "HTTP MCPServer nodes require a canonical sanitized endpoint",
			})
		}
	}
	if hasKind(node.Kinds, "MCPServer") && node.Properties["transport"] == "stdio" {
		if scheme, _ := node.Properties["id_scheme"].(string); scheme != ingest.MCPStdioIdentitySchemeV3 {
			errs = append(errs, FieldError{
				Path:    fmt.Sprintf("graph.nodes[%d].properties.id_scheme", index),
				Message: "stdio MCPServer nodes require mcp_stdio_v3_hashed_argv",
			})
		}
		command, _ := node.Properties["command"].(string)
		rawHashes, hashesPresent := node.Properties["arg_hashes"]
		argumentHashes, hashesOK := stringSlice(rawHashes)
		hashesOK = hashesOK && rawHashes != nil
		hashesCanonical := hashesOK
		if hashesOK {
			for i, argumentHash := range argumentHashes {
				if ingest.IsCanonicalSHA256(argumentHash) {
					continue
				}
				hashesCanonical = false
				errs = append(errs, FieldError{
					Path: fmt.Sprintf(
						"graph.nodes[%d].properties.arg_hashes[%d]",
						index,
						i,
					),
					Message: "must be a canonical sha256 digest",
				})
			}
		}

		argCount, countOK := nonNegativeWholeNumber(node.Properties["arg_count"])
		switch {
		case strings.TrimSpace(command) == "":
			errs = append(errs, FieldError{
				Path:    fmt.Sprintf("graph.nodes[%d].properties.command", index),
				Message: "stdio MCPServer nodes require command identity input",
			})
		case !hashesPresent || !hashesOK:
			errs = append(errs, FieldError{
				Path:    fmt.Sprintf("graph.nodes[%d].properties.arg_hashes", index),
				Message: "stdio MCPServer arg_hashes must be an explicit array of strings",
			})
		case hashesCanonical && node.ID != ingest.ComputeMCPServerIDFromArgumentHashes(command, argumentHashes...):
			errs = append(errs, FieldError{
				Path:    fmt.Sprintf("graph.nodes[%d].id", index),
				Message: "must match the ordered hashed-argv stdio identity",
			})
		}
		switch {
		case !countOK:
			errs = append(errs, FieldError{
				Path:    fmt.Sprintf("graph.nodes[%d].properties.arg_count", index),
				Message: "stdio MCPServer arg_count must be a non-negative integer",
			})
		case hashesPresent && hashesOK && argCount != float64(len(argumentHashes)):
			errs = append(errs, FieldError{
				Path:    fmt.Sprintf("graph.nodes[%d].properties.arg_count", index),
				Message: "must equal the number of ordered arg_hashes",
			})
		}
	}
	if hasKind(node.Kinds, "MCPServer") || hasKind(node.Kinds, "A2AAgent") {
		errs = append(errs, validateAuthProperties(node.Properties, index)...)
	}
	if hasKind(node.Kinds, "MCPServer") {
		errs = append(errs, validateObservedMCPAuthProperties(node.Properties, index)...)
	}
	if hasKind(node.Kinds, "A2AAgent") {
		errs = append(errs, validateObservedA2AAuthProperties(node.Properties, index)...)
		status, _ := node.Properties["signature_verification_status"].(string)
		switch status {
		case "unknown",
			"unsigned",
			"unsupported_version",
			"malformed",
			"key_unavailable",
			"invalid",
			"valid_untrusted",
			"valid_trusted":
		default:
			errs = append(errs, FieldError{
				Path:    fmt.Sprintf("graph.nodes[%d].properties.signature_verification_status", index),
				Message: fmt.Sprintf("invalid canonical signature status %q", status),
			})
		}
		source, _ := node.Properties["signature_key_source"].(string)
		switch source {
		case "none", "trusted_store", "jku":
		default:
			errs = append(errs, FieldError{
				Path:    fmt.Sprintf("graph.nodes[%d].properties.signature_key_source", index),
				Message: fmt.Sprintf("invalid signature key source %q", source),
			})
		}
		trust, _ := node.Properties["signature_key_trust"].(string)
		switch trust {
		case "unknown", "untrusted", "trusted":
		default:
			errs = append(errs, FieldError{
				Path:    fmt.Sprintf("graph.nodes[%d].properties.signature_key_trust", index),
				Message: fmt.Sprintf("invalid signature key trust %q", trust),
			})
		}
		if status == "valid_trusted" && (source != "trusted_store" || trust != "trusted") {
			errs = append(errs, FieldError{
				Path:    fmt.Sprintf("graph.nodes[%d].properties.signature_key_trust", index),
				Message: "valid_trusted requires trusted_store source and trusted key",
			})
		}
		if status == "valid_untrusted" && (source != "jku" || trust != "untrusted") {
			errs = append(errs, FieldError{
				Path:    fmt.Sprintf("graph.nodes[%d].properties.signature_key_trust", index),
				Message: "valid_untrusted requires jku source and untrusted key",
			})
		}
		if !validA2ASignatureProvenancePair(source, trust) ||
			!validA2ASignatureStatusProvenance(status, source, trust) {
			errs = append(errs, FieldError{
				Path: fmt.Sprintf(
					"graph.nodes[%d].properties.signature_key_source",
					index,
				),
				Message: "signature status, key source, and key trust are contradictory",
			})
		}
		if signed, exists := node.Properties["is_signed"]; exists {
			signedValue, ok := signed.(bool)
			if !ok {
				errs = append(errs, FieldError{
					Path:    fmt.Sprintf("graph.nodes[%d].properties.is_signed", index),
					Message: "must be boolean when present",
				})
			} else {
				expectedSigned := status != "unknown" && status != "unsigned"
				if signedValue != expectedSigned {
					errs = append(errs, FieldError{
						Path: fmt.Sprintf(
							"graph.nodes[%d].properties.is_signed",
							index,
						),
						Message: "is_signed contradicts signature verification status",
					})
				}
			}
		}
	}
	return errs
}

func validA2ASignatureProvenancePair(source, trust string) bool {
	return (source == "none" && trust == "unknown") ||
		(source == "trusted_store" && trust == "trusted") ||
		(source == "jku" && trust == "untrusted")
}

func validA2ASignatureStatusProvenance(status, source, trust string) bool {
	switch status {
	case "unknown", "unsigned", "unsupported_version", "malformed":
		return source == "none" && trust == "unknown"
	case "key_unavailable":
		return validA2ASignatureProvenancePair(source, trust)
	case "invalid":
		return source != "none" && validA2ASignatureProvenancePair(source, trust)
	case "valid_untrusted":
		return source == "jku" && trust == "untrusted"
	case "valid_trusted":
		return source == "trusted_store" && trust == "trusted"
	default:
		return false
	}
}

func validateStdioChildID(
	nodesByID map[string]ingest.Node,
	edge ingest.Edge,
	index int,
) []FieldError {
	source, sourceExists := nodesByID[edge.Source]
	if !sourceExists ||
		!hasKind(source.Kinds, "MCPServer") ||
		source.Properties["transport"] != "stdio" {
		return nil
	}
	target, targetExists := nodesByID[edge.Target]
	if !targetExists {
		return nil
	}

	var prefix, componentProperty string
	switch edge.Kind {
	case "PROVIDES_TOOL":
		prefix, componentProperty = "MCPTool", "name"
	case "PROVIDES_RESOURCE":
		prefix, componentProperty = "MCPResource", "uri"
	case "PROVIDES_PROMPT":
		prefix, componentProperty = "MCPPrompt", "name"
	default:
		return nil
	}
	component, _ := target.Properties[componentProperty].(string)
	if component == "" {
		return nil
	}
	if edge.Target == ingest.ComputeNodeID(prefix, edge.Source, component) {
		return nil
	}
	return []FieldError{{
		Path:    fmt.Sprintf("graph.edges[%d].target", index),
		Message: "must use the current parent identity",
	}}
}

// validateEdgeRiskWeight enforces that a topology-traversable raw edge carries
// a valid risk_weight. Valid means: present, numeric, finite, and
// non-negative. This mirrors the traversal engine's traversalEdgeCost check so
// a risk-weighted path query cannot fail at request time on ingested data.
func validateEdgeRiskWeight(properties map[string]any, index int) []FieldError {
	path := fmt.Sprintf("graph.edges[%d].properties.risk_weight", index)
	raw, exists := properties["risk_weight"]
	if !exists {
		return []FieldError{{
			Path:    path,
			Message: "topology-traversable raw edge must include risk_weight",
		}}
	}
	weight, ok := numericFloat(raw)
	if !ok {
		return []FieldError{{
			Path:    path,
			Message: "must be a number",
		}}
	}
	if math.IsNaN(weight) || math.IsInf(weight, 0) {
		return []FieldError{{
			Path:    path,
			Message: "must be a finite number",
		}}
	}
	if weight < 0 {
		return []FieldError{{
			Path:    path,
			Message: "must be non-negative",
		}}
	}
	return nil
}

// numericFloat coerces a JSON-decoded numeric value to float64. JSON numbers
// decode to float64, but ingest data constructed in-process may carry native
// integer types, so those are accepted too.
func numericFloat(value any) (float64, bool) {
	switch number := value.(type) {
	case float64:
		return number, true
	case float32:
		return float64(number), true
	case int:
		return float64(number), true
	case int64:
		return float64(number), true
	case int32:
		return float64(number), true
	case json.Number:
		parsed, err := number.Float64()
		return parsed, err == nil
	default:
		return 0, false
	}
}

func nonNegativeWholeNumber(value any) (float64, bool) {
	number, ok := numericFloat(value)
	if !ok || math.IsNaN(number) || math.IsInf(number, 0) || number < 0 || number != math.Trunc(number) {
		return 0, false
	}
	return number, true
}

func stringSlice(value any) ([]string, bool) {
	switch typed := value.(type) {
	case nil:
		return []string{}, true
	case []string:
		return append([]string(nil), typed...), true
	case []any:
		values := make([]string, len(typed))
		for i, item := range typed {
			text, ok := item.(string)
			if !ok {
				return nil, false
			}
			values[i] = text
		}
		return values, true
	default:
		return nil, false
	}
}

func validateAuthProperties(properties map[string]any, index int) []FieldError {
	var errs []FieldError
	method, _ := properties["auth_method"].(string)
	methodCanonical := false
	switch method {
	case "unknown", "none", "basic", "apiKey", "bearer", "oauth", "oidc", "mtls", "custom":
		methodCanonical = true
	default:
		errs = append(errs, FieldError{
			Path:    fmt.Sprintf("graph.nodes[%d].properties.auth_method", index),
			Message: fmt.Sprintf("invalid canonical auth method %q", method),
		})
	}
	assurance, _ := properties["auth_assurance"].(string)
	assuranceCanonical := false
	switch assurance {
	case "unknown", "unauthenticated", "weak", "moderate", "strong":
		assuranceCanonical = true
	default:
		errs = append(errs, FieldError{
			Path:    fmt.Sprintf("graph.nodes[%d].properties.auth_assurance", index),
			Message: fmt.Sprintf("invalid canonical auth assurance %q", assurance),
		})
	}
	if methodCanonical && assuranceCanonical {
		expectedAssurance := string(common.AssessAuth(method).Assurance)
		if assurance != expectedAssurance {
			errs = append(errs, FieldError{
				Path: fmt.Sprintf("graph.nodes[%d].properties.auth_assurance", index),
				Message: fmt.Sprintf(
					"must be %q for auth method %q",
					expectedAssurance,
					method,
				),
			})
		}
	}
	evidence, _ := properties["auth_evidence"].(string)
	evidenceCanonical := false
	switch evidence {
	case "unknown", "declared_security_scheme", "configured_credential",
		"anonymous_probe_succeeded", "local_process":
		evidenceCanonical = true
	default:
		errs = append(errs, FieldError{
			Path:    fmt.Sprintf("graph.nodes[%d].properties.auth_evidence", index),
			Message: fmt.Sprintf("invalid canonical auth evidence %q", evidence),
		})
	}

	if methodCanonical && assuranceCanonical && evidenceCanonical &&
		!configuredAuthEvidenceCompatible(method, evidence) {
		errs = append(errs, FieldError{
			Path: fmt.Sprintf("graph.nodes[%d].properties.auth_evidence", index),
			Message: fmt.Sprintf(
				"auth evidence %q is incompatible with configured auth method %q",
				evidence,
				method,
			),
		})
	}
	return errs
}

// configuredAuthEvidenceCompatible encodes the tuples emitted by the
// first-party Config, MCP discovery, protocol-scan, and A2A collectors, plus
// the explicit anonymous-probe tuple accepted from affirmative runtime
// evidence imports. "none" paired with unknown or declared evidence remains
// valid but fail-closed during analysis: only anonymous_probe_succeeded proves
// unauthenticated access. Unknown can legitimately describe no observation, an
// ambiguous declaration, a configured query credential whose scheme cannot be
// inferred, or a local stdio process.
func configuredAuthEvidenceCompatible(method, evidence string) bool {
	switch method {
	case string(common.AuthNone):
		return evidence == common.AuthEvidenceUnknown ||
			evidence == common.AuthEvidenceDeclaredScheme ||
			evidence == common.AuthEvidenceAnonymousProbeSucceeded
	case string(common.AuthUnknown):
		return evidence == common.AuthEvidenceUnknown ||
			evidence == common.AuthEvidenceDeclaredScheme ||
			evidence == common.AuthEvidenceConfiguredCredential ||
			evidence == common.AuthEvidenceLocalProcess
	case string(common.AuthBasic), string(common.AuthAPIKey),
		string(common.AuthBearer), string(common.AuthOAuth),
		string(common.AuthOIDC), string(common.AuthMTLS), string(common.AuthCustom):
		return evidence == common.AuthEvidenceConfiguredCredential ||
			evidence == common.AuthEvidenceDeclaredScheme
	default:
		return false
	}
}

// validateObservedMCPAuthProperties treats runtime authentication as one
// indivisible evidence tuple. A collector may omit the tuple entirely (for
// example, Config collection), but it may not publish a partially populated or
// internally contradictory tuple. This prevents a single forged observed field
// from overriding the separately retained configured posture during analysis.
func validateObservedMCPAuthProperties(properties map[string]any, index int) []FieldError {
	const (
		methodKey    = "observed_auth_method"
		assuranceKey = "observed_auth_assurance"
		evidenceKey  = "observed_auth_evidence"
	)
	_, methodPresent := properties[methodKey]
	_, assurancePresent := properties[assuranceKey]
	_, evidencePresent := properties[evidenceKey]
	if !methodPresent && !assurancePresent && !evidencePresent {
		return nil
	}

	basePath := fmt.Sprintf("graph.nodes[%d].properties.", index)
	var errs []FieldError
	method, methodOK := properties[methodKey].(string)
	assurance, assuranceOK := properties[assuranceKey].(string)
	evidence, evidenceOK := properties[evidenceKey].(string)
	for _, field := range []struct {
		key     string
		present bool
		valid   bool
	}{
		{key: methodKey, present: methodPresent, valid: methodOK},
		{key: assuranceKey, present: assurancePresent, valid: assuranceOK},
		{key: evidenceKey, present: evidencePresent, valid: evidenceOK},
	} {
		switch {
		case !field.present:
			errs = append(errs, FieldError{
				Path:    basePath + field.key,
				Message: "is required when any observed authentication field is present",
			})
		case !field.valid:
			errs = append(errs, FieldError{
				Path:    basePath + field.key,
				Message: "must be a canonical string",
			})
		}
	}
	if !methodOK || !assuranceOK || !evidenceOK {
		return errs
	}

	methodCanonical := false
	switch method {
	case "unknown", "none", "basic", "apiKey", "bearer", "oauth", "oidc", "mtls", "custom":
		methodCanonical = true
	default:
		errs = append(errs, FieldError{
			Path:    basePath + methodKey,
			Message: fmt.Sprintf("invalid canonical observed auth method %q", method),
		})
	}
	assuranceCanonical := false
	switch assurance {
	case "unknown", "unauthenticated", "weak", "moderate", "strong":
		assuranceCanonical = true
	default:
		errs = append(errs, FieldError{
			Path:    basePath + assuranceKey,
			Message: fmt.Sprintf("invalid canonical observed auth assurance %q", assurance),
		})
	}
	evidenceCanonical := false
	switch evidence {
	case common.AuthEvidenceUnknown,
		common.AuthEvidenceConfiguredCredential,
		common.AuthEvidenceAnonymousProbeSucceeded,
		common.AuthEvidenceLocalProcess:
		evidenceCanonical = true
	default:
		errs = append(errs, FieldError{
			Path:    basePath + evidenceKey,
			Message: fmt.Sprintf("invalid canonical observed auth evidence %q", evidence),
		})
	}
	if !methodCanonical || !assuranceCanonical || !evidenceCanonical {
		return errs
	}

	expectedAssurance := string(common.AssessAuth(method).Assurance)
	if assurance != expectedAssurance {
		errs = append(errs, FieldError{
			Path: basePath + assuranceKey,
			Message: fmt.Sprintf(
				"must be %q for observed auth method %q",
				expectedAssurance,
				method,
			),
		})
	}

	status, _ := properties["status"].(string)
	transport, _ := properties["transport"].(string)
	switch evidence {
	case common.AuthEvidenceAnonymousProbeSucceeded:
		if method != string(common.AuthNone) ||
			assurance != string(common.AuthAssuranceUnauthenticated) ||
			status != "reachable" || transport != "http" {
			errs = append(errs, FieldError{
				Path:    basePath + evidenceKey,
				Message: "anonymous_probe_succeeded requires the exact reachable HTTP none/unauthenticated tuple",
			})
		}
	case common.AuthEvidenceLocalProcess:
		if method != string(common.AuthUnknown) ||
			assurance != string(common.AuthAssuranceUnknown) ||
			status != "reachable" || transport != "stdio" {
			errs = append(errs, FieldError{
				Path:    basePath + evidenceKey,
				Message: "local_process requires the exact reachable stdio unknown/unknown tuple",
			})
		}
	case common.AuthEvidenceUnknown:
		if method != string(common.AuthUnknown) ||
			assurance != string(common.AuthAssuranceUnknown) ||
			(status != "reachable" && status != "unreachable") {
			errs = append(errs, FieldError{
				Path:    basePath + evidenceKey,
				Message: "unknown observed evidence requires a reachable or unreachable unknown/unknown tuple",
			})
		}
	case common.AuthEvidenceConfiguredCredential:
		if method == string(common.AuthNone) || status != "reachable" || transport != "http" {
			errs = append(errs, FieldError{
				Path:    basePath + evidenceKey,
				Message: "credential observation requires a reachable HTTP non-none auth tuple",
			})
		}
	}
	return errs
}

// validateObservedA2AAuthProperties accepts only the bounded, read-only task
// lookup observation that proves anonymous access to an A2A protocol handler.
// Reading a public Agent Card is declaration discovery, not runtime auth
// evidence, and no other observed tuple is permitted to claim otherwise.
func validateObservedA2AAuthProperties(properties map[string]any, index int) []FieldError {
	const (
		methodKey      = "observed_auth_method"
		assuranceKey   = "observed_auth_assurance"
		evidenceKey    = "observed_auth_evidence"
		probeMethodKey = "auth_probe_method"
		probeStatusKey = "auth_probe_status"
		probeDetailKey = "auth_probe_detail"
	)
	_, methodPresent := properties[methodKey]
	_, assurancePresent := properties[assuranceKey]
	_, evidencePresent := properties[evidenceKey]
	_, probeMethodPresent := properties[probeMethodKey]
	_, probeStatusPresent := properties[probeStatusKey]
	_, probeDetailPresent := properties[probeDetailKey]
	if !methodPresent && !assurancePresent && !evidencePresent &&
		!probeMethodPresent && !probeStatusPresent && !probeDetailPresent {
		return nil
	}

	basePath := fmt.Sprintf("graph.nodes[%d].properties.", index)
	var errs []FieldError
	probeMethod, probeMethodOK := properties[probeMethodKey].(string)
	probeStatus, probeStatusOK := properties[probeStatusKey].(string)
	probeDetail, probeDetailOK := properties[probeDetailKey].(string)
	for _, field := range []struct {
		key     string
		present bool
		valid   bool
	}{
		{key: probeMethodKey, present: probeMethodPresent, valid: probeMethodOK},
		{key: probeStatusKey, present: probeStatusPresent, valid: probeStatusOK},
		{key: probeDetailKey, present: probeDetailPresent, valid: probeDetailOK},
	} {
		switch {
		case !field.present:
			errs = append(errs, FieldError{
				Path:    basePath + field.key,
				Message: "is required when any A2A authentication probe field is present",
			})
		case !field.valid:
			errs = append(errs, FieldError{
				Path:    basePath + field.key,
				Message: "must be a canonical string",
			})
		}
	}
	if !probeMethodOK || !probeStatusOK || !probeDetailOK {
		return errs
	}
	if probeMethod != "get_task_nonexistent" {
		errs = append(errs, FieldError{
			Path:    basePath + probeMethodKey,
			Message: "must be the canonical bounded method get_task_nonexistent",
		})
	}
	statusCanonical := false
	switch probeStatus {
	case "anonymous_protocol_access", "authentication_required", "unknown":
		statusCanonical = true
	default:
		errs = append(errs, FieldError{
			Path:    basePath + probeStatusKey,
			Message: fmt.Sprintf("invalid canonical A2A auth probe status %q", probeStatus),
		})
	}
	if statusCanonical && !validA2AAuthProbeDetail(probeStatus, probeDetail) {
		errs = append(errs, FieldError{
			Path: basePath + probeDetailKey,
			Message: fmt.Sprintf(
				"invalid bounded detail %q for A2A auth probe status %q",
				probeDetail,
				probeStatus,
			),
		})
	}

	switch probeStatus {
	case "anonymous_protocol_access":
		observedMethod, observedMethodOK := properties[methodKey].(string)
		observedAssurance, observedAssuranceOK := properties[assuranceKey].(string)
		observedEvidence, observedEvidenceOK := properties[evidenceKey].(string)
		for _, field := range []struct {
			key     string
			present bool
			valid   bool
			value   string
			want    string
		}{
			{key: methodKey, present: methodPresent, value: observedMethod, valid: observedMethodOK, want: string(common.AuthNone)},
			{key: assuranceKey, present: assurancePresent, value: observedAssurance, valid: observedAssuranceOK, want: string(common.AuthAssuranceUnauthenticated)},
			{key: evidenceKey, present: evidencePresent, value: observedEvidence, valid: observedEvidenceOK, want: common.AuthEvidenceAnonymousProbeSucceeded},
		} {
			switch {
			case !field.present:
				errs = append(errs, FieldError{
					Path:    basePath + field.key,
					Message: "is required for anonymous_protocol_access",
				})
			case !field.valid:
				errs = append(errs, FieldError{
					Path:    basePath + field.key,
					Message: "must be a canonical string",
				})
			case field.value != field.want:
				errs = append(errs, FieldError{
					Path:    basePath + field.key,
					Message: fmt.Sprintf("must be %q for anonymous_protocol_access", field.want),
				})
			}
		}
	case "authentication_required", "unknown":
		for _, field := range []struct {
			key     string
			present bool
		}{
			{key: methodKey, present: methodPresent},
			{key: assuranceKey, present: assurancePresent},
			{key: evidenceKey, present: evidencePresent},
		} {
			if field.present {
				errs = append(errs, FieldError{
					Path:    basePath + field.key,
					Message: "must be omitted for a non-positive A2A authentication probe",
				})
			}
		}
	}
	return errs
}

func validA2AAuthProbeDetail(status, detail string) bool {
	switch status {
	case "anonymous_protocol_access":
		return detail == "task_not_found_v1" || detail == "task_not_found_v0_3"
	case "authentication_required":
		return detail == "http_unauthorized" || detail == "http_forbidden"
	case "unknown":
		switch detail {
		case "no_preferred_interface",
			"nonconformant_preferred_interface",
			"unsupported_protocol_binding",
			"unsupported_protocol_version",
			"invalid_preferred_interface_url",
			"query_interface_not_probeable",
			"cross_origin_interface",
			"random_id_generation_failed",
			"request_encoding_failed",
			"request_creation_failed",
			"transport_unavailable",
			"timeout",
			"context_canceled",
			"transport_error",
			"redirect_response",
			"unexpected_http_status",
			"non_json_response",
			"response_too_large",
			"malformed_jsonrpc_response",
			"unexpected_jsonrpc_response",
			"response_id_mismatch",
			"non_task_not_found_error":
			return true
		}
	}
	return false
}

func validateCredentialProperties(properties map[string]any, index int) []FieldError {
	var errs []FieldError
	path := fmt.Sprintf("graph.nodes[%d].properties.", index)
	valueHash, _ := properties["value_hash"].(string)
	if strings.TrimSpace(valueHash) == "" {
		errs = append(errs, FieldError{Path: path + "value_hash", Message: "Credential nodes must include non-empty value_hash"})
	}
	mergeKey, _ := properties["merge_key"].(string)
	if mergeKey != "value_hash" && mergeKey != "identity" {
		errs = append(errs, FieldError{Path: path + "merge_key", Message: "must be value_hash or identity"})
	}
	identityBasis, _ := properties["identity_basis"].(string)
	switch identityBasis {
	case "value_hash", "provider_name", "metadata", "unknown":
	default:
		errs = append(errs, FieldError{Path: path + "identity_basis", Message: "invalid credential identity basis"})
	}
	if mergeKey == "value_hash" && identityBasis != "value_hash" {
		errs = append(errs, FieldError{Path: path + "identity_basis", Message: "must be value_hash when merge_key is value_hash"})
	}
	if mergeKey == "identity" && identityBasis == "value_hash" {
		errs = append(errs, FieldError{Path: path + "identity_basis", Message: "must not be value_hash when merge_key is identity"})
	}
	material, _ := properties["material_status"].(string)
	switch material {
	case "observed", "masked", "hashed", "unobserved", "unknown":
	default:
		errs = append(errs, FieldError{Path: path + "material_status", Message: "invalid credential material status"})
	}
	exposure, _ := properties["exposure_status"].(string)
	switch exposure {
	case "exposed", "not_observed", "unknown":
	default:
		errs = append(errs, FieldError{Path: path + "exposure_status", Message: "invalid credential exposure status"})
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
