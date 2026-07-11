package analysis

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/adithyan-ak/agenthound/server/internal/graph"
	"github.com/adithyan-ak/agenthound/server/model"
)

type FindingDetail struct {
	Finding        Finding           `json:"finding"`
	CompositeProps map[string]any    `json:"composite_props,omitempty"`
	AttackPath     *AttackPath       `json:"attack_path"`
	Remediation    []RemediationStep `json:"remediation"`
	Impact         *Impact           `json:"impact"`
	Snapshot       *FindingSnapshot  `json:"snapshot,omitempty"`
}

type FindingSnapshot struct {
	Scope             string            `json:"scope"`
	ScanID            string            `json:"scan_id"`
	ProjectionStatus  string            `json:"projection_status"`
	Stale             bool              `json:"stale"`
	LiveEvidenceState LiveEvidenceState `json:"live_evidence_state"`
}

type LiveEvidenceState string

const (
	LiveEvidenceUnavailable                 LiveEvidenceState = "unavailable"
	LiveEvidenceWithheldStaleProjection     LiveEvidenceState = "withheld_stale_projection"
	LiveEvidenceLookupFailed                LiveEvidenceState = "lookup_failed"
	LiveEvidenceClassificationMismatch      LiveEvidenceState = "classification_mismatch"
	LiveEvidenceMatchingFindingNoGraph      LiveEvidenceState = "matching_finding_no_graph"
	LiveEvidenceMatchingPublishedProjection LiveEvidenceState = "matching_published_projection"
	LiveEvidencePersistedExact              LiveEvidenceState = "persisted_exact_evidence"
)

type AttackPath struct {
	Nodes           []PathNode             `json:"nodes"`
	Edges           []PathEdge             `json:"edges"`
	Shape           EvidenceShape          `json:"shape"`
	Continuity      EvidenceContinuity     `json:"continuity"`
	Direction       EvidenceDirection      `json:"direction"`
	Completeness    EvidenceCompleteness   `json:"completeness"`
	Linearization   *EvidenceLinearization `json:"linearization,omitempty"`
	Cost            AttackCost             `json:"cost"`
	TotalRiskWeight *float64               `json:"total_risk_weight"`
}

type EvidenceShape string

const (
	EvidenceShapeLinear       EvidenceShape = "linear"
	EvidenceShapeBranched     EvidenceShape = "branched"
	EvidenceShapeDisconnected EvidenceShape = "disconnected"
	EvidenceShapeCyclic       EvidenceShape = "cyclic"
	EvidenceShapeNodesOnly    EvidenceShape = "nodes_only"
)

type EvidenceDirection string

const (
	EvidenceDirectionForward       EvidenceDirection = "forward"
	EvidenceDirectionReverse       EvidenceDirection = "reverse"
	EvidenceDirectionMixed         EvidenceDirection = "mixed"
	EvidenceDirectionNonLinear     EvidenceDirection = "non_linear"
	EvidenceDirectionNotApplicable EvidenceDirection = "not_applicable"
)

type EvidenceState string

const (
	EvidenceStateComplete      EvidenceState = "complete"
	EvidenceStateIncomplete    EvidenceState = "incomplete"
	EvidenceStateNotApplicable EvidenceState = "not_applicable"
)

type EvidenceContinuityState string

const (
	EvidenceContinuityContinuous    EvidenceContinuityState = "continuous"
	EvidenceContinuityDiscontinuous EvidenceContinuityState = "discontinuous"
	EvidenceContinuityNotApplicable EvidenceContinuityState = "not_applicable"
)

type EvidenceContinuity struct {
	State          EvidenceContinuityState `json:"state"`
	ComponentCount int                     `json:"component_count"`
	MissingNodeIDs []string                `json:"missing_node_ids"`
}

type EvidenceCompleteness struct {
	State   EvidenceState `json:"state"`
	Reasons []string      `json:"reasons"`
}

type EvidenceLinearization struct {
	NodeIDs     []string `json:"node_ids"`
	EdgeIndexes []int    `json:"edge_indexes"`
}

type AttackCost struct {
	State                    EvidenceState `json:"state"`
	Value                    *float64      `json:"value"`
	Reasons                  []string      `json:"reasons"`
	MissingWeightEdgeIndexes []int         `json:"missing_weight_edge_indexes"`
}

type PathNode struct {
	ID         string         `json:"id"`
	Kinds      []string       `json:"kinds"`
	Properties map[string]any `json:"properties"`
}

type PathEdge struct {
	Source     string          `json:"source"`
	Target     string          `json:"target"`
	Kind       string          `json:"kind"`
	Properties map[string]any  `json:"properties"`
	Synthetic  bool            `json:"synthetic"`
	Provenance *EdgeProvenance `json:"provenance,omitempty"`
}

type EdgeProvenance struct {
	Type            string `json:"type"`
	Basis           string `json:"basis,omitempty"`
	SourceCollector string `json:"source_collector,omitempty"`
}

type RemediationStep struct {
	Step        int              `json:"step"`
	Title       string           `json:"title"`
	Description string           `json:"description"`
	EdgeKind    string           `json:"edge_kind"`
	Source      RemediationActor `json:"source"`
	Target      RemediationActor `json:"target"`
	Channels    []string         `json:"channels,omitempty"`
	Commands    []string         `json:"commands,omitempty"`
}

type RemediationActor struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Kind string `json:"kind"`
}

type Impact struct {
	Summary         string `json:"summary"`
	BlastRadius     string `json:"blast_radius"`
	DataSensitivity string `json:"data_sensitivity,omitempty"`
}

func GetFindingByID(ctx context.Context, db graph.GraphDB, findingID string) (*Finding, error) {
	findings, err := QueryFindings(ctx, db, "")
	if err != nil {
		return nil, err
	}
	for i := range findings {
		if findings[i].ID == findingID {
			return &findings[i], nil
		}
	}
	return nil, nil
}

// AttackPathFromExactEvidence renders the detector-selected witness persisted
// with the finding. It never queries the mutable graph, so a published detail
// cannot drift to a different LIMIT 1 match or disappear after publication.
func AttackPathFromExactEvidence(f *Finding) *AttackPath {
	if f == nil || f.ExactEvidence == nil {
		return nil
	}
	exact := f.ExactEvidence
	path := &AttackPath{
		Nodes: make([]PathNode, 0, len(exact.Nodes)),
		Edges: make([]PathEdge, 0, len(exact.Edges)),
	}
	for _, node := range exact.Nodes {
		properties := node.Properties
		if properties == nil {
			properties = map[string]any{}
		}
		path.Nodes = append(path.Nodes, PathNode{
			ID: node.ID, Kinds: append([]string(nil), node.Kinds...), Properties: properties,
		})
	}
	for _, edge := range exact.Edges {
		properties := edge.Properties
		if properties == nil {
			properties = map[string]any{}
		}
		pathEdge := PathEdge{
			Source: edge.Source, Target: edge.Target, Kind: edge.Kind,
			Properties: properties, Synthetic: edge.Synthetic,
		}
		if edge.Synthetic {
			pathEdge.Provenance = &EdgeProvenance{
				Type:            stringMapVal(edge.Provenance, "type"),
				Basis:           stringMapVal(edge.Provenance, "basis"),
				SourceCollector: stringMapVal(edge.Provenance, "source_collector"),
			}
		}
		path.Edges = append(path.Edges, pathEdge)
	}
	issues := append([]string(nil), exact.Reasons...)
	if !exact.Complete && len(issues) == 0 {
		issues = append(issues, "detector_evidence_incomplete")
	}
	finalizeEvidenceGraph(path, issues)
	markExpectedEvidenceEndpoints(path, f.SourceID, f.TargetID)
	return path
}

func stringMapVal(values map[string]any, key string) string {
	if values == nil {
		return ""
	}
	value, _ := values[key].(string)
	return value
}

const compositeEdgePropsQuery = `
MATCH (src {objectid: $source})-[r]->(tgt {objectid: $target})
WHERE type(r) = $edge_kind AND r.is_composite = true
RETURN properties(r) AS props
LIMIT 1`

func GetCompositeEdgeProps(ctx context.Context, db graph.GraphDB, f *Finding) (map[string]any, error) {
	rows, err := db.Query(ctx, compositeEdgePropsQuery, map[string]any{
		"source":    f.SourceID,
		"target":    f.TargetID,
		"edge_kind": f.EdgeKind,
	})
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	props, ok := rows[0]["props"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("composite edge properties have unexpected type %T", rows[0]["props"])
	}
	return props, nil
}

var pathQueriesByEdgeKind = map[string][]string{
	"CAN_REACH": {
		`MATCH (a:AgentInstance {objectid: $source})
      -[r1:TRUSTS_SERVER]->(s:MCPServer)
      -[r2:PROVIDES_TOOL]->(t:MCPTool)
      -[r3:HAS_ACCESS_TO]->(r:MCPResource {objectid: $target})
RETURN [n IN [a, s, t, r] | {id: n.objectid, name: n.name, kinds: labels(n), properties: properties(n)}] AS nodes,
       [rel IN [r1, r2, r3] | {kind: type(rel), source: startNode(rel).objectid, target: endNode(rel).objectid, properties: properties(rel)}] AS edges
LIMIT 1`,
		`MATCH (a:AgentInstance {objectid: $source})-[r1:TRUSTS_SERVER]->(s1:MCPServer)
      -[r2:PROVIDES_TOOL]->(t1:MCPTool)
MATCH (s2:MCPServer)-[r3:HAS_ENV_VAR]->(c:Credential)
MATCH (c)<-[r4:USES_CREDENTIAL]-(i:Identity)<-[r5:AUTHENTICATES_WITH]-(s2)
MATCH (s2)-[r6:PROVIDES_TOOL]->(t2:MCPTool)-[r7:HAS_ACCESS_TO]->(r:MCPResource {objectid: $target})
WHERE s1 <> s2
RETURN [n IN [a, s1, t1, c, i, s2, t2, r] | {id: n.objectid, name: n.name, kinds: labels(n), properties: properties(n)}] AS nodes,
       [rel IN [r1, r2, r3, r4, r5, r6, r7] | {kind: type(rel), source: startNode(rel).objectid, target: endNode(rel).objectid, properties: properties(rel)}] AS edges
LIMIT 1`,
	},
	"CAN_REACH_CROSS_PROTOCOL": {
		`MATCH delegation = (ext:A2AAgent {objectid: $source})-[:DELEGATES_TO*1..3]->(int:A2AAgent)
MATCH (int)-[r1:RUNS_ON]->(h:Host)<-[r2:RUNS_ON]-(s:MCPServer)
MATCH (a:AgentInstance)-[r3:TRUSTS_SERVER]->(s)
      -[r4:PROVIDES_TOOL]->(t:MCPTool)-[r5:HAS_ACCESS_TO]->(r:MCPResource {objectid: $target})
RETURN [n IN nodes(delegation) + [h, s, a, t, r] | {id: n.objectid, name: n.name, kinds: labels(n), properties: properties(n)}] AS nodes,
       [rel IN relationships(delegation) + [r1, r2, r3, r4, r5] | {kind: type(rel), source: startNode(rel).objectid, target: endNode(rel).objectid, properties: properties(rel)}] AS edges
LIMIT 1`,
	},
	// CAN_REACH_CREDENTIAL_CHAIN reconstructs the cross-service path emitted
	// by processors/cross_service_credential_chain.go. The composite edge
	// has the AgentInstance as source and the upstream provider Credential
	// as target; the chain is joined by Credential.value_hash, not by a
	// graph edge. We re-traverse the same join here so the UI can show
	// what the user followed: agent -> mcp server -> env-var credential
	// (==value_hash==) -> litellm gateway -> upstream provider credential.
	"CAN_REACH_CREDENTIAL_CHAIN": {
		`MATCH (a:AgentInstance {objectid: $source})-[r1:TRUSTS_SERVER]->(s:MCPServer)
      -[r2:HAS_ENV_VAR]->(c1:Credential)
MATCH (gw:LiteLLMGateway)-[r3:EXPOSES_CREDENTIAL]->(c1master:Credential)
WHERE c1master.value_hash = c1.value_hash AND c1master.objectid <> c1.objectid
MATCH (gw)-[r4:EXPOSES_CREDENTIAL]->(c2:Credential {objectid: $target})
RETURN [n IN [a, s, c1, c1master, gw, c2] | {id: n.objectid, name: n.name, kinds: labels(n), properties: properties(n)}] AS nodes,
       [rel IN [r1, r2, r3, r4] | {kind: type(rel), source: startNode(rel).objectid, target: endNode(rel).objectid, properties: properties(rel)}] +
       [{kind: 'VALUE_HASH_MATCH', source: c1.objectid, target: c1master.objectid,
         properties: {is_synthetic: true, provenance_type: 'identity_correlation',
                      provenance_basis: 'value_hash',
                      source_collector: 'cross_service_credential_chain'}}] AS edges
LIMIT 1`,
	},
	"CAN_EXFILTRATE_VIA": {
		`MATCH (a:AgentInstance {objectid: $source})-[r1:TRUSTS_SERVER]->(s1:MCPServer)
      -[r2:PROVIDES_TOOL]->(outbound:MCPTool {objectid: $target})
WHERE ANY(cap IN outbound.capability_surface WHERE cap IN ['email_send', 'network_outbound', 'file_write', 'auto_fetch_render', 'allowlisted_proxy'])
WITH a, s1, r1, r2, outbound
OPTIONAL MATCH (a)-[r3:TRUSTS_SERVER]->(s2:MCPServer)-[r4:PROVIDES_TOOL]->(t2:MCPTool)-[r5:HAS_ACCESS_TO]->(res:MCPResource)
WHERE res.sensitivity IN ['critical', 'high']
WITH a, s1, r1, r2, outbound, s2, r3, t2, r4, res, r5 LIMIT 1
RETURN [n IN [a, s1, outbound] + CASE WHEN res IS NOT NULL THEN [s2, t2, res] ELSE [] END | {id: n.objectid, name: n.name, kinds: labels(n), properties: properties(n)}] AS nodes,
       [rel IN [r1, r2] + CASE WHEN res IS NOT NULL THEN [r3, r4, r5] ELSE [] END | {kind: type(rel), source: startNode(rel).objectid, target: endNode(rel).objectid, properties: properties(rel)}] AS edges
LIMIT 1`,
	},
	"CAN_EXECUTE": {
		`MATCH (s:MCPServer)-[r1:PROVIDES_TOOL]->(t:MCPTool {objectid: $source}),
      (s)-[r2:RUNS_ON]->(h:Host {objectid: $target})
RETURN [n IN [s, t, h] | {id: n.objectid, name: n.name, kinds: labels(n), properties: properties(n)}] AS nodes,
       [rel IN [r1, r2] | {kind: type(rel), source: startNode(rel).objectid, target: endNode(rel).objectid, properties: properties(rel)}] AS edges
LIMIT 1`,
	},
	"HAS_ACCESS_TO": {
		`MATCH (s:MCPServer)-[r1:PROVIDES_TOOL]->(t:MCPTool {objectid: $source}),
      (s)-[r2:PROVIDES_RESOURCE]->(r:MCPResource {objectid: $target})
RETURN [n IN [s, t, r] | {id: n.objectid, name: n.name, kinds: labels(n), properties: properties(n)}] AS nodes,
       [rel IN [r1, r2] | {kind: type(rel), source: startNode(rel).objectid, target: endNode(rel).objectid, properties: properties(rel)}] AS edges
LIMIT 1`,
	},
	"SHADOWS": {
		`MATCH (s1:MCPServer)-[r1:PROVIDES_TOOL]->(t1:MCPTool {objectid: $source}),
      (s2:MCPServer)-[r2:PROVIDES_TOOL]->(t2:MCPTool {objectid: $target})
WHERE s1 <> s2
RETURN [n IN [s1, t1, t2, s2] | {id: n.objectid, name: n.name, kinds: labels(n), properties: properties(n)}] AS nodes,
       [rel IN [r1, r2] | {kind: type(rel), source: startNode(rel).objectid, target: endNode(rel).objectid, properties: properties(rel)}] AS edges
LIMIT 1`,
	},
	"POISONED_DESCRIPTION": {
		`MATCH (s:MCPServer)-[r1:PROVIDES_TOOL]->(t:MCPTool {objectid: $source})
RETURN [n IN [s, t] | {id: n.objectid, name: n.name, kinds: labels(n), properties: properties(n)}] AS nodes,
       [rel IN [r1] | {kind: type(rel), source: startNode(rel).objectid, target: endNode(rel).objectid, properties: properties(rel)}] AS edges
LIMIT 1`,
	},
	"CAN_IMPERSONATE": {
		`MATCH (a1:A2AAgent {objectid: $source}), (a2:A2AAgent {objectid: $target})
RETURN [{id: a1.objectid, name: a1.name, kinds: labels(a1), properties: properties(a1)},
        {id: a2.objectid, name: a2.name, kinds: labels(a2), properties: properties(a2)}] AS nodes,
       [] AS edges
LIMIT 1`,
	},
	"POISONED_INSTRUCTIONS": {
		`MATCH (a:AgentInstance)-[r1:LOADS_INSTRUCTIONS]->(f:InstructionFile {objectid: $source})
RETURN [n IN [a, f] | {id: n.objectid, name: n.name, kinds: labels(n), properties: properties(n)}] AS nodes,
       [rel IN [r1] | {kind: type(rel), source: startNode(rel).objectid, target: endNode(rel).objectid, properties: properties(rel)}] AS edges
LIMIT 1`,
	},
}

const genericFallbackQuery = `
MATCH (src {objectid: $source}), (tgt {objectid: $target}),
      p = shortestPath((src)-[*1..10]-(tgt))
WHERE ALL(r IN relationships(p) WHERE NOT coalesce(r.is_composite, false))
RETURN [n IN nodes(p) | {id: n.objectid, name: n.name, kinds: labels(n), properties: properties(n)}] AS nodes,
       [r IN relationships(p) | {kind: type(r), source: startNode(r).objectid, target: endNode(r).objectid, properties: properties(r)}] AS edges
LIMIT 1`

func ReconstructAttackPath(ctx context.Context, db graph.GraphDB, f *Finding, compositeProps map[string]any) (*AttackPath, error) {
	params := map[string]any{
		"source": f.SourceID,
		"target": f.TargetID,
	}

	var queries []string

	edgeKind := f.EdgeKind
	if edgeKind == "CAN_REACH" {
		if isCredentialChain(compositeProps) {
			queries = append(queries, pathQueriesByEdgeKind["CAN_REACH_CREDENTIAL_CHAIN"]...)
		}
		if boolVal(compositeProps, "cross_protocol") {
			queries = append(queries, pathQueriesByEdgeKind["CAN_REACH_CROSS_PROTOCOL"]...)
		}
	}

	if qs, ok := pathQueriesByEdgeKind[edgeKind]; ok {
		queries = append(queries, qs...)
	}

	var queryErrs []error
	for i, q := range queries {
		path, err := tryPathQuery(ctx, db, q, params)
		if err != nil {
			queryErrs = append(queryErrs, fmt.Errorf("evidence query %d: %w", i, err))
			continue
		}
		if path != nil {
			return path, nil
		}
	}
	if len(queryErrs) > 0 {
		return nil, errors.Join(queryErrs...)
	}

	path, err := tryPathQuery(ctx, db, genericFallbackQuery, params)
	if err != nil {
		queryErrs = append(queryErrs, fmt.Errorf("fallback path query: %w", err))
		return nil, errors.Join(queryErrs...)
	}
	if path == nil && len(queryErrs) > 0 {
		return nil, errors.Join(queryErrs...)
	}
	return path, nil
}

func tryPathQuery(ctx context.Context, db graph.GraphDB, cypher string, params map[string]any) (*AttackPath, error) {
	rows, err := db.Query(ctx, cypher, params)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	path, err := parseAttackPath(rows[0])
	if err != nil || path == nil {
		return path, err
	}
	source, _ := params["source"].(string)
	target, _ := params["target"].(string)
	markExpectedEvidenceEndpoints(path, source, target)
	return path, nil
}

func parseAttackPath(row map[string]any) (*AttackPath, error) {
	rawNodes, nodesOK := anySlice(row["nodes"])
	rawEdges, edgesOK := anySlice(row["edges"])

	if !nodesOK {
		return nil, fmt.Errorf("evidence nodes have unexpected type %T", row["nodes"])
	}
	if len(rawNodes) == 0 {
		return nil, nil
	}

	var issues []string
	if !edgesOK {
		issues = append(issues, "edges_not_an_array")
	}
	nodes := make([]PathNode, 0, len(rawNodes))
	seen := make(map[string]bool)
	for i, rn := range rawNodes {
		nm, ok := rn.(map[string]any)
		if !ok {
			issues = append(issues, fmt.Sprintf("node_%d_not_an_object", i))
			continue
		}
		pn := parsePathNode(nm)
		if pn.ID == "" {
			issues = append(issues, fmt.Sprintf("node_%d_missing_id", i))
			continue
		}
		if seen[pn.ID] {
			continue
		}
		seen[pn.ID] = true
		nodes = append(nodes, pn)
	}

	edges := make([]PathEdge, 0, len(rawEdges))
	for i, re := range rawEdges {
		em, ok := re.(map[string]any)
		if !ok {
			issues = append(issues, fmt.Sprintf("edge_%d_not_an_object", i))
			continue
		}
		pe := parsePathEdge(em)
		if pe.Source == "" || pe.Target == "" || pe.Kind == "" {
			issues = append(issues, fmt.Sprintf("edge_%d_missing_identity", i))
			continue
		}
		edges = append(edges, pe)
	}

	path := &AttackPath{Nodes: nodes, Edges: edges}
	finalizeEvidenceGraph(path, issues)
	return path, nil
}

func anySlice(value any) ([]any, bool) {
	switch values := value.(type) {
	case []any:
		return values, true
	case nil:
		return []any{}, true
	default:
		return []any{}, false
	}
}

func parsePathNode(m map[string]any) PathNode {
	pn := PathNode{
		Properties: make(map[string]any),
		Kinds:      []string{},
	}

	if id, ok := m["id"].(string); ok {
		pn.ID = id
	}

	switch kinds := m["kinds"].(type) {
	case []any:
		for _, k := range kinds {
			if s, ok := k.(string); ok {
				pn.Kinds = append(pn.Kinds, s)
			}
		}
	case []string:
		pn.Kinds = kinds
	}

	if props, ok := m["properties"].(map[string]any); ok {
		pn.Properties = props
	}

	return pn
}

func parsePathEdge(m map[string]any) PathEdge {
	pe := PathEdge{
		Properties: make(map[string]any),
	}

	if s, ok := m["source"].(string); ok {
		pe.Source = s
	}
	if t, ok := m["target"].(string); ok {
		pe.Target = t
	}
	if k, ok := m["kind"].(string); ok {
		pe.Kind = k
	}
	if props, ok := m["properties"].(map[string]any); ok {
		pe.Properties = props
	}
	pe.Synthetic = boolFromAny(pe.Properties["is_synthetic"])
	if pe.Synthetic {
		provenanceType, _ := pe.Properties["provenance_type"].(string)
		if provenanceType == "" {
			provenanceType = "synthetic_join"
		}
		basis, _ := pe.Properties["provenance_basis"].(string)
		sourceCollector, _ := pe.Properties["source_collector"].(string)
		pe.Provenance = &EdgeProvenance{
			Type:            provenanceType,
			Basis:           basis,
			SourceCollector: sourceCollector,
		}
	}

	return pe
}

func boolFromAny(v any) bool {
	switch value := v.(type) {
	case bool:
		return value
	case string:
		return strings.EqualFold(value, "true")
	default:
		return false
	}
}

var impactTemplates = map[string]struct {
	summary     string
	blastRadius string
}{
	"CAN_REACH": {
		summary:     "Agent %s has an inferred transitive access path to resource %s through the observed trust graph.",
		blastRadius: "Prompts handled by %s may be able to reach %s if the inferred relationships are invocable as modeled.",
	},
	"CAN_REACH_CROSS_PROTOCOL": {
		summary:     "A2A agent %s correlates with the MCP path to %s through a shared host; this is a 50%%-confidence hypothesis, not proven end-to-end invocation.",
		blastRadius: "The correlation identifies a boundary to investigate; it does not establish that %s can invoke %s.",
	},
	"CAN_REACH_CREDENTIAL_CHAIN_OBSERVED": {
		summary:     "Agent %s has a path through a shared LiteLLM gateway to credential %s with observed usable material.",
		blastRadius: "Agent %s can reach observed credential material for %s through the correlated gateway path.",
	},
	"CAN_REACH_CREDENTIAL_CHAIN_REFERENCE": {
		summary:     "Agent %s has a path through a shared LiteLLM gateway to credential reference %s; usable material is not present in this finding evidence.",
		blastRadius: "The path links agent %s to credential reference %s; verify material and exposure evidence before treating it as a credential leak.",
	},
	"CAN_EXFILTRATE_VIA": {
		summary:     "Agent %s has inferred sensitive-data access, and tool %s matched the configured exfiltration-channel predicate.",
		blastRadius: "The matched capability creates a potential output route; this finding is not evidence that data was exfiltrated.",
	},
	"CAN_EXECUTE": {
		summary:     "Tool metadata classifies %s as exposing shell or code execution that may run on host %s.",
		blastRadius: "Confirm the tool implementation and sandbox boundary before treating this metadata-derived route as host compromise.",
	},
	"HAS_ACCESS_TO": {
		summary:     "Tool %s has inferred access to resource %s based on capability matching.",
		blastRadius: "Review the attack path for impact assessment.",
	},
	"SHADOWS": {
		summary:     "Tool %s references tool %s by name from another server, matching the shadowing heuristic.",
		blastRadius: "Review both tool descriptions and server trust before concluding that requests can be intercepted.",
	},
	"POISONED_DESCRIPTION": {
		summary:     "Tool %s matched suspicious instruction patterns in its description.",
		blastRadius: "Pattern matches identify content to review; they do not prove that an agent followed the instructions.",
	},
	"CAN_IMPERSONATE": {
		summary:     "Agent %s has skill-description similarity to agent %s above the impersonation heuristic threshold.",
		blastRadius: "Similarity can confuse discovery or delegation, but does not by itself prove malicious impersonation.",
	},
	"POISONED_INSTRUCTIONS": {
		summary:     "Instruction file %s matched suspicious instruction patterns.",
		blastRadius: "Agents loading the file may be exposed; the pattern match does not prove that the instructions executed.",
	},
}

func BuildImpact(f *Finding, path *AttackPath, compositeProps map[string]any) *Impact {
	edgeKind := f.EdgeKind
	if edgeKind == "CAN_REACH" {
		switch {
		case f.Variant == model.FindingVariantCredentialObservedMaterial:
			edgeKind = "CAN_REACH_CREDENTIAL_CHAIN_OBSERVED"
		case f.Variant == model.FindingVariantCredentialReference:
			edgeKind = "CAN_REACH_CREDENTIAL_CHAIN_REFERENCE"
		case f.Variant == model.FindingVariantCrossProtocolHostCorrelation:
			edgeKind = "CAN_REACH_CROSS_PROTOCOL"
		case isCredentialChain(compositeProps):
			// Compatibility for live findings produced before variants were
			// persisted. Published rows use the explicit Variant above.
			if f.Category == "Credential Exposure" && f.Severity == "critical" {
				edgeKind = "CAN_REACH_CREDENTIAL_CHAIN_OBSERVED"
			} else {
				edgeKind = "CAN_REACH_CREDENTIAL_CHAIN_REFERENCE"
			}
		case boolVal(compositeProps, "cross_protocol"):
			edgeKind = "CAN_REACH_CROSS_PROTOCOL"
		}
	}

	srcName := f.SourceName
	if srcName == "" {
		srcName = f.SourceID
	}
	tgtName := f.TargetName
	if tgtName == "" {
		tgtName = f.TargetID
	}

	tmpl, ok := impactTemplates[edgeKind]
	if !ok {
		return &Impact{
			Summary:     fmt.Sprintf("Composite edge %s detected between %s and %s.", f.EdgeKind, srcName, tgtName),
			BlastRadius: "Review the attack path for impact assessment.",
		}
	}

	impact := &Impact{
		Summary:     formatImpactTemplate(tmpl.summary, srcName, tgtName),
		BlastRadius: formatImpactTemplate(tmpl.blastRadius, srcName, tgtName),
	}

	if path != nil {
		for _, n := range path.Nodes {
			if sensitivity, ok := n.Properties["sensitivity"].(string); ok && sensitivity != "" {
				impact.DataSensitivity = sensitivity
				break
			}
		}
	}

	return impact
}

// isCredentialChain returns true when compositeProps describe a finding
// emitted by processors/cross_service_credential_chain.go. We branch on
// source_collector (canonical) and fall back to via_gateway/merge_value_hash
// presence for older edges that may pre-date the source_collector tag.
func isCredentialChain(props map[string]any) bool {
	if props == nil {
		return false
	}
	if sc, _ := props["source_collector"].(string); sc == "cross_service_credential_chain" {
		return true
	}
	if gw, _ := props["via_gateway"].(string); gw != "" {
		if mh, _ := props["merge_value_hash"].(string); mh != "" {
			return true
		}
	}
	return false
}

// formatImpactTemplate substitutes srcName/tgtName into a Summary or
// BlastRadius template without producing Go's "%!(EXTRA ...)" warts.
// Templates may carry zero placeholders (static prose like CAN_EXECUTE's
// blast radius), one placeholder (POISONED_DESCRIPTION's summary names
// only the tool), or two (CAN_REACH names both ends of the chain).
// Calling fmt.Sprintf with extra args produces a literal trailing
// "%!(EXTRA string=...)" in the output, which is what users were
// previously seeing on POISONED_DESCRIPTION / POISONED_INSTRUCTIONS
// findings.
func formatImpactTemplate(tmpl, srcName, tgtName string) string {
	switch strings.Count(tmpl, "%s") {
	case 0:
		return tmpl
	case 1:
		return fmt.Sprintf(tmpl, srcName)
	default:
		return fmt.Sprintf(tmpl, srcName, tgtName)
	}
}
