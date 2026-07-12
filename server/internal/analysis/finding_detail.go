package analysis

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/adithyan-ak/agenthound/server/internal/graph"
	"github.com/adithyan-ak/agenthound/server/model"
)

type FindingDetail struct {
	Finding        Finding           `json:"finding"`
	CompositeProps map[string]any    `json:"composite_props,omitempty"`
	AttackPath     *AttackPath       `json:"attack_path"`
	EvidenceDAG    *EvidenceDAG      `json:"evidence_dag"`
	Remediation    []RemediationStep `json:"remediation"`
	Impact         *Impact           `json:"impact"`
}

type AttackPath struct {
	Nodes []PathNode `json:"nodes"`
	Edges []PathEdge `json:"edges"`
	// TotalRiskWeight is NULLABLE: nil means the total is unknown because at
	// least one edge on the path carried no risk_weight. A benign 0 is never
	// substituted for a missing weight. WeightMissingCount records how many
	// edges lacked a weight.
	TotalRiskWeight    *float64 `json:"total_risk_weight"`
	WeightMissingCount int      `json:"weight_missing_count"`
}

// EvidenceDAG is the typed evidence graph backing a finding. It records the
// join between each pair of evidence nodes as observed (a real graph edge in
// its stored direction), reversed (a real edge traversed against its
// direction), or synthetic (a non-edge join such as a value_hash equality).
// Absence of a complete evidence set is explicit (Complete=false), never
// coerced into a clean verdict.
type EvidenceDAG struct {
	Nodes               []EvidenceNode `json:"nodes"`
	Joins               []EvidenceJoin `json:"joins"`
	ConnectedComponents int            `json:"connected_components"`
	ConfidenceBasis     string         `json:"confidence_basis"`
	// WeightTotal / WeightMissingCount mirror the path weight totals with the
	// same nullable semantics.
	WeightTotal        *float64 `json:"weight_total"`
	WeightMissingCount int      `json:"weight_missing_count"`
	// Complete is true only when the evidence forms a single connected
	// component spanning the finding's source and target.
	Complete bool `json:"complete"`
}

// JoinType classifies how two evidence nodes are joined.
type JoinType string

const (
	// JoinObserved is a real graph edge traversed in its stored direction.
	JoinObserved JoinType = "observed"
	// JoinReversed is a real graph edge traversed against its stored
	// direction (the attack flow runs target→source).
	JoinReversed JoinType = "reversed"
	// JoinSynthetic is a non-edge join (e.g. a Credential.value_hash
	// equality) that binds two nodes without a graph relationship.
	JoinSynthetic JoinType = "synthetic"
)

type EvidenceNode struct {
	ID    string   `json:"id"`
	Kinds []string `json:"kinds"`
	Name  string   `json:"name,omitempty"`
	// Role is the node's position in the attack flow: source, target, or
	// intermediate.
	Role string `json:"role"`
}

type EvidenceJoin struct {
	Source string   `json:"source"`
	Target string   `json:"target"`
	Kind   string   `json:"kind"`
	Type   JoinType `json:"type"`
	// Weight is NULLABLE: nil when the underlying edge carried no risk_weight.
	Weight *float64 `json:"weight"`
}

type PathNode struct {
	ID         string         `json:"id"`
	Kinds      []string       `json:"kinds"`
	Properties map[string]any `json:"properties"`
}

type PathEdge struct {
	Source     string         `json:"source"`
	Target     string         `json:"target"`
	Kind       string         `json:"kind"`
	Properties map[string]any `json:"properties"`
}

type RemediationStep struct {
	Step        int      `json:"step"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	EdgeKind    string   `json:"edge_kind"`
	Commands    []string `json:"commands,omitempty"`
}

type Impact struct {
	Summary         string `json:"summary"`
	BlastRadius     string `json:"blast_radius"`
	DataSensitivity string `json:"data_sensitivity,omitempty"`
}

// EvidenceDAGFromPersisted decodes the typed evidence DAG stored on a finding
// occurrence back into an *EvidenceDAG. The nullable weight totals and missing
// count are overlaid from the occurrence's own columns so the detail view
// reports exactly what was persisted at snapshot time — not a recomputation
// against a since-mutated live graph. Returns (nil,false) when the finding
// carries no persisted DAG (so the caller can fall back to live reconstruction).
func EvidenceDAGFromPersisted(f *model.Finding) (*EvidenceDAG, bool) {
	if f == nil || len(f.EvidenceDAG) == 0 {
		return nil, false
	}
	raw, err := json.Marshal(f.EvidenceDAG)
	if err != nil {
		return nil, false
	}
	var dag EvidenceDAG
	if err := json.Unmarshal(raw, &dag); err != nil {
		return nil, false
	}
	// Prefer the occurrence's own nullable weight columns as the source of
	// truth for the totals (they and the DAG were derived together at ingest).
	dag.WeightTotal = f.WeightTotal
	dag.WeightMissingCount = f.WeightMissingCount
	return &dag, true
}

// AttackPathFromEvidenceDAG rebuilds a presentational AttackPath from a
// persisted evidence DAG so the detail view's path, remediation, and impact
// are all derived from the SAME persisted evidence the list returned, keeping
// list/detail in parity. Synthetic joins are preserved (marked is_synthetic)
// so weight accounting stays consistent with sumEdgeWeights.
func AttackPathFromEvidenceDAG(dag *EvidenceDAG) *AttackPath {
	if dag == nil {
		return nil
	}
	nodes := make([]PathNode, 0, len(dag.Nodes))
	for _, n := range dag.Nodes {
		props := map[string]any{}
		if n.Name != "" {
			props["name"] = n.Name
		}
		nodes = append(nodes, PathNode{ID: n.ID, Kinds: n.Kinds, Properties: props})
	}
	edges := make([]PathEdge, 0, len(dag.Joins))
	for _, j := range dag.Joins {
		props := map[string]any{}
		if j.Weight != nil {
			props["risk_weight"] = *j.Weight
		}
		if j.Type == JoinSynthetic {
			props["is_synthetic"] = true
		}
		edges = append(edges, PathEdge{Source: j.Source, Target: j.Target, Kind: j.Kind, Properties: props})
	}
	return &AttackPath{
		Nodes:              nodes,
		Edges:              edges,
		TotalRiskWeight:    dag.WeightTotal,
		WeightMissingCount: dag.WeightMissingCount,
	}
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

// compositeEdgePropsQuery matches the composite edge by its generations-set
// membership rather than by endpoint generation_id equality. A cross-artifact
// credential chain spans generations (the agent is a config-generation
// observation, the upstream credential a loot-generation observation), so
// pinning BOTH endpoints to a single generation_id would fail to find the edge
// and leave the persisted DAG/detail/impact empty. Keying on the edge's own
// generations set finds it regardless of where its endpoints were observed.
const compositeEdgePropsQuery = `
MATCH (src {objectid: $source})-[r]->(tgt {objectid: $target})
WHERE type(r) = $edge_kind AND r.is_composite = true
  AND $generation IN coalesce(r.generations, [])
RETURN properties(r) AS props
LIMIT 1`

func GetCompositeEdgeProps(ctx context.Context, db graph.GraphDB, f *Finding) (map[string]any, error) {
	rows, err := db.Query(ctx, compositeEdgePropsQuery, map[string]any{
		"source":     f.SourceID,
		"target":     f.TargetID,
		"edge_kind":  f.EdgeKind,
		"generation": f.GenerationID,
	})
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	props, _ := rows[0]["props"].(map[string]any)
	return props, nil
}

var pathQueriesByEdgeKind = map[string][]string{
	"CAN_REACH": {
		`MATCH (a:AgentInstance {objectid: $source, generation_id: $generation})
      -[r1:TRUSTS_SERVER]->(s:MCPServer)
      -[r2:PROVIDES_TOOL]->(t:MCPTool)
      -[r3:HAS_ACCESS_TO]->(r:MCPResource {objectid: $target, generation_id: $generation})
RETURN [n IN [a, s, t, r] | {id: n.objectid, name: n.name, kinds: labels(n), properties: properties(n)}] AS nodes,
       [rel IN [r1, r2, r3] | {kind: type(rel), source: startNode(rel).objectid, target: endNode(rel).objectid, properties: properties(rel)}] AS edges
LIMIT 1`,
		`MATCH (a:AgentInstance {objectid: $source, generation_id: $generation})-[r1:TRUSTS_SERVER]->(s1:MCPServer)
      -[r2:PROVIDES_TOOL]->(t1:MCPTool)
MATCH (s2:MCPServer)-[r3:HAS_ENV_VAR]->(c:Credential)
MATCH (c)<-[r4:USES_CREDENTIAL]-(i:Identity)<-[r5:AUTHENTICATES_WITH]-(s2)
MATCH (s2)-[r6:PROVIDES_TOOL]->(t2:MCPTool)-[r7:HAS_ACCESS_TO]->(r:MCPResource {objectid: $target, generation_id: $generation})
WHERE s1 <> s2
RETURN [n IN [a, s1, t1, c, i, s2, t2, r] | {id: n.objectid, name: n.name, kinds: labels(n), properties: properties(n)}] AS nodes,
       [rel IN [r1, r2, r3, r4, r5, r6, r7] | {kind: type(rel), source: startNode(rel).objectid, target: endNode(rel).objectid, properties: properties(rel)}] AS edges
LIMIT 1`,
	},
	"CAN_REACH_CROSS_PROTOCOL": {
		`MATCH (ext:A2AAgent {objectid: $source, generation_id: $generation})-[d:DELEGATES_TO*1..3]->(int:A2AAgent)
MATCH (int)-[r1:RUNS_ON]->(h:Host)<-[r2:RUNS_ON]-(s:MCPServer)
MATCH (a:AgentInstance)-[r3:TRUSTS_SERVER]->(s)
      -[r4:PROVIDES_TOOL]->(t:MCPTool)-[r5:HAS_ACCESS_TO]->(r:MCPResource {objectid: $target, generation_id: $generation})
RETURN [n IN [ext, int, h, s, a, t, r] | {id: n.objectid, name: n.name, kinds: labels(n), properties: properties(n)}] AS nodes,
       [{kind: 'DELEGATES_TO', source: ext.objectid, target: int.objectid, properties: {}}] + [rel IN [r1, r2, r3, r4, r5] | {kind: type(rel), source: startNode(rel).objectid, target: endNode(rel).objectid, properties: properties(rel)}] AS edges
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
		`MATCH (a:AgentInstance {objectid: $source, generation_id: $generation})-[r1:TRUSTS_SERVER]->(s:MCPServer)
      -[r2:HAS_ENV_VAR]->(c1:Credential)
MATCH (gw:LiteLLMGateway)-[r3:EXPOSES_CREDENTIAL]->(c1master:Credential)
WHERE c1master.value_hash = c1.value_hash AND c1master.objectid <> c1.objectid
MATCH (gw)-[r4:EXPOSES_CREDENTIAL]->(c2:Credential {objectid: $target, generation_id: $generation})
RETURN [n IN [a, s, c1, c1master, gw, c2] | {id: n.objectid, name: n.name, kinds: labels(n), properties: properties(n)}] AS nodes,
       [rel IN [r1, r2, r3, r4] | {kind: type(rel), source: startNode(rel).objectid, target: endNode(rel).objectid, properties: properties(rel)}] +
       [{kind: 'VALUE_HASH_MATCH', source: c1.objectid, target: c1master.objectid, properties: {merge_value_hash: c1.value_hash, is_synthetic: true}}] AS edges
LIMIT 1`,
	},
	"CAN_EXFILTRATE_VIA": {
		`MATCH (a:AgentInstance {objectid: $source, generation_id: $generation})-[:TRUSTS_SERVER]->(s1:MCPServer)
      -[r1:PROVIDES_TOOL]->(outbound:MCPTool {objectid: $target, generation_id: $generation})
WHERE ANY(cap IN outbound.capability_surface WHERE cap IN ['email_send', 'network_outbound', 'file_write'])
WITH a, s1, r1, outbound
OPTIONAL MATCH (a)-[:TRUSTS_SERVER]->(s2:MCPServer)-[:PROVIDES_TOOL]->(t2:MCPTool)-[:HAS_ACCESS_TO]->(res:MCPResource)
WHERE res.sensitivity IN ['critical', 'high']
WITH a, s1, r1, outbound, s2, t2, res LIMIT 1
RETURN [n IN [a, s1, outbound] + CASE WHEN res IS NOT NULL THEN [s2, t2, res] ELSE [] END | {id: n.objectid, name: n.name, kinds: labels(n), properties: properties(n)}] AS nodes,
       [{kind: 'TRUSTS_SERVER', source: a.objectid, target: s1.objectid, properties: {}}] + [{kind: 'PROVIDES_TOOL', source: s1.objectid, target: outbound.objectid, properties: {}}] AS edges
LIMIT 1`,
	},
	"CAN_EXECUTE": {
		`MATCH (s:MCPServer)-[r1:PROVIDES_TOOL]->(t:MCPTool {objectid: $source, generation_id: $generation}),
      (s)-[r2:RUNS_ON]->(h:Host {objectid: $target, generation_id: $generation})
RETURN [n IN [s, t, h] | {id: n.objectid, name: n.name, kinds: labels(n), properties: properties(n)}] AS nodes,
       [rel IN [r1, r2] | {kind: type(rel), source: startNode(rel).objectid, target: endNode(rel).objectid, properties: properties(rel)}] AS edges
LIMIT 1`,
	},
	"HAS_ACCESS_TO": {
		`MATCH (s:MCPServer)-[r1:PROVIDES_TOOL]->(t:MCPTool {objectid: $source, generation_id: $generation}),
      (s)-[r2:PROVIDES_RESOURCE]->(r:MCPResource {objectid: $target, generation_id: $generation})
RETURN [n IN [s, t, r] | {id: n.objectid, name: n.name, kinds: labels(n), properties: properties(n)}] AS nodes,
       [rel IN [r1, r2] | {kind: type(rel), source: startNode(rel).objectid, target: endNode(rel).objectid, properties: properties(rel)}] AS edges
LIMIT 1`,
	},
	"SHADOWS": {
		`MATCH (s1:MCPServer)-[r1:PROVIDES_TOOL]->(t1:MCPTool {objectid: $source, generation_id: $generation}),
      (s2:MCPServer)-[r2:PROVIDES_TOOL]->(t2:MCPTool {objectid: $target, generation_id: $generation})
WHERE s1 <> s2
RETURN [n IN [s1, t1, t2, s2] | {id: n.objectid, name: n.name, kinds: labels(n), properties: properties(n)}] AS nodes,
       [rel IN [r1, r2] | {kind: type(rel), source: startNode(rel).objectid, target: endNode(rel).objectid, properties: properties(rel)}] AS edges
LIMIT 1`,
	},
	"POISONED_DESCRIPTION": {
		`MATCH (s:MCPServer)-[r1:PROVIDES_TOOL]->(t:MCPTool {objectid: $source, generation_id: $generation})
RETURN [n IN [s, t] | {id: n.objectid, name: n.name, kinds: labels(n), properties: properties(n)}] AS nodes,
       [rel IN [r1] | {kind: type(rel), source: startNode(rel).objectid, target: endNode(rel).objectid, properties: properties(rel)}] AS edges
LIMIT 1`,
	},
	"CAN_IMPERSONATE": {
		`MATCH (a1:A2AAgent {objectid: $source, generation_id: $generation}), (a2:A2AAgent {objectid: $target, generation_id: $generation})
RETURN [{id: a1.objectid, name: a1.name, kinds: labels(a1), properties: properties(a1)},
        {id: a2.objectid, name: a2.name, kinds: labels(a2), properties: properties(a2)}] AS nodes,
       [] AS edges
LIMIT 1`,
	},
	"POISONED_INSTRUCTIONS": {
		`MATCH (a:AgentInstance)-[r1:LOADS_INSTRUCTIONS]->(f:InstructionFile {objectid: $source, generation_id: $generation})
RETURN [n IN [a, f] | {id: n.objectid, name: n.name, kinds: labels(n), properties: properties(n)}] AS nodes,
       [rel IN [r1] | {kind: type(rel), source: startNode(rel).objectid, target: endNode(rel).objectid, properties: properties(rel)}] AS edges
LIMIT 1`,
	},
}

// ReconstructAttackPath rebuilds the observed evidence path for a finding.
// It keys directly on the finding's edge kind — including the dedicated
// CAN_REACH_CROSS_PROTOCOL and CAN_REACH_CREDENTIAL_CHAIN variants — so a
// heuristic or credential-access reach is reconstructed with its true chain
// rather than the proven-reach template. When no dedicated query matches (or
// none returns rows), it falls back to a single bounded, directed,
// minimum-weight traversal (see pathfind.go) instead of the previous
// undirected shortestPath.
func ReconstructAttackPath(ctx context.Context, db graph.GraphDB, f *Finding, compositeProps map[string]any) (*AttackPath, error) {
	// Credential-chain findings can span generations (agent in the config
	// generation, upstream key in the loot generation). Reconstruct the chain
	// from the composite edge's PERSISTED evidence metadata so the DAG is
	// complete and self-contained rather than depending on a single-generation
	// re-traversal that would return nothing for a cross-artifact chain.
	if f.EdgeKind == "CAN_REACH_CREDENTIAL_CHAIN" {
		if p := credentialChainPathFromProps(f, compositeProps); p != nil {
			return p, nil
		}
	}

	params := map[string]any{
		"source":     f.SourceID,
		"target":     f.TargetID,
		"generation": f.GenerationID,
	}

	for _, q := range pathQueriesByEdgeKind[f.EdgeKind] {
		path, err := tryPathQuery(ctx, db, q, params)
		if err != nil {
			continue
		}
		if path != nil {
			return path, nil
		}
	}

	// Generation-backed occurrences must never fall back to an unscoped live
	// traversal: that could assemble evidence from a different retained
	// generation. An absent dedicated path is honestly incomplete.
	if f.GenerationID != "" {
		return nil, nil
	}
	path, err := BoundedMinWeightPath(ctx, db, f.SourceID, f.TargetID, DefaultTraversalPolicy())
	if err != nil {
		return nil, fmt.Errorf("bounded path traversal: %w", err)
	}
	return path, nil
}

// credentialChainPathFromProps rebuilds the full agent → server → env-var
// credential ==(value_hash)== master key → gateway → upstream credential path
// from the composite edge's persisted evidence metadata. It returns nil when
// the edge predates the enriched metadata (so the caller falls back to the
// live re-traversal), which is the only case where a single-generation query
// might still succeed (a same-artifact chain).
//
// The rebuilt path is deterministic and generation-independent: every node id
// and display name comes from the persisted edge, so the resulting evidence DAG
// is a single connected component spanning source→target (Complete=true) even
// when the endpoints were observed in different generations. The synthetic
// value_hash join is marked so it is excluded from weight accounting.
func credentialChainPathFromProps(f *Finding, props map[string]any) *AttackPath {
	if props == nil {
		return nil
	}
	serverID := stringFromProps(props, "via_server_id")
	credID := stringFromProps(props, "via_credential_id")
	masterID := stringFromProps(props, "master_credential_id")
	gatewayID := stringFromProps(props, "via_gateway_id")
	if serverID == "" || credID == "" || masterID == "" || gatewayID == "" {
		return nil
	}
	valueHash := stringFromProps(props, "merge_value_hash")

	sourceKind := f.SourceKind
	if sourceKind == "" {
		sourceKind = "AgentInstance"
	}
	targetKind := f.TargetKind
	if targetKind == "" {
		targetKind = "Credential"
	}
	node := func(id, kind, name string) PathNode {
		p := map[string]any{}
		if name != "" {
			p["name"] = name
		}
		return PathNode{ID: id, Kinds: []string{kind}, Properties: p}
	}
	nodes := []PathNode{
		node(f.SourceID, sourceKind, f.SourceName),
		node(serverID, "MCPServer", stringFromProps(props, "via_server")),
		node(credID, "Credential", stringFromProps(props, "via_credential")),
		node(masterID, "Credential", stringFromProps(props, "master_credential_name")),
		node(gatewayID, "LiteLLMGateway", stringFromProps(props, "via_gateway")),
		node(f.TargetID, targetKind, f.TargetName),
	}
	edge := func(src, tgt, kind string, synthetic bool) PathEdge {
		p := map[string]any{}
		if synthetic {
			p["is_synthetic"] = true
			if valueHash != "" {
				p["merge_value_hash"] = valueHash
			}
		}
		return PathEdge{Source: src, Target: tgt, Kind: kind, Properties: p}
	}
	edges := []PathEdge{
		edge(f.SourceID, serverID, "TRUSTS_SERVER", false),
		edge(serverID, credID, "HAS_ENV_VAR", false),
		edge(credID, masterID, "VALUE_HASH_MATCH", true),
		edge(gatewayID, masterID, "EXPOSES_CREDENTIAL", false),
		edge(gatewayID, f.TargetID, "EXPOSES_CREDENTIAL", false),
	}
	total, missing := sumEdgeWeights(edges)
	return &AttackPath{
		Nodes:              nodes,
		Edges:              edges,
		TotalRiskWeight:    total,
		WeightMissingCount: missing,
	}
}

// stringFromProps reads a string-valued property, returning "" when absent or
// non-string.
func stringFromProps(props map[string]any, key string) string {
	if props == nil {
		return ""
	}
	if s, ok := props[key].(string); ok {
		return s
	}
	return ""
}

func tryPathQuery(ctx context.Context, db graph.GraphDB, cypher string, params map[string]any) (*AttackPath, error) {
	rows, err := db.Query(ctx, cypher, params)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return parseAttackPath(rows[0])
}

func parseAttackPath(row map[string]any) (*AttackPath, error) {
	rawNodes, _ := row["nodes"].([]any)
	rawEdges, _ := row["edges"].([]any)

	if len(rawNodes) == 0 {
		return nil, nil
	}

	nodes := make([]PathNode, 0, len(rawNodes))
	seen := make(map[string]bool)
	for _, rn := range rawNodes {
		nm, ok := rn.(map[string]any)
		if !ok {
			continue
		}
		pn := parsePathNode(nm)
		if pn.ID == "" || seen[pn.ID] {
			continue
		}
		seen[pn.ID] = true
		nodes = append(nodes, pn)
	}

	edges := make([]PathEdge, 0, len(rawEdges))
	for _, re := range rawEdges {
		em, ok := re.(map[string]any)
		if !ok {
			continue
		}
		pe := parsePathEdge(em)
		if pe.Source == "" || pe.Target == "" {
			continue
		}
		edges = append(edges, pe)
	}

	total, missing := sumEdgeWeights(edges)
	return &AttackPath{
		Nodes:              nodes,
		Edges:              edges,
		TotalRiskWeight:    total,
		WeightMissingCount: missing,
	}, nil
}

// edgeWeight returns the edge's risk_weight and whether it was present. A
// value of exactly 0 is a legitimate weight (e.g. CONFIGURED_IN), so presence
// is keyed on the property existing and being numeric, not on being non-zero.
func edgeWeight(pe PathEdge) (float64, bool) {
	if pe.Properties == nil {
		return 0, false
	}
	v, ok := pe.Properties["risk_weight"]
	if !ok || v == nil {
		return 0, false
	}
	switch f := v.(type) {
	case float64:
		return f, true
	case int64:
		return float64(f), true
	case int:
		return float64(f), true
	default:
		return 0, false
	}
}

// isSyntheticEdge reports whether an edge is a non-graph join (e.g. a
// value_hash equality) rather than a traversable, cost-bearing attack step.
// Synthetic joins are identity facts, so they are excluded from weight
// accounting entirely — they neither add to the total nor count as a missing
// weight.
func isSyntheticEdge(pe PathEdge) bool {
	if pe.Kind == "VALUE_HASH_MATCH" {
		return true
	}
	if pe.Properties != nil {
		if syn, _ := pe.Properties["is_synthetic"].(bool); syn {
			return true
		}
	}
	return false
}

// sumEdgeWeights totals the present risk weights of the weight-bearing (non-
// synthetic) edges and counts the missing ones. The total is nil (unknown)
// whenever any weight-bearing edge lacked a weight, so a partial sum is never
// reported as if it were complete.
func sumEdgeWeights(edges []PathEdge) (*float64, int) {
	var total float64
	var missing int
	for _, pe := range edges {
		if isSyntheticEdge(pe) {
			continue
		}
		if w, ok := edgeWeight(pe); ok {
			total += w
		} else {
			missing++
		}
	}
	if missing > 0 {
		return nil, missing
	}
	return &total, 0
}

func parsePathNode(m map[string]any) PathNode {
	pn := PathNode{
		Properties: make(map[string]any),
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

	return pe
}

func floatFromAny(v any) float64 {
	switch f := v.(type) {
	case float64:
		return f
	case int64:
		return float64(f)
	case int:
		return float64(f)
	default:
		return 0
	}
}

var impactTemplates = map[string]struct {
	summary     string
	blastRadius string
}{
	"CAN_REACH": {
		summary:     "Agent %s can transitively access resource %s through the trust chain.",
		blastRadius: "Any prompt running in %s context can access %s.",
	},
	"CAN_REACH_CROSS_PROTOCOL": {
		summary:     "External A2A agent %s can reach %s resource across protocol boundaries (A2A -> MCP).",
		blastRadius: "Any prompt running in %s context can access %s.",
	},
	"CAN_REACH_CREDENTIAL_CHAIN": {
		summary:     "Agent %s can reach upstream provider credential %s through a value_hash collision in a LiteLLM gateway.",
		blastRadius: "Compromise of agent %s's MCP env-var credential exposes upstream provider key %s, enabling lateral movement to every service the gateway fronts.",
	},
	"CAN_EXFILTRATE_VIA": {
		summary:     "Agent %s has access to sensitive data and can exfiltrate it via %s tool with outbound capability.",
		blastRadius: "Data from resources with sensitive data can be sent to external destinations.",
	},
	"CAN_EXECUTE": {
		summary:     "Tool %s can execute arbitrary commands on host %s.",
		blastRadius: "Full host compromise is possible through any agent with access to this tool.",
	},
	"HAS_ACCESS_TO": {
		summary:     "Tool %s has inferred access to resource %s based on capability matching.",
		blastRadius: "Review the attack path for impact assessment.",
	},
	"SHADOWS": {
		summary:     "Tool %s shadows tool %s, potentially intercepting requests meant for the legitimate tool.",
		blastRadius: "Agents trusting the malicious server may unknowingly use the shadow tool.",
	},
	"POISONED_DESCRIPTION": {
		summary:     "Tool %s has injection patterns that could manipulate LLM behavior.",
		blastRadius: "Any agent invoking this tool may execute attacker-controlled instructions.",
	},
	"CAN_IMPERSONATE": {
		summary:     "Agent %s can impersonate agent %s due to highly similar skill descriptions.",
		blastRadius: "Clients may be tricked into delegating to the impersonating agent.",
	},
	"POISONED_INSTRUCTIONS": {
		summary:     "Instruction file %s contains suspicious patterns that could hijack agent behavior.",
		blastRadius: "All agents loading this instruction file are affected.",
	},
}

func BuildImpact(f *Finding, path *AttackPath, compositeProps map[string]any) *Impact {
	srcName := f.SourceName
	if srcName == "" {
		srcName = f.SourceID
	}
	tgtName := f.TargetName
	if tgtName == "" {
		tgtName = f.TargetID
	}

	tmpl, ok := impactTemplates[f.EdgeKind]
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

	// Channel-specific exfiltration prose: name the outbound channel(s) the
	// tool actually exposes (email_send, network_outbound, ...) instead of a
	// generic "outbound capability".
	if f.EdgeKind == "CAN_EXFILTRATE_VIA" {
		if channels := exfilChannels(compositeProps); channels != "" {
			impact.Summary += fmt.Sprintf(" Outbound channel(s): %s.", channels)
		}
	}

	if path != nil {
		for _, n := range path.Nodes {
			if sensitivity, ok := n.Properties["sensitivity"].(string); ok && sensitivity != "" {
				impact.DataSensitivity = sensitivity
				break
			}
		}
	}
	// Persisted DAG nodes intentionally carry a compact identity projection,
	// not arbitrary mutable node properties. Composite observations therefore
	// snapshot the resource sensitivity explicitly; use it when the path node
	// projection has no sensitivity so impact remains independent of live
	// Neo4j.
	if impact.DataSensitivity == "" && compositeProps != nil {
		if sensitivity, ok := compositeProps["resource_sensitivity"].(string); ok {
			impact.DataSensitivity = sensitivity
		}
	}

	return impact
}

// exfilChannels renders the CAN_EXFILTRATE_VIA edge's exfil_channels property
// (set by the can_exfiltrate processor) as a comma-joined list. Returns empty
// when the channel set was not recorded.
func exfilChannels(props map[string]any) string {
	if props == nil {
		return ""
	}
	raw, ok := props["exfil_channels"]
	if !ok || raw == nil {
		return ""
	}
	var chans []string
	switch v := raw.(type) {
	case []any:
		for _, c := range v {
			if s, ok := c.(string); ok && s != "" {
				chans = append(chans, s)
			}
		}
	case []string:
		chans = append(chans, v...)
	}
	return strings.Join(chans, ", ")
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

// BuildEvidenceDAG derives the typed evidence graph for a finding from its
// reconstructed attack path. Each path edge becomes a typed join (observed,
// reversed, or synthetic), the weakly-connected-component count is computed
// over those joins, and the nullable weight total is carried through with its
// missing-weight count. When no path was reconstructed the DAG is explicitly
// incomplete (Complete=false, WeightTotal=nil) so a caller can never mistake a
// missing evidence set for a clean, zero-cost verdict.
func BuildEvidenceDAG(f *Finding, path *AttackPath, compositeProps map[string]any) *EvidenceDAG {
	basis := f.ConfidenceBasis
	if basis == "" {
		basis = confidenceBasis(f.EdgeKind, f.Confidence, boolVal(compositeProps, "cross_protocol"))
	}

	if path == nil || len(path.Nodes) == 0 {
		nodes := endpointNodes(f)
		return &EvidenceDAG{
			Nodes:               nodes,
			Joins:               []EvidenceJoin{},
			ConnectedComponents: len(nodes),
			ConfidenceBasis:     basis,
			WeightTotal:         nil,
			WeightMissingCount:  0,
			Complete:            false,
		}
	}

	// Narrative (flow) order is the order nodes were returned by the path
	// query. A join whose source appears later in the flow than its target
	// was traversed against its stored direction.
	flowIndex := make(map[string]int, len(path.Nodes))
	nodes := make([]EvidenceNode, 0, len(path.Nodes))
	for i, n := range path.Nodes {
		flowIndex[n.ID] = i
		name, _ := n.Properties["name"].(string)
		nodes = append(nodes, EvidenceNode{
			ID:    n.ID,
			Kinds: n.Kinds,
			Name:  name,
			Role:  nodeRole(f, n.ID),
		})
	}

	joins := make([]EvidenceJoin, 0, len(path.Edges))
	for _, e := range path.Edges {
		var w *float64
		if wt, ok := edgeWeight(e); ok {
			ww := wt
			w = &ww
		}
		joins = append(joins, EvidenceJoin{
			Source: e.Source,
			Target: e.Target,
			Kind:   e.Kind,
			Type:   classifyJoin(e, flowIndex),
			Weight: w,
		})
	}

	components := connectedComponents(nodes, joins)
	spans := nodeRolePresent(nodes, "source") && nodeRolePresent(nodes, "target")
	complete := components == 1 && spans

	// Recompute from the edges so the DAG is self-consistent regardless of how
	// the AttackPath was populated (dedicated query, bounded traversal, or a
	// hand-built path). Synthetic joins are excluded from weight accounting.
	total, missing := sumEdgeWeights(path.Edges)

	return &EvidenceDAG{
		Nodes:               nodes,
		Joins:               joins,
		ConnectedComponents: components,
		ConfidenceBasis:     basis,
		WeightTotal:         total,
		WeightMissingCount:  missing,
		Complete:            complete,
	}
}

// endpointNodes returns the finding's source/target as bare evidence nodes,
// used when no path could be reconstructed.
func endpointNodes(f *Finding) []EvidenceNode {
	var nodes []EvidenceNode
	if f.SourceID != "" {
		nodes = append(nodes, EvidenceNode{ID: f.SourceID, Name: f.SourceName, Kinds: kindsOrNil(f.SourceKind), Role: "source"})
	}
	if f.TargetID != "" && f.TargetID != f.SourceID {
		nodes = append(nodes, EvidenceNode{ID: f.TargetID, Name: f.TargetName, Kinds: kindsOrNil(f.TargetKind), Role: "target"})
	}
	return nodes
}

func kindsOrNil(kind string) []string {
	if kind == "" {
		return nil
	}
	return []string{kind}
}

func nodeRole(f *Finding, id string) string {
	switch id {
	case f.SourceID:
		return "source"
	case f.TargetID:
		return "target"
	default:
		return "intermediate"
	}
}

func nodeRolePresent(nodes []EvidenceNode, role string) bool {
	for _, n := range nodes {
		if n.Role == role {
			return true
		}
	}
	return false
}

// classifyJoin labels an edge as synthetic (a non-graph join such as a
// value_hash equality), reversed (traversed against its stored direction), or
// observed (traversed in its stored direction).
func classifyJoin(e PathEdge, flowIndex map[string]int) JoinType {
	if e.Kind == "VALUE_HASH_MATCH" {
		return JoinSynthetic
	}
	if e.Properties != nil {
		if syn, _ := e.Properties["is_synthetic"].(bool); syn {
			return JoinSynthetic
		}
	}
	si, sok := flowIndex[e.Source]
	ti, tok := flowIndex[e.Target]
	if sok && tok && si > ti {
		return JoinReversed
	}
	return JoinObserved
}

// connectedComponents counts weakly-connected components over the evidence
// nodes, treating every join as undirected, via union-find.
func connectedComponents(nodes []EvidenceNode, joins []EvidenceJoin) int {
	parent := make(map[string]string, len(nodes))
	for _, n := range nodes {
		parent[n.ID] = n.ID
	}
	var find func(string) string
	find = func(x string) string {
		p, ok := parent[x]
		if !ok {
			parent[x] = x
			return x
		}
		if p != x {
			parent[x] = find(p)
		}
		return parent[x]
	}
	union := func(a, b string) {
		ra, rb := find(a), find(b)
		if ra != rb {
			parent[ra] = rb
		}
	}
	for _, j := range joins {
		if _, ok := parent[j.Source]; !ok {
			parent[j.Source] = j.Source
		}
		if _, ok := parent[j.Target]; !ok {
			parent[j.Target] = j.Target
		}
		union(j.Source, j.Target)
	}
	roots := make(map[string]bool)
	for k := range parent {
		roots[find(k)] = true
	}
	return len(roots)
}
