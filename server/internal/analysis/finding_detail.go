package analysis

import (
	"context"
	"fmt"
	"strings"

	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

type FindingDetail struct {
	Finding        Finding           `json:"finding"`
	CompositeProps map[string]any    `json:"composite_props,omitempty"`
	AttackPath     *AttackPath       `json:"attack_path"`
	Remediation    []RemediationStep `json:"remediation"`
	Impact         *Impact           `json:"impact"`
}

type AttackPath struct {
	Nodes           []PathNode `json:"nodes"`
	Edges           []PathEdge `json:"edges"`
	TotalRiskWeight float64    `json:"total_risk_weight"`
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
	props, _ := rows[0]["props"].(map[string]any)
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
		`MATCH (ext:A2AAgent {objectid: $source})-[d:DELEGATES_TO*1..3]->(int:A2AAgent)
MATCH (int)-[r1:RUNS_ON]->(h:Host)<-[r2:RUNS_ON]-(s:MCPServer)
MATCH (a:AgentInstance)-[r3:TRUSTS_SERVER]->(s)
      -[r4:PROVIDES_TOOL]->(t:MCPTool)-[r5:HAS_ACCESS_TO]->(r:MCPResource {objectid: $target})
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
		`MATCH (a:AgentInstance {objectid: $source})-[r1:TRUSTS_SERVER]->(s:MCPServer)
      -[r2:HAS_ENV_VAR]->(c1:Credential)
MATCH (gw:LiteLLMGateway)-[r3:EXPOSES_CREDENTIAL]->(c1master:Credential)
WHERE c1master.value_hash = c1.value_hash AND c1master.objectid <> c1.objectid
MATCH (gw)-[r4:EXPOSES_CREDENTIAL]->(c2:Credential {objectid: $target})
RETURN [n IN [a, s, c1, c1master, gw, c2] | {id: n.objectid, name: n.name, kinds: labels(n), properties: properties(n)}] AS nodes,
       [rel IN [r1, r2, r3, r4] | {kind: type(rel), source: startNode(rel).objectid, target: endNode(rel).objectid, properties: properties(rel)}] +
       [{kind: 'VALUE_HASH_MATCH', source: c1.objectid, target: c1master.objectid, properties: {merge_value_hash: c1.value_hash, is_synthetic: true}}] AS edges
LIMIT 1`,
	},
	"CAN_EXFILTRATE_VIA": {
		`MATCH (a:AgentInstance {objectid: $source})-[:TRUSTS_SERVER]->(s1:MCPServer)
      -[r1:PROVIDES_TOOL]->(outbound:MCPTool {objectid: $target})
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

	for _, q := range queries {
		path, err := tryPathQuery(ctx, db, q, params)
		if err != nil {
			continue
		}
		if path != nil {
			return path, nil
		}
	}

	path, err := tryPathQuery(ctx, db, genericFallbackQuery, params)
	if err != nil {
		return nil, fmt.Errorf("fallback path query: %w", err)
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
	var totalWeight float64
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

		if pe.Properties != nil {
			totalWeight += floatFromAny(pe.Properties["risk_weight"])
		}
	}

	return &AttackPath{
		Nodes:           nodes,
		Edges:           edges,
		TotalRiskWeight: totalWeight,
	}, nil
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
	edgeKind := f.EdgeKind
	if edgeKind == "CAN_REACH" {
		switch {
		case isCredentialChain(compositeProps):
			edgeKind = "CAN_REACH_CREDENTIAL_CHAIN"
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
