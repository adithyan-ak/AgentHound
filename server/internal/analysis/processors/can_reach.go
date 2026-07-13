package processors

import (
	"context"
	"time"

	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

type CanReach struct{}

func (p *CanReach) Name() string           { return "can_reach" }
func (p *CanReach) Dependencies() []string { return []string{"has_access_to"} }

func (p *CanReach) Process(ctx context.Context, db graph.GraphDB, scanID string) (graph.ProcessingStats, error) {
	start := time.Now()

	directCypher := `
MATCH (a:AgentInstance)-[ts:TRUSTS_SERVER]->(s:MCPServer)
      -[provides:PROVIDES_TOOL]->(t:MCPTool)-[access:HAS_ACCESS_TO]->(r:MCPResource)
MERGE (a)-[e:CAN_REACH]->(r)
SET e.scan_id = $scan_id, e.last_seen = datetime(), e.is_composite = true, e.source_collector = 'mcp',
    e.via_server = s.name, e.via_tool = t.name, e.hops = 3, e.risk_weight = 0.1,
    e.confidence = CASE WHEN ts.risk_weight <= 0.1 THEN 1.0
                        WHEN ts.risk_weight <= 0.3 THEN 0.8
                        ELSE 0.5 END,
    e.evidence_version = 1,
    e.evidence_node_ids = [a.objectid, s.objectid, t.objectid, r.objectid],
    e.evidence_relationship_ids = [id(ts), id(provides), id(access)]
RETURN count(*) AS written`

	credChainCypher := `
MATCH (a:AgentInstance)-[trust1:TRUSTS_SERVER]->(s1:MCPServer)-[provides1:PROVIDES_TOOL]->(t1:MCPTool)
WHERE ANY(cap IN t1.capability_surface WHERE cap IN ['file_read', 'credential_access'])
MATCH (s2:MCPServer)-[environment:HAS_ENV_VAR]->(c:Credential)
MATCH (c)<-[uses:USES_CREDENTIAL]-(i:Identity)<-[authenticates:AUTHENTICATES_WITH]-(s2)
MATCH (s2)-[provides2:PROVIDES_TOOL]->(t2:MCPTool)-[access:HAS_ACCESS_TO]->(r:MCPResource)
WHERE s1 <> s2
  AND s1.auth_assurance IN ['unauthenticated', 'weak']
  AND NOT EXISTS {
    MATCH (a)-[current:CAN_REACH]->(r)
    WHERE current.scan_id = $scan_id
  }
MERGE (a)-[e:CAN_REACH]->(r)
SET e.scan_id = $scan_id, e.last_seen = datetime(), e.is_composite = true, e.source_collector = 'mcp',
    e.via_credential = c.name, e.hops = 6, e.confidence = 0.6, e.risk_weight = 0.1,
    e.evidence_version = 1,
    e.evidence_node_ids = [
      a.objectid, s1.objectid, t1.objectid, s2.objectid,
      c.objectid, i.objectid, t2.objectid, r.objectid
    ],
    e.evidence_relationship_ids = [
      id(trust1), id(provides1), id(environment), id(uses),
      id(authenticates), id(provides2), id(access)
    ]
RETURN count(*) AS written`

	// verifiedUpgradeCypher re-correlates a persisted raw CREDENTIAL_REACH_VERIFIED
	// edge (emitted by the campaign runner's cred-reach scenario) against the
	// freshly rebuilt CAN_REACH edges and, on a full match, upgrades the CAN_REACH
	// edge's evidence-state/confidence in place. It creates NO new edge and no new
	// finding — the existing CAN_REACH finding is upgraded, so risk is not
	// double-counted.
	//
	// Re-correlation rejects forged/mismatched/stale witnesses: the LIVE credential
	// identity (objectid + value_hash + merge_key) must equal the witness echo on
	// the raw edge, the resource must still be served by the witness server, and a
	// current-epoch CAN_REACH edge to that resource must route through that exact
	// credential. A forged credential_id resolves to a reference_only node with no
	// value_hash, so the value_hash equality fails and nothing is upgraded.
	verifiedUpgradeCypher := `
MATCH (c:Credential)-[v:CREDENTIAL_REACH_VERIFIED]->(r:MCPResource)
WHERE coalesce(v.is_composite, false) = false
  AND v.outcome = 'credential_gated_reach_verified'
  AND c.objectid = v.credential_id
  AND c.value_hash IS NOT NULL AND c.value_hash = v.credential_value_hash
  AND c.merge_key = v.credential_merge_key
  AND r.objectid = v.resource_id
  AND EXISTS {
    MATCH (s:MCPServer)-[:PROVIDES_RESOURCE]->(r)
    WHERE s.objectid = v.server_id
  }
MATCH (a)-[e:CAN_REACH]->(r)
WHERE e.is_composite = true
  AND e.scan_id = $scan_id
  AND c.objectid IN e.evidence_node_ids
SET e.reach_evidence_state = 'verified',
    e.verified_outcome = v.outcome,
    e.verified_scenario_id = v.scenario_id,
    e.verified_scenario_version = v.scenario_version,
    e.verified_run_id = v.run_id,
    e.verified_at = v.verified_at,
    e.confidence = 1.0
RETURN count(e) AS upgraded`

	params := map[string]any{"scan_id": scanID}
	var total int

	// The upgrade runs LAST so it re-correlates against the CAN_REACH edges the
	// prior two queries just built this epoch.
	for _, cypher := range []string{directCypher, credChainCypher, verifiedUpgradeCypher} {
		n, err := db.ExecuteWrite(ctx, cypher, params)
		if err != nil {
			return graph.ProcessingStats{
				ProcessorName: p.Name(),
				Duration:      time.Since(start),
			}, err
		}
		total += n
	}

	return graph.ProcessingStats{
		ProcessorName: p.Name(),
		EdgesCreated:  total,
		Duration:      time.Since(start),
	}, nil
}
