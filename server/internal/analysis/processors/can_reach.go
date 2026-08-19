package processors

import (
	"context"
	"fmt"
	"time"

	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

type CanReach struct{}

func (p *CanReach) Name() string           { return "can_reach" }
func (p *CanReach) Dependencies() []string { return []string{"auth_strength", "has_access_to"} }

func (p *CanReach) Process(ctx context.Context, db graph.GraphDB, scanID string) (graph.ProcessingStats, error) {
	start := time.Now()

	directCypher := `
MATCH (a:AgentInstance)-[ts:TRUSTS_SERVER]->(s:MCPServer)
      -[provides:PROVIDES_TOOL]->(t:MCPTool)-[access:HAS_ACCESS_TO]->(r:MCPResource)
MERGE (a)-[e:CAN_REACH]->(r)
SET e.scan_id = $scan_id, e.last_seen = datetime(), e.is_composite = true, e.source_collector = 'mcp',
    e.via_server = s.name, e.via_tool = t.name, e.hops = 3, e.risk_weight = 0.1,
    e.confidence = CASE WHEN ts.effective_risk_weight <= 0.1 THEN 1.0
                        WHEN ts.effective_risk_weight <= 0.3 THEN 0.8
                        ELSE 0.5 END,
	    e.evidence_version = 1,
	    e.evidence_node_ids = [a.objectid, s.objectid, t.objectid, r.objectid],
	    e.evidence_relationship_ids = [id(ts), id(provides), id(access)],
	    e.reach_evidence_state = 'inferred'
REMOVE e.proof_action, e.proof_action_id, e.proof_verified_at, e.proof_type,
       e.proof_outcome, e.proof_control_stage, e.proof_control_status,
       e.proof_control_resource_addressed, e.proof_credential_stage,
       e.proof_credential_status, e.proof_credential_resource_addressed,
       e.proof_cleanup_status, e.verified_outcome, e.verified_scenario_id,
       e.verified_scenario_version, e.verified_run_id, e.verified_at,
       e.verified_oracle_type, e.verified_control_stage, e.verified_control_status,
       e.verified_control_resource_addressed, e.verified_authed_stage,
       e.verified_authed_status, e.verified_authed_resource_addressed,
       e.verified_cleanup_status
RETURN count(*) AS written`

	credChainCypher := fmt.Sprintf(`
MATCH (a:AgentInstance)-[trust1:TRUSTS_SERVER]->(s1:MCPServer)-[provides1:PROVIDES_TOOL]->(t1:MCPTool)
WHERE ANY(cap IN t1.capability_surface WHERE cap IN ['file_read', 'credential_access'])
MATCH (s2:MCPServer)-[authenticates:AUTHENTICATES_WITH]->(i:Identity)-[uses:USES_CREDENTIAL]->(c:Credential)
MATCH (s2)-[provides2:PROVIDES_TOOL]->(t2:MCPTool)-[access:HAS_ACCESS_TO]->(r:MCPResource)
WHERE s1 <> s2
  AND %s
  AND (
    (s1.effective_auth_assurance = 'unauthenticated'
      AND s1.effective_auth_source = 'observed')
    OR s1.effective_auth_assurance = 'weak'
  )
  AND c.value_hash IS NOT NULL AND c.value_hash <> ''
  AND c.merge_key = 'value_hash'
  AND c.identity_basis = 'value_hash'
  AND c.material_status = 'observed'
  AND c.exposure_status = 'exposed'
WITH a, s1, t1, s2, i, c, t2, r,
     trust1, provides1, authenticates, uses, provides2, access
ORDER BY a.objectid, s1.objectid, t1.objectid, s2.objectid,
         i.objectid, c.objectid, t2.objectid, r.objectid
WITH a, r, collect({
  s1: s1, t1: t1, s2: s2, i: i, c: c, t2: t2,
  trust1: trust1, provides1: provides1, authenticates: authenticates,
  uses: uses, provides2: provides2, access: access
})[0] AS winner
WHERE NOT EXISTS {
    MATCH (a)-[current:CAN_REACH]->(r)
    WHERE current.scan_id = $scan_id
  }
MERGE (a)-[e:CAN_REACH]->(r)
SET e.scan_id = $scan_id, e.last_seen = datetime(), e.is_composite = true, e.source_collector = 'mcp',
    e.via_credential = winner.c.name, e.hops = 6, e.confidence = 0.6, e.risk_weight = 0.1,
    e.evidence_version = 1,
    e.evidence_node_ids = [
      a.objectid, winner.s1.objectid, winner.t1.objectid, winner.s2.objectid,
      winner.i.objectid, winner.c.objectid, winner.t2.objectid, r.objectid
    ],
	    e.evidence_relationship_ids = [
	      id(winner.trust1), id(winner.provides1), id(winner.authenticates),
	      id(winner.uses), id(winner.provides2), id(winner.access)
	    ],
	    e.reach_evidence_state = 'inferred'
REMOVE e.proof_action, e.proof_action_id, e.proof_verified_at, e.proof_type,
       e.proof_outcome, e.proof_control_stage, e.proof_control_status,
       e.proof_control_resource_addressed, e.proof_credential_stage,
       e.proof_credential_status, e.proof_credential_resource_addressed,
       e.proof_cleanup_status, e.verified_outcome, e.verified_scenario_id,
       e.verified_scenario_version, e.verified_run_id, e.verified_at,
       e.verified_oracle_type, e.verified_control_stage, e.verified_control_status,
       e.verified_control_resource_addressed, e.verified_authed_stage,
       e.verified_authed_status, e.verified_authed_resource_addressed,
       e.verified_cleanup_status
RETURN count(*) AS written`, compatibleScopePredicate("s1", "s2"))

	// A proof edge is part of the same scan as the freshly rebuilt prediction.
	// Correlating through its Credential endpoint removes campaign witnesses and
	// arbitrary ID-valued echoes: the credential must already be one of the exact
	// evidence nodes selected for this CAN_REACH path.
	proofUpgradeCypher := `
MATCH (c:Credential)-[v:CREDENTIAL_ACCESS_OBSERVED]->(r:MCPResource)
WHERE coalesce(v.is_composite, false) = false
  AND v.scan_id = $scan_id
MATCH (a:AgentInstance)-[e:CAN_REACH]->(r)
WHERE e.is_composite = true
  AND e.scan_id = $scan_id
  AND c.objectid IN coalesce(e.evidence_node_ids, [])
SET e.reach_evidence_state = 'verified',
    e.proof_action = v.action,
    e.proof_action_id = v.action_id,
    e.proof_verified_at = v.verified_at,
    e.proof_type = v.proof_type,
    e.proof_outcome = v.outcome,
    e.proof_control_stage = v.control_stage,
    e.proof_control_status = v.control_status,
    e.proof_control_resource_addressed = v.control_resource_addressed,
    e.proof_credential_stage = v.credential_stage,
    e.proof_credential_status = v.credential_status,
    e.proof_credential_resource_addressed = v.credential_resource_addressed,
    e.proof_cleanup_status = v.cleanup_status,
    e.confidence = 1.0
RETURN count(e) AS upgraded`

	params := map[string]any{"scan_id": scanID}
	var total int

	// The upgrade runs LAST so it re-correlates against the CAN_REACH edges the
	// prior two queries just built this epoch.
	for _, cypher := range []string{directCypher, credChainCypher, proofUpgradeCypher} {
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
