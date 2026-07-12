package processors

import (
	"context"
	"time"

	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

// CrossServiceCredentialChain wires the v0.2 credential-chain demo:
// when the Config Collector emits a Credential C1 (an env var or
// hardcoded value referenced by an MCP server) AND the LiteLLM Looter
// emits a Credential C1master (the master key the operator supplied),
// AND C1.value_hash == C1master.value_hash, those two nodes describe
// the same secret. The LiteLLM gateway then exposes upstream provider
// keys (C2) via EXPOSES_CREDENTIAL — and a CAN_REACH edge from the
// agent through that chain to the upstream credential is the finding.
//
// Path:
//
//	(:AgentInstance)-[:TRUSTS_SERVER]->(:MCPServer)
//	    -[:HAS_ENV_VAR]->(:Credential C1)
//	    where C1.value_hash matches a Credential C1master from a LiteLLM Looter run
//	(:LiteLLMGateway:AIService gw)-[:EXPOSES_CREDENTIAL]->(:Credential C1master)
//	(gw)-[:EXPOSES_CREDENTIAL]->(:Credential C2)
//	    where C2.type IN ["apiKey", "virtual_key"]
//
// We emit (:AgentInstance)-[:CAN_REACH]->(C2) with metadata that
// records the merge endpoint (hash + LiteLLM gateway name).
//
// Dependencies: ["has_access_to", "can_reach"] — has_access_to so the
// graph has resource accessibility wired, can_reach so this processor
// runs AFTER the existing transitive can_reach work and we don't
// double-emit edges that the Phase 4 chain already covers.
type CrossServiceCredentialChain struct{}

func (p *CrossServiceCredentialChain) Name() string { return "cross_service_credential_chain" }

func (p *CrossServiceCredentialChain) Dependencies() []string {
	return []string{"has_access_to", "can_reach"}
}

func (p *CrossServiceCredentialChain) Process(ctx context.Context, db graph.GraphDB, scanID string) (graph.ProcessingStats, error) {
	start := time.Now()

	// The join: c1.value_hash = c1master.value_hash. c1 comes from the
	// Config Collector (MCPServer-[:HAS_ENV_VAR]->c1). c1master comes
	// from the LiteLLM Looter ((gw:LiteLLMGateway)-[:EXPOSES_CREDENTIAL]->c1master).
	// gw also -[:EXPOSES_CREDENTIAL]->c2, the upstream provider Credential.
	//
	// We require c1 != c1master (otherwise this would only fire on
	// hand-loaded test fixtures where both nodes happen to share an
	// objectid; in real graphs they always have different objectids
	// because the Config Collector and Looter compute IDs differently).
	// Single query (one ExecuteWrite): the same agent→server→credential
	// join also yields the credential blast radius (count of distinct
	// agents that can reach the merged secret), which we materialize on
	// both the env-var credential (c1) and its value_hash-merged master
	// (c1master). Folding it here avoids re-MATCHing the join path. The
	// join is first reduced to the agent grain so blast radius counts
	// DISTINCT agents rather than (agent, path) tuples — an agent with
	// multiple reachable paths must not inflate the count. Each distinct
	// agent's witness relationship IDs are preserved, then re-UNWOUND so the
	// CAN_REACH MERGE stays one edge per (agent, upstream-credential) and each
	// edge retains the exact relationship IDs for that agent's path.
	// merge_key filter (U-MED-4): when a Looter cannot observe the raw
	// credential value (e.g. LiteLLM masks upstream provider api_key
	// server-side, so /model/info gives us no key material), it emits a
	// Credential with a SYNTHETIC value_hash = SHA-256("provider:name")
	// and marks the node merge_key='identity'. Those hashes cannot
	// legitimately participate in the cross-collector value_hash join —
	// there is no raw sk-... that hashes to sha256("openai:gpt-4"), so
	// they can't false-positive today, but the explicit filter makes
	// intent unambiguous and rules out a hypothetical collision-crafted
	// synthetic ever matching a real credential. Only canonical
	// merge_key='value_hash' credentials are eligible.
	cypher := `
MATCH (a:AgentInstance)-[trust:TRUSTS_SERVER]->(s:MCPServer)
      -[environment:HAS_ENV_VAR]->(c1:Credential)
WHERE c1.value_hash IS NOT NULL AND c1.value_hash <> ''
  AND c1.merge_key = 'value_hash'
  AND c1.material_status = 'observed'
  AND c1.exposure_status = 'exposed'
MATCH (gw:LiteLLMGateway)-[exposes_master:EXPOSES_CREDENTIAL]->(c1master:Credential)
WHERE c1master.value_hash = c1.value_hash
  AND c1master.objectid <> c1.objectid
  AND c1master.merge_key = 'value_hash'
  AND c1master.material_status = 'observed'
  AND c1master.exposure_status = 'exposed'
MATCH (gw)-[exposes_upstream:EXPOSES_CREDENTIAL]->(c2:Credential)
WHERE c2.type IN ['apiKey', 'virtual_key'] AND c2.objectid <> c1master.objectid
// Collapse each agent's (possibly multiple) traversal paths to the agent
// grain first. An agent that reaches the merged secret via more than one
// path (e.g. two TRUSTS_SERVER or HAS_ENV_VAR edges) would otherwise yield
// several distinct witness tuples and inflate the blast radius. Grouping by
// the agent node here makes one row per distinct agent while collect() keeps
// that agent's witness relationship-ID tuples for the CAN_REACH evidence.
WITH s, c1, c1master, c2, gw, a,
     collect([
       id(trust), id(environment), id(exposes_master), id(exposes_upstream)
     ]) AS agent_paths
WITH s, c1, c1master, c2, gw, collect({
  agent: a,
  relationship_ids: agent_paths[0]
}) AS agent_witnesses
WITH s, c1, c1master, c2, gw, agent_witnesses,
     size(agent_witnesses) AS reachable_agents
SET c1.blast_radius = reachable_agents, c1master.blast_radius = reachable_agents
WITH s, c1, c1master, c2, gw, agent_witnesses
UNWIND agent_witnesses AS witness
WITH s, c1, c1master, c2, gw,
     witness.agent AS a,
     witness.relationship_ids AS witness_relationship_ids
MERGE (a)-[e:CAN_REACH]->(c2)
SET e.scan_id = $scan_id, e.last_seen = datetime(), e.is_composite = true,
    e.source_collector = 'cross_service_credential_chain',
    e.via_server = s.name,
    e.via_credential = c1.name,
    e.via_gateway = gw.name,
    e.merge_value_hash = c1.value_hash,
    e.upstream_provider = COALESCE(c2.provider, 'unknown'),
    e.hops = 5,
    e.confidence = 0.95,
    e.risk_weight = 0.1,
    e.evidence_version = 1,
    e.evidence_node_ids = [
      a.objectid, s.objectid, c1.objectid, c1master.objectid,
      gw.objectid, c2.objectid
    ],
    e.evidence_relationship_ids = witness_relationship_ids,
    e.evidence_synthetic_edge = [
      c1.objectid, c1master.objectid, 'VALUE_HASH_MATCH',
      'identity_correlation', 'value_hash', 'cross_service_credential_chain'
    ]
RETURN count(e) AS written`

	written, err := db.ExecuteWrite(ctx, cypher, map[string]any{"scan_id": scanID})
	if err != nil {
		return graph.ProcessingStats{
			ProcessorName: p.Name(),
			Duration:      time.Since(start),
		}, err
	}
	return graph.ProcessingStats{
		ProcessorName: p.Name(),
		EdgesCreated:  written,
		Duration:      time.Since(start),
	}, nil
}
