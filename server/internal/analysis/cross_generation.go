package analysis

import (
	"context"

	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

// CrossGenerationCredentialChain wires the cross-service credential chain
// ACROSS generations, which is what a real deployment needs: the Config
// Collector and a Looter (e.g. LiteLLM) ship as SEPARATE artifacts, so their
// facts live in different generations. The in-ingest, single-scan processor
// can only ever see one artifact's scan_id, so the chain never fired across
// them. This step restores the analysis by selecting an EXPLICIT set of current
// collector generations and joining by value_hash across all of them.
//
// The join is identical in shape to the single-scan processor
// (server/internal/analysis/processors/cross_service_credential_chain.go): a
// Config-Collector Credential C1 referenced by an MCP server matches a LiteLLM
// master key C1master by value_hash, and the gateway also exposes an upstream
// provider Credential C2. The difference is scoping: instead of
// `x.scan_id = $scan_id`, every node must be observed by one of the selected
// generations (generations-set membership), so C1 (config generation) and
// C1master/C2 (loot generation) both qualify.
//
// Emitted edges are attributed to ownerGenerationID (the generation currently
// being ingested/promoted) so they belong to that generation's finding snapshot
// and are removed when it is deleted. synthetic-identity credentials
// (merge_key='identity') are excluded from the value_hash join, exactly as the
// single-scan processor does.
func CrossGenerationCredentialChain(ctx context.Context, db graph.GraphDB, gens []string, ownerGenerationID, ownerScanID string) (int, error) {
	if len(gens) == 0 || ownerGenerationID == "" {
		return 0, nil
	}
	cypher := `
MATCH (a:AgentInstance)-[:TRUSTS_SERVER]->(s:MCPServer)
      -[:HAS_ENV_VAR]->(c1:Credential)
WHERE ANY(g IN coalesce(a.generations, []) WHERE g IN $gens)
  AND ANY(g IN coalesce(s.generations, []) WHERE g IN $gens)
  AND ANY(g IN coalesce(c1.generations, []) WHERE g IN $gens)
  AND c1.value_hash IS NOT NULL AND c1.value_hash <> ''
  AND (c1.merge_key IS NULL OR c1.merge_key = 'value_hash')
MATCH (gw:LiteLLMGateway)-[:EXPOSES_CREDENTIAL]->(c1master:Credential)
WHERE ANY(g IN coalesce(gw.generations, []) WHERE g IN $gens)
  AND ANY(g IN coalesce(c1master.generations, []) WHERE g IN $gens)
  AND c1master.value_hash = c1.value_hash
  AND c1master.objectid <> c1.objectid
  AND (c1master.merge_key IS NULL OR c1master.merge_key = 'value_hash')
MATCH (gw)-[:EXPOSES_CREDENTIAL]->(c2:Credential)
WHERE ANY(g IN coalesce(c2.generations, []) WHERE g IN $gens)
  AND c2.type IN ['apiKey', 'virtual_key'] AND c2.objectid <> c1master.objectid
  // The owner generation MUST contribute at least one matched observation to
  // this path. Otherwise the owner would be credited with (and its finding
  // snapshot would carry) a chain it did not actually produce — the join could
  // be satisfied entirely by OTHER selected generations. Requiring $gen to be
  // among some matched node's generations ties the emitted, owner-scoped edge
  // to a real owner-observed fact.
  AND (
    $gen IN coalesce(a.generations, []) OR
    $gen IN coalesce(s.generations, []) OR
    $gen IN coalesce(c1.generations, []) OR
    $gen IN coalesce(c1master.generations, []) OR
    $gen IN coalesce(c2.generations, []) OR
    $gen IN coalesce(gw.generations, [])
  )
// blast_radius (count of distinct agents that reach the merged secret) is
// derived onto the OWNER-scoped composite edge below, NOT written back onto the
// raw Credential observations (c1/c1master): those belong to the config/loot
// generations and are immutable prior observations, so mutating them would
// rewrite another generation's facts. The derivation lives on this generation's
// own immutable composite evidence.
WITH s, c1, c1master, c2, gw, collect(DISTINCT a) AS agents
WITH s, c1, c1master, c2, gw, agents, size(agents) AS reachable_agents
UNWIND agents AS a
MERGE (a)-[e:CAN_REACH_CREDENTIAL_CHAIN]->(c2)
SET e.scan_id = $scan_id, e.last_seen = datetime(), e.is_composite = true,
    e.source_collector = 'cross_service_credential_chain',
    e.join_type = 'synthetic',
    e.generation_id = $gen,
    e.generations = CASE WHEN $gen IN coalesce(e.generations, []) THEN e.generations ELSE coalesce(e.generations, []) + $gen END,
    e.blast_radius = reachable_agents,
    e.via_server = s.name,
    e.via_credential = c1.name,
    e.via_gateway = gw.name,
    e.merge_value_hash = c1.value_hash,
    e.upstream_provider = COALESCE(c2.provider, 'unknown'),
    e.hops = 5,
    e.confidence = 0.95,
    e.risk_weight = 0.1,
    // Full evidence metadata + per-endpoint generation ids so the persisted
    // finding's DAG/detail/impact can be reconstructed WITHOUT re-traversing a
    // single generation. A cross-artifact chain spans generations (the agent is
    // in the config generation, the upstream key in the loot generation), so a
    // single-generation re-traversal would find nothing; these properties make
    // the persisted evidence self-contained and complete.
    e.source_generation = a.generation_id,
    e.target_generation = c2.generation_id,
    e.via_server_id = s.objectid,
    e.via_server_generation = s.generation_id,
    e.via_credential_id = c1.objectid,
    e.via_credential_generation = c1.generation_id,
    e.master_credential_id = c1master.objectid,
    e.master_credential_name = c1master.name,
    e.master_credential_generation = c1master.generation_id,
    e.via_gateway_id = gw.objectid,
    e.via_gateway_generation = gw.generation_id
RETURN count(e) AS written`

	return db.ExecuteWrite(ctx, cypher, map[string]any{
		"gens":    gens,
		"gen":     ownerGenerationID,
		"scan_id": ownerScanID,
	})
}
