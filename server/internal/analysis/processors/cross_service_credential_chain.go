package processors

import (
	"context"
	"time"

	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

// CrossServiceCredentialChain wires the v0.2 credential-chain demo:
// when the Config Collector emits a Credential C1 (observed material
// referenced by an MCP server, independent of its config location) AND the
// LiteLLM Looter
// emits a Credential C1master (the master key the operator supplied),
// AND C1.value_hash == C1master.value_hash, those two nodes describe
// the same secret. The LiteLLM gateway then exposes upstream provider
// keys (C2) via EXPOSES_CREDENTIAL — and a CAN_REACH edge from the
// agent through that chain to the upstream credential is the finding.
//
// Path:
//
//	(:AgentInstance)-[:TRUSTS_SERVER]->(:MCPServer)
//	    -[:AUTHENTICATES_WITH]->(:Identity)-[:USES_CREDENTIAL]->(:Credential C1)
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
	// Config Collector's canonical authentication topology
	// (MCPServer-[:AUTHENTICATES_WITH]->Identity-[:USES_CREDENTIAL]->c1).
	// c1master comes
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
	// every configured credential (c1) and master credential (c1master)
	// participating in the same value-hash correlation. Folding it here
	// avoids re-MATCHing the join path. The aggregation grain is the shared
	// value_hash, not an individual c1: distinct config nodes may represent
	// the same secret, and their reachable agents must contribute to one
	// global blast radius. Candidate paths are then ordered by their stable
	// seven-node object-ID tuple before one winner per (agent, upstream
	// credential) is selected. Relationship IDs are evidence only and do not
	// influence the winner, so relationship recreation cannot flip topology.
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
      -[authenticates:AUTHENTICATES_WITH]->(i:Identity)-[uses:USES_CREDENTIAL]->(c1:Credential)
WHERE c1.value_hash IS NOT NULL AND c1.value_hash <> ''
  AND c1.merge_key = 'value_hash'
  AND c1.identity_basis = 'value_hash'
  AND c1.material_status = 'observed'
  AND c1.exposure_status = 'exposed'
MATCH (gw:LiteLLMGateway)-[exposes_master:EXPOSES_CREDENTIAL]->(c1master:Credential)
WHERE c1master.value_hash = c1.value_hash
  AND c1master.value_hash IS NOT NULL AND c1master.value_hash <> ''
  AND c1master.objectid <> c1.objectid
  AND c1master.merge_key = 'value_hash'
  AND c1master.identity_basis = 'value_hash'
  AND c1master.material_status = 'observed'
  AND c1master.exposure_status = 'exposed'
MATCH (gw)-[exposes_upstream:EXPOSES_CREDENTIAL]->(c2:Credential)
WHERE c2.type IN ['apiKey', 'virtual_key'] AND c2.objectid <> c1master.objectid
// Aggregate globally by the cross-service identity key. Grouping by c1 here
// would undercount a master credential when two distinct config credentials
// carry the same secret. DISTINCT agents prevent multiple paths for one agent
// from inflating the shared-secret blast radius.
WITH c1.value_hash AS matched_value_hash,
     collect(DISTINCT a) AS reachable_agents,
     collect(DISTINCT c1) AS configured_credentials,
     collect(DISTINCT c1master) AS master_credentials,
     collect(DISTINCT {
       agent: a,
       server: s,
       identity: i,
       configured_credential: c1,
       master_credential: c1master,
       gateway: gw,
       upstream_credential: c2,
       relationship_ids: [
         id(trust), id(authenticates), id(uses), id(exposes_master), id(exposes_upstream)
       ]
     }) AS candidates
FOREACH (credential IN configured_credentials |
  SET credential.blast_radius = size(reachable_agents))
FOREACH (credential IN master_credentials |
  SET credential.blast_radius = size(reachable_agents))
WITH candidates
UNWIND candidates AS candidate
// A single agent/upstream pair may be reachable through several config nodes
// or servers. Select one stable seven-node evidence tuple before MERGE so later
// rows cannot overwrite the edge with traversal-order-dependent evidence.
WITH candidate
ORDER BY candidate.agent.objectid,
         candidate.upstream_credential.objectid,
         candidate.server.objectid,
         candidate.identity.objectid,
         candidate.configured_credential.objectid,
         candidate.master_credential.objectid,
         candidate.gateway.objectid
WITH candidate.agent AS a,
     candidate.upstream_credential AS c2,
     collect(candidate)[0] AS winner
MERGE (a)-[e:CAN_REACH]->(c2)
SET e.scan_id = $scan_id, e.last_seen = datetime(), e.is_composite = true,
    e.source_collector = 'cross_service_credential_chain',
    e.via_server = winner.server.name,
    e.via_credential = winner.configured_credential.name,
    e.via_gateway = winner.gateway.name,
    e.merge_value_hash = winner.configured_credential.value_hash,
    e.upstream_provider = COALESCE(c2.provider, 'unknown'),
    e.hops = 6,
    e.confidence = 0.95,
    e.risk_weight = 0.1,
    e.evidence_version = 1,
    e.evidence_node_ids = [
      a.objectid, winner.server.objectid, winner.identity.objectid,
      winner.configured_credential.objectid, winner.master_credential.objectid,
      winner.gateway.objectid, c2.objectid
    ],
    e.evidence_relationship_ids = winner.relationship_ids,
    e.evidence_synthetic_edge = [
      winner.configured_credential.objectid, winner.master_credential.objectid,
      'VALUE_HASH_MATCH',
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
