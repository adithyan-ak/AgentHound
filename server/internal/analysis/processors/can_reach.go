package processors

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/adithyan-ak/agenthound/sdk/campaign"
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
WITH a, s1, t1, s2, c, i, t2, r,
     trust1, provides1, environment, uses, authenticates, provides2, access
ORDER BY a.objectid, s1.objectid, t1.objectid, s2.objectid,
         c.objectid, i.objectid, t2.objectid, r.objectid
WITH a, r, collect({
  s1: s1, t1: t1, s2: s2, c: c, i: i, t2: t2,
  trust1: trust1, provides1: provides1, environment: environment,
  uses: uses, authenticates: authenticates, provides2: provides2, access: access
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
      winner.c.objectid, winner.i.objectid, winner.t2.objectid, r.objectid
    ],
    e.evidence_relationship_ids = [
      id(winner.trust1), id(winner.provides1), id(winner.environment), id(winner.uses),
      id(winner.authenticates), id(winner.provides2), id(winner.access)
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
	validatedEvidenceIDs, err := validatedCampaignEvidenceRelationshipIDs(ctx, db)
	if err != nil {
		return graph.ProcessingStats{
			ProcessorName: p.Name(),
			Duration:      time.Since(start),
		}, err
	}

	verifiedUpgradeCypher := `
MATCH (a:AgentInstance)-[v:CREDENTIAL_REACH_VERIFIED]->(r:MCPResource)
WHERE coalesce(v.is_composite, false) = false
  AND id(v) IN $validated_evidence_ids
  AND a.objectid = v.agent_id
  AND v.agent_kind = 'AgentInstance'
  AND v.server_kind = 'MCPServer'
  AND v.credential_kind = 'Credential'
  AND v.resource_kind = 'MCPResource'
  AND v.witness_schema_version = 2
  AND v.topology_normalization_version = 1
  AND v.publication_revision > 0
  AND v.predicted_edge_kind = 'CAN_REACH'
  AND v.scenario_id = 'cred-reach'
  AND v.scenario_version = 1
  AND v.oracle_type = 'differential_credential_reach'
  AND v.outcome = 'credential_gated_reach_verified'
  AND v.authed_stage = 'resource_read'
  AND v.authed_resource_addressed = true
  AND v.authed_status = 'allowed'
  AND v.control_status = 'denied'
  AND (
    (v.control_stage = 'initialize' AND v.control_resource_addressed = false)
    OR
    (v.control_stage = 'resource_read' AND v.control_resource_addressed = true)
  )
  AND r.objectid = v.resource_id
  AND r.uri = v.resource_identity_input
MATCH (s:MCPServer)-[:PROVIDES_RESOURCE]->(r)
WHERE s.objectid = v.server_id
MATCH (c:Credential)
WHERE c.objectid = v.credential_id
  AND c.value_hash IS NOT NULL AND c.value_hash = v.credential_value_hash
  AND c.merge_key = v.credential_merge_key
MATCH (a)-[e:CAN_REACH]->(r)
WHERE e.is_composite = true
  AND e.scan_id = $scan_id
  AND e.evidence_node_ids = v.evidence_node_ids
  AND size(v.evidence_node_ids) = size(v.evidence_node_kinds)
MATCH (evidence_node)
WHERE evidence_node.objectid IN v.evidence_node_ids
WITH a, v, r, e, collect(DISTINCT evidence_node) AS evidence_nodes
WHERE size(evidence_nodes) = size(v.evidence_node_ids)
  AND ALL(evidence_index IN range(0, size(v.evidence_node_ids) - 1) WHERE
    ANY(candidate IN evidence_nodes WHERE
      candidate.objectid = v.evidence_node_ids[evidence_index]
      AND v.evidence_node_kinds[evidence_index] IN labels(candidate)
    )
  )
SET e.reach_evidence_state = 'verified',
    e.verified_outcome = v.outcome,
    e.verified_scenario_id = v.scenario_id,
    e.verified_scenario_version = v.scenario_version,
    e.verified_run_id = v.run_id,
    e.verified_at = v.verified_at,
    e.verified_oracle_type = v.oracle_type,
    e.verified_control_stage = v.control_stage,
    e.verified_control_status = v.control_status,
    e.verified_control_resource_addressed = v.control_resource_addressed,
    e.verified_authed_stage = v.authed_stage,
    e.verified_authed_status = v.authed_status,
    e.verified_authed_resource_addressed = v.authed_resource_addressed,
    e.verified_cleanup_status = 'not_applicable',
    e.confidence = 1.0
RETURN count(e) AS upgraded`

	params := map[string]any{
		"scan_id":                scanID,
		"validated_evidence_ids": validatedEvidenceIDs,
	}
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

const campaignEvidenceValidationQuery = `
MATCH (a:AgentInstance)-[v:CREDENTIAL_REACH_VERIFIED]->(r:MCPResource)
WHERE coalesce(v.is_composite, false) = false
RETURN id(v) AS relationship_id,
       a.objectid AS source_agent_id,
       r.objectid AS target_resource_id,
       properties(v) AS properties`

func validatedCampaignEvidenceRelationshipIDs(
	ctx context.Context,
	db graph.GraphDB,
) ([]int64, error) {
	rows, err := db.Query(ctx, campaignEvidenceValidationQuery, nil)
	if err != nil {
		return nil, fmt.Errorf("query campaign verification evidence: %w", err)
	}
	validated := make([]int64, 0, len(rows))
	for _, row := range rows {
		properties, ok := row["properties"].(map[string]any)
		if !ok {
			continue
		}
		evidence, fingerprint, err := campaignEvidenceFromProperties(properties)
		if err != nil ||
			evidence.Witness.Fingerprint() != fingerprint ||
			stringProperty(row, "source_agent_id") != evidence.Witness.AgentID ||
			stringProperty(row, "target_resource_id") != evidence.Witness.ResourceID {
			continue
		}
		relationshipID, ok := int64Property(row, "relationship_id")
		if !ok {
			continue
		}
		validated = append(validated, relationshipID)
	}
	return validated, nil
}

func campaignEvidenceFromProperties(properties map[string]any) (campaign.Evidence, string, error) {
	witness := campaign.Witness{
		SchemaVersion:                intProperty(properties, campaign.PropWitnessSchema),
		TopologyNormalizationVersion: intProperty(properties, campaign.PropTopologyVersion),
		PublicationRevision:          intProperty(properties, campaign.PropPublicationRevision),
		PredictedEdgeKind:            stringProperty(properties, campaign.PropPredictedEdgeKind),
		AgentID:                      stringProperty(properties, campaign.PropAgentID),
		AgentKind:                    stringProperty(properties, campaign.PropAgentKind),
		CredentialID:                 stringProperty(properties, campaign.PropCredentialID),
		CredentialKind:               stringProperty(properties, campaign.PropCredentialKind),
		CredentialValueHash:          stringProperty(properties, campaign.PropCredentialValueHash),
		CredentialMergeKey:           stringProperty(properties, campaign.PropCredentialMergeKey),
		ServerID:                     stringProperty(properties, campaign.PropServerID),
		ServerKind:                   stringProperty(properties, campaign.PropServerKind),
		ResourceID:                   stringProperty(properties, campaign.PropResourceID),
		ResourceKind:                 stringProperty(properties, campaign.PropResourceKind),
		ResourceIdentityInput:        stringProperty(properties, campaign.PropResourceIdentity),
		EvidenceNodeIDs:              stringSliceProperty(properties, campaign.PropEvidenceNodeIDs),
		EvidenceNodeKinds:            stringSliceProperty(properties, campaign.PropEvidenceNodeKinds),
	}
	evidence := campaign.Evidence{
		ScenarioID:       stringProperty(properties, campaign.PropScenarioID),
		ScenarioVersion:  intProperty(properties, campaign.PropScenarioVersion),
		RunID:            stringProperty(properties, campaign.PropRunID),
		EngagementID:     stringProperty(properties, campaign.PropEngagementID),
		OracleType:       stringProperty(properties, campaign.PropOracleType),
		Outcome:          campaign.Outcome(stringProperty(properties, campaign.PropOutcome)),
		ControlStage:     campaign.ProbeStage(stringProperty(properties, campaign.PropControlStage)),
		ControlStatus:    campaign.ProbeStatus(stringProperty(properties, campaign.PropControlStatus)),
		ControlAddressed: boolProperty(properties, campaign.PropControlAddressed),
		AuthedStage:      campaign.ProbeStage(stringProperty(properties, campaign.PropAuthedStage)),
		AuthedStatus:     campaign.ProbeStatus(stringProperty(properties, campaign.PropAuthedStatus)),
		AuthedAddressed:  boolProperty(properties, campaign.PropAuthedAddressed),
		VerifiedAt:       stringProperty(properties, campaign.PropVerifiedAt),
		Witness:          witness,
	}
	if err := witness.Validate(); err != nil {
		return campaign.Evidence{}, "", err
	}
	if evidence.ScenarioID != "cred-reach" ||
		evidence.ScenarioVersion != 1 ||
		evidence.OracleType != campaign.OracleTypeDifferentialCredentialReach ||
		evidence.Outcome != campaign.OutcomeCredentialGatedReachVerified ||
		strings.TrimSpace(evidence.RunID) == "" ||
		strings.TrimSpace(evidence.EngagementID) == "" {
		return campaign.Evidence{}, "", fmt.Errorf("campaign evidence contract mismatch")
	}
	if _, err := time.Parse(time.RFC3339, evidence.VerifiedAt); err != nil {
		return campaign.Evidence{}, "", fmt.Errorf("campaign verified_at is invalid")
	}
	control := campaign.ProbeResult{
		Stage: evidence.ControlStage, ResourceAddressed: evidence.ControlAddressed,
		Status: evidence.ControlStatus,
	}
	authed := campaign.ProbeResult{
		Stage: evidence.AuthedStage, ResourceAddressed: evidence.AuthedAddressed,
		Status: evidence.AuthedStatus,
	}
	if campaign.Classify(control, authed) != evidence.Outcome {
		return campaign.Evidence{}, "", fmt.Errorf("campaign staged observation contract mismatch")
	}
	fingerprint := stringProperty(properties, campaign.PropWitnessFingerprint)
	if fingerprint == "" {
		return campaign.Evidence{}, "", fmt.Errorf("campaign witness fingerprint is missing")
	}
	return evidence, fingerprint, nil
}

func stringProperty(properties map[string]any, key string) string {
	value, _ := properties[key].(string)
	return value
}

func intProperty(properties map[string]any, key string) int {
	switch value := properties[key].(type) {
	case int:
		return value
	case int32:
		return int(value)
	case int64:
		return int(value)
	case float64:
		return int(value)
	default:
		return 0
	}
}

func int64Property(properties map[string]any, key string) (int64, bool) {
	switch value := properties[key].(type) {
	case int:
		return int64(value), true
	case int32:
		return int64(value), true
	case int64:
		return value, true
	case float64:
		return int64(value), true
	default:
		return 0, false
	}
}

func boolProperty(properties map[string]any, key string) bool {
	value, _ := properties[key].(bool)
	return value
}

func stringSliceProperty(properties map[string]any, key string) []string {
	switch values := properties[key].(type) {
	case []string:
		return append([]string(nil), values...)
	case []any:
		result := make([]string, 0, len(values))
		for _, value := range values {
			text, ok := value.(string)
			if !ok {
				return nil
			}
			result = append(result, text)
		}
		return result
	default:
		return nil
	}
}
