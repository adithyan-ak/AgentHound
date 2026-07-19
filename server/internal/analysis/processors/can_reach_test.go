package processors

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/adithyan-ak/agenthound/sdk/campaign"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

func TestCanReach_Name(t *testing.T) {
	p := &CanReach{}
	if p.Name() != "can_reach" {
		t.Errorf("Name() = %q, want can_reach", p.Name())
	}
}

func TestCanReach_Dependencies(t *testing.T) {
	p := &CanReach{}
	deps := p.Dependencies()
	if len(deps) != 1 || deps[0] != "has_access_to" {
		t.Errorf("Dependencies() = %v, want [has_access_to]", deps)
	}
}

func TestCanReach_ProcessSuccess(t *testing.T) {
	mock := &graph.MockGraphDB{ExecuteWriteResult: 4}

	p := &CanReach{}
	stats, err := p.Process(context.Background(), mock, "scan-1")
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if stats.ProcessorName != "can_reach" {
		t.Errorf("ProcessorName = %q", stats.ProcessorName)
	}
	// 3 queries x 4 each = 12
	if stats.EdgesCreated != 12 {
		t.Errorf("EdgesCreated = %d, want 12", stats.EdgesCreated)
	}

	calls := mock.CallsTo("ExecuteWrite")
	if len(calls) != 3 {
		t.Errorf("ExecuteWrite called %d times, want 3 (direct + credential chain + verified upgrade)", len(calls))
	}
	direct, _ := calls[0].Args[0].(string)
	if strings.Contains(direct, "WHERE NOT EXISTS((a)-[:CAN_REACH]->(r))") {
		t.Fatalf("direct CAN_REACH must refresh an existing inferred edge:\n%s", direct)
	}
	credential, _ := calls[1].Args[0].(string)
	if !strings.Contains(credential, "current.scan_id = $scan_id") {
		t.Fatalf("credential pass must preserve a direct path refreshed this scan:\n%s", credential)
	}
	if !strings.Contains(credential, "NOT EXISTS {") ||
		!strings.Contains(credential, "MATCH (a)-[current:CAN_REACH]->(r)") {
		t.Fatalf("credential pass must use Neo4j-4.4-compatible EXISTS subquery:\n%s", credential)
	}
	if strings.Contains(credential, "s1.auth_method IS NULL OR") ||
		!strings.Contains(credential, "coalesce(s1.observed_auth_assurance, s1.auth_assurance) IN ['unauthenticated', 'weak']") {
		t.Fatalf("unknown auth must not satisfy credential delegation:\n%s", credential)
	}
	if !strings.Contains(
		credential,
		"ORDER BY a.objectid, s1.objectid, t1.objectid, s2.objectid,\n"+
			"         c.objectid, i.objectid, t2.objectid, r.objectid",
	) || !strings.Contains(credential, "})[0] AS winner") {
		t.Fatalf("credential paths must reduce by the complete stable object-ID tuple:\n%s", credential)
	}
	orderStart := strings.Index(credential, "ORDER BY")
	winnerStart := strings.Index(credential, "})[0] AS winner")
	if orderStart < 0 || winnerStart < orderStart ||
		strings.Contains(credential[orderStart:winnerStart], "id(") {
		t.Fatalf("relationship IDs must not participate in credential-path selection:\n%s", credential)
	}
}

// TestCanReach_VerifiedUpgradeQuery asserts the third query re-correlates a raw
// CREDENTIAL_REACH_VERIFIED edge against the live credential identity + topology
// and upgrades the CAN_REACH edge in place (no new edge, no double-count).
func TestCanReach_VerifiedUpgradeQuery(t *testing.T) {
	mock := &graph.MockGraphDB{ExecuteWriteResult: 1}
	p := &CanReach{}
	if _, err := p.Process(context.Background(), mock, "scan-1"); err != nil {
		t.Fatalf("Process: %v", err)
	}
	calls := mock.CallsTo("ExecuteWrite")
	if len(calls) != 3 {
		t.Fatalf("ExecuteWrite called %d times, want 3", len(calls))
	}
	upgrade, _ := calls[2].Args[0].(string)
	// Re-correlation must bind the LIVE credential identity to the witness echo.
	for _, needle := range []string{
		"CREDENTIAL_REACH_VERIFIED",
		"id(v) IN $validated_evidence_ids",
		"a.objectid = v.agent_id",
		"c.value_hash = v.credential_value_hash",
		"c.merge_key = v.credential_merge_key",
		"r.objectid = v.resource_id",
		"r.uri = v.resource_identity_input",
		"PROVIDES_RESOURCE",
		"reach_evidence_state = 'verified'",
		"e.evidence_node_ids = v.evidence_node_ids",
		"v.evidence_node_kinds[evidence_index] IN labels(candidate)",
		"v.publication_revision > 0",
		"e.verified_cleanup_status = 'not_applicable'",
	} {
		if !strings.Contains(upgrade, needle) {
			t.Fatalf("verified-upgrade query missing %q:\n%s", needle, upgrade)
		}
	}
	// The upgrade must NOT MERGE/CREATE a new edge (no duplicate finding).
	if strings.Contains(upgrade, "MERGE (a)-[e:CAN_REACH]") || strings.Contains(upgrade, "CREATE (") {
		t.Fatalf("verified-upgrade must not create a second CAN_REACH edge:\n%s", upgrade)
	}
	if !strings.Contains(upgrade, "e.confidence = 1.0") {
		t.Fatalf("verified-upgrade must raise confidence:\n%s", upgrade)
	}
	if strings.Contains(upgrade, "publication_revision =") {
		t.Fatalf("publication revision must be provenance-only, not equality-gated:\n%s", upgrade)
	}
}

func TestCanReach_ProcessFirstQueryError(t *testing.T) {
	mock := &graph.MockGraphDB{ExecuteWriteError: errors.New("query failed")}

	p := &CanReach{}
	_, err := p.Process(context.Background(), mock, "scan-1")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCanReach_ProcessSecondQueryError(t *testing.T) {
	callCount := 0
	mock := &graph.MockGraphDB{
		ExecuteWriteFunc: func(_ context.Context, _ string, _ map[string]any) (int, error) {
			callCount++
			if callCount == 2 {
				return 0, errors.New("credential chain query failed")
			}
			return 3, nil
		},
	}

	p := &CanReach{}
	_, err := p.Process(context.Background(), mock, "scan-1")
	if err == nil {
		t.Fatal("expected error on second query")
	}
}

func validCampaignEvidenceRow(t *testing.T, agentID string, relationshipID int64) map[string]any {
	t.Helper()
	serverID := "sha256:campaign-server"
	resourceInput := "postgres://prod/customers"
	resourceID := ingest.ComputeNodeID("MCPResource", serverID, resourceInput)
	witness := campaign.Witness{
		SchemaVersion:                campaign.WitnessSchemaVersion,
		TopologyNormalizationVersion: campaign.WitnessTopologyNormalizationVersion,
		PublicationRevision:          1,
		PredictedEdgeKind:            campaign.PredictedEdgeKindCanReach,
		AgentID:                      agentID,
		AgentKind:                    "AgentInstance",
		CredentialID:                 "sha256:campaign-credential",
		CredentialKind:               "Credential",
		CredentialValueHash:          "sha256:campaign-value",
		CredentialMergeKey:           campaign.CredentialMergeKeyValueHash,
		ServerID:                     serverID,
		ServerKind:                   "MCPServer",
		ResourceID:                   resourceID,
		ResourceKind:                 "MCPResource",
		ResourceIdentityInput:        resourceInput,
		EvidenceNodeIDs: []string{
			agentID, serverID, "sha256:campaign-credential", resourceID,
		},
		EvidenceNodeKinds: []string{
			"AgentInstance", "MCPServer", "Credential", "MCPResource",
		},
	}
	evidence := campaign.Evidence{
		ScenarioID:       "cred-reach",
		ScenarioVersion:  1,
		RunID:            "run-1",
		EngagementID:     "ENG-1",
		OracleType:       campaign.OracleTypeDifferentialCredentialReach,
		Outcome:          campaign.OutcomeCredentialGatedReachVerified,
		ControlStage:     campaign.ProbeStageInitialize,
		ControlStatus:    campaign.ProbeDenied,
		ControlAddressed: false,
		AuthedStage:      campaign.ProbeStageResourceRead,
		AuthedStatus:     campaign.ProbeAllowed,
		AuthedAddressed:  true,
		VerifiedAt:       time.Unix(0, 0).UTC().Format(time.RFC3339),
		Witness:          witness,
	}
	_, edges := evidence.EvidenceGraph("scan-campaign")
	if len(edges) != 1 {
		t.Fatal("valid campaign evidence did not emit an edge")
	}
	return map[string]any{
		"relationship_id":    relationshipID,
		"source_agent_id":    agentID,
		"target_resource_id": resourceID,
		"properties":         edges[0].Properties,
	}
}

func TestValidatedCampaignEvidenceAcceptsOldPositivePublicationRevision(t *testing.T) {
	row := validCampaignEvidenceRow(t, "sha256:agent-a", 41)
	db := &graph.MockGraphDB{QueryResult: []map[string]any{row}}
	ids, err := validatedCampaignEvidenceRelationshipIDs(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 || ids[0] != 41 {
		t.Fatalf("validated ids = %v, want [41]", ids)
	}
}

func TestValidatedCampaignEvidenceRejectsPerFieldTamper(t *testing.T) {
	base := validCampaignEvidenceRow(t, "sha256:agent-a", 41)
	baseProps, ok := base["properties"].(map[string]any)
	if !ok {
		t.Fatalf("properties have unexpected type %T", base["properties"])
	}
	tampers := map[string]func(map[string]any, map[string]any){
		"source agent":                   func(row, _ map[string]any) { row["source_agent_id"] = "sha256:agent-b" },
		"target resource":                func(row, _ map[string]any) { row["target_resource_id"] = "sha256:other" },
		campaign.PropWitnessSchema:       func(_, props map[string]any) { props[campaign.PropWitnessSchema] = 1 },
		campaign.PropTopologyVersion:     func(_, props map[string]any) { props[campaign.PropTopologyVersion] = 2 },
		campaign.PropPublicationRevision: func(_, props map[string]any) { props[campaign.PropPublicationRevision] = 0 },
		campaign.PropPredictedEdgeKind:   func(_, props map[string]any) { props[campaign.PropPredictedEdgeKind] = "HAS_ACCESS_TO" },
		campaign.PropAgentID:             func(_, props map[string]any) { props[campaign.PropAgentID] = "sha256:agent-b" },
		campaign.PropAgentKind:           func(_, props map[string]any) { props[campaign.PropAgentKind] = "A2AAgent" },
		campaign.PropCredentialID:        func(_, props map[string]any) { props[campaign.PropCredentialID] = "sha256:other" },
		campaign.PropCredentialKind:      func(_, props map[string]any) { props[campaign.PropCredentialKind] = "Identity" },
		campaign.PropCredentialValueHash: func(_, props map[string]any) { props[campaign.PropCredentialValueHash] = "sha256:other" },
		campaign.PropCredentialMergeKey:  func(_, props map[string]any) { props[campaign.PropCredentialMergeKey] = "identity" },
		campaign.PropServerID:            func(_, props map[string]any) { props[campaign.PropServerID] = "sha256:other" },
		campaign.PropServerKind:          func(_, props map[string]any) { props[campaign.PropServerKind] = "Host" },
		campaign.PropResourceID:          func(_, props map[string]any) { props[campaign.PropResourceID] = "sha256:other" },
		campaign.PropResourceKind:        func(_, props map[string]any) { props[campaign.PropResourceKind] = "Credential" },
		campaign.PropResourceIdentity:    func(_, props map[string]any) { props[campaign.PropResourceIdentity] = "other://resource" },
		campaign.PropEvidenceNodeIDs:     func(_, props map[string]any) { props[campaign.PropEvidenceNodeIDs] = []string{"sha256:agent-a"} },
		campaign.PropEvidenceNodeKinds:   func(_, props map[string]any) { props[campaign.PropEvidenceNodeKinds] = []string{"AgentInstance"} },
		campaign.PropWitnessFingerprint:  func(_, props map[string]any) { props[campaign.PropWitnessFingerprint] = "tampered" },
		campaign.PropScenarioID:          func(_, props map[string]any) { props[campaign.PropScenarioID] = "other" },
		campaign.PropScenarioVersion:     func(_, props map[string]any) { props[campaign.PropScenarioVersion] = 2 },
		campaign.PropOracleType:          func(_, props map[string]any) { props[campaign.PropOracleType] = "other" },
		campaign.PropOutcome:             func(_, props map[string]any) { props[campaign.PropOutcome] = string(campaign.OutcomeNotObserved) },
		campaign.PropControlStage: func(_, props map[string]any) {
			props[campaign.PropControlStage] = string(campaign.ProbeStageResourceRead)
		},
		campaign.PropControlStatus:    func(_, props map[string]any) { props[campaign.PropControlStatus] = string(campaign.ProbeAllowed) },
		campaign.PropControlAddressed: func(_, props map[string]any) { props[campaign.PropControlAddressed] = true },
		campaign.PropAuthedStage:      func(_, props map[string]any) { props[campaign.PropAuthedStage] = string(campaign.ProbeStageInitialize) },
		campaign.PropAuthedStatus:     func(_, props map[string]any) { props[campaign.PropAuthedStatus] = string(campaign.ProbeDenied) },
		campaign.PropAuthedAddressed:  func(_, props map[string]any) { props[campaign.PropAuthedAddressed] = false },
	}
	for name, tamper := range tampers {
		t.Run(name, func(t *testing.T) {
			props := make(map[string]any, len(baseProps))
			for key, value := range baseProps {
				switch typed := value.(type) {
				case []string:
					props[key] = append([]string(nil), typed...)
				default:
					props[key] = value
				}
			}
			row := map[string]any{
				"relationship_id":    base["relationship_id"],
				"source_agent_id":    base["source_agent_id"],
				"target_resource_id": base["target_resource_id"],
				"properties":         props,
			}
			tamper(row, props)
			db := &graph.MockGraphDB{QueryResult: []map[string]any{row}}
			ids, err := validatedCampaignEvidenceRelationshipIDs(context.Background(), db)
			if err != nil {
				t.Fatal(err)
			}
			if len(ids) != 0 {
				t.Fatalf("tampered evidence validated with ids %v", ids)
			}
		})
	}
}
