package ingest

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/adithyan-ak/agenthound/sdk/campaign"
	"github.com/adithyan-ak/agenthound/sdk/common"
	sdkingest "github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

func pipelineCampaignEvidence(outcome campaign.Outcome) campaign.Evidence {
	const (
		agentID      = "campaign-agent-a"
		serverID     = "campaign-server"
		credentialID = "campaign-credential"
		resourceURI  = "postgres://prod/customers"
	)
	serviceScopeID := "sha256:prevalidation-test-network"
	scopedServerID := sdkingest.ScopedNodeID(sdkingest.ScopeNetworkContext, serviceScopeID, serverID)
	rawResourceID := sdkingest.ComputeNodeID("MCPResource", serverID, resourceURI)
	resourceID := sdkingest.ScopedNodeID(sdkingest.ScopeNetworkContext, serviceScopeID, rawResourceID)
	evidence := campaign.Evidence{
		ScenarioID:       "cred-reach",
		ScenarioVersion:  1,
		RunID:            "run-campaign-prevalidation",
		EngagementID:     "ENG-CAMPAIGN",
		OracleType:       campaign.OracleTypeDifferentialCredentialReach,
		Outcome:          outcome,
		ControlStage:     campaign.ProbeStageResourceRead,
		ControlStatus:    campaign.ProbeDenied,
		ControlAddressed: true,
		AuthedStage:      campaign.ProbeStageResourceRead,
		AuthedStatus:     campaign.ProbeAllowed,
		AuthedAddressed:  true,
		VerifiedAt:       time.Unix(0, 0).UTC().Format(time.RFC3339),
		Witness: campaign.Witness{
			SchemaVersion:                campaign.WitnessSchemaVersion,
			TopologyNormalizationVersion: campaign.WitnessTopologyNormalizationVersion,
			PublicationRevision:          1,
			PredictedEdgeKind:            campaign.PredictedEdgeKindCanReach,
			AgentID:                      agentID,
			AgentKind:                    "AgentInstance",
			CredentialID:                 credentialID,
			CredentialKind:               "Credential",
			CredentialValueHash:          "campaign-value-hash",
			CredentialMergeKey:           campaign.CredentialMergeKeyValueHash,
			ServerID:                     scopedServerID,
			ServerKind:                   "MCPServer",
			ServerIdentityID:             serverID,
			ServiceScope:                 sdkingest.ScopeNetworkContext,
			ServiceScopeID:               serviceScopeID,
			ResourceID:                   resourceID,
			ResourceKind:                 "MCPResource",
			ResourceIdentityInput:        resourceURI,
			EvidenceNodeIDs: []string{
				agentID, "entry-server", "entry-tool", scopedServerID,
				credentialID, "campaign-identity", "resource-tool", resourceID,
			},
			EvidenceNodeKinds: []string{
				"AgentInstance", "MCPServer", "MCPTool", "MCPServer",
				"Credential", "Identity", "MCPTool", "MCPResource",
			},
		},
	}
	if outcome == campaign.OutcomeNotObserved {
		evidence.AuthedStatus = campaign.ProbeDenied
	}
	return evidence
}

func pipelineCampaignEnvelope(scanID string, evidence campaign.Evidence) *sdkingest.IngestData {
	data := common.NewIngestData("scan", scanID)
	data.Meta.Identity = testCollectionIdentity()
	data.Meta.Extra = map[string]any{
		campaign.EvidenceArtifactMetadataKey: evidence.Artifact(),
	}
	coverageKey := campaignCoverageKey(evidence.Artifact())
	state := sdkingest.OutcomePartial
	if evidence.Outcome.Definitive() {
		state = sdkingest.OutcomeComplete
	}
	nodes, edges := evidence.EvidenceGraph(scanID)
	data.Graph.Nodes = nodes
	data.Graph.Edges = edges
	if data.Graph.Nodes == nil {
		data.Graph.Nodes = []sdkingest.Node{}
	}
	if data.Graph.Edges == nil {
		data.Graph.Edges = []sdkingest.Edge{}
	}
	data.Meta.Collection = &sdkingest.CollectionReport{
		State:        state,
		CoverageKeys: []string{coverageKey},
		Outcomes: []sdkingest.CollectionOutcome{{
			Collector: "scan", CoverageKey: coverageKey,
			Target: evidence.Witness.ServerID, Method: "campaign:cred-reach",
			State: state, Items: len(edges),
		}},
	}
	sdkingest.TagObservationDomain(&data.Graph, coverageKey)
	return data
}

func TestPipelineRejectedNegativeNeverBeginsOrTouchesGraph(t *testing.T) {
	evidence := pipelineCampaignEvidence(campaign.OutcomeNotObserved)
	data := pipelineCampaignEnvelope("rejected-negative", evidence)
	artifact := evidence.Artifact()
	artifact.Authenticated.Status = campaign.ProbeAllowed
	data.Meta.Extra[campaign.EvidenceArtifactMetadataKey] = artifact

	writer := &fakeWriter{}
	scans := &fakeScanStore{}
	db := &graph.MockGraphDB{}
	pipeline := newTestPipeline(writer, db, scans, noOpRunPP)

	result, err := pipeline.Ingest(context.Background(), data)
	if result != nil {
		t.Fatalf("rejected campaign returned result: %+v", result)
	}
	var rejection *CampaignArtifactRejectionError
	if !errors.As(err, &rejection) {
		t.Fatalf("error = %v, want CampaignArtifactRejectionError", err)
	}
	if len(scans.creates) != 0 ||
		len(writer.nodeCalls) != 0 ||
		len(writer.edgeCalls) != 0 ||
		len(db.CallsTo("ExecuteWrite")) != 0 {
		t.Fatal("rejected negative touched scan lifecycle, graph writer, or reconciliation")
	}
	if len(scans.rejections) != 1 {
		t.Fatalf("rejection audits = %d, want 1", len(scans.rejections))
	}
	audit := scans.rejections[0]
	if audit.RunID != evidence.RunID ||
		audit.ScenarioID != evidence.ScenarioID ||
		audit.ScenarioVersion != evidence.ScenarioVersion ||
		audit.Outcome != string(evidence.Outcome) ||
		len(audit.ReasonCodes) != 1 ||
		audit.ReasonCodes[0] != campaignRejectionArtifactContract {
		t.Fatalf("unexpected sanitized rejection audit: %+v", audit)
	}
}

func TestPipelineRejectedPositivePreservesCanonicalWriterState(t *testing.T) {
	evidence := pipelineCampaignEvidence(campaign.OutcomeCredentialGatedReachVerified)
	data := pipelineCampaignEnvelope("rejected-positive", evidence)
	data.Graph.Edges[0].Properties[campaign.PropWitnessFingerprint] = "tampered"

	writer := &fakeWriter{}
	scans := &fakeScanStore{}
	db := &graph.MockGraphDB{}
	pipeline := newTestPipeline(writer, db, scans, noOpRunPP)

	_, err := pipeline.Ingest(context.Background(), data)
	var rejection *CampaignArtifactRejectionError
	if !errors.As(err, &rejection) {
		t.Fatalf("error = %v, want CampaignArtifactRejectionError", err)
	}
	if len(scans.creates) != 0 ||
		len(writer.nodeCalls) != 0 ||
		len(writer.edgeCalls) != 0 {
		t.Fatal("invalid positive reached BeginScan or shared canonical MERGE writer")
	}
	if len(scans.rejections) != 1 ||
		scans.rejections[0].ReasonCodes[0] != campaignRejectionEvidenceContract {
		t.Fatalf("unexpected rejection audit: %+v", scans.rejections)
	}
}

func TestPipelineGenericCampaignRejectionIsAuditOnly(t *testing.T) {
	evidence := pipelineCampaignEvidence(campaign.OutcomeCredentialGatedReachVerified)
	data := pipelineCampaignEnvelope("generic-invalid-campaign", evidence)
	data.Graph.Edges[0].ObservationDomains = nil

	writer := &fakeWriter{}
	scans := &fakeScanStore{}
	db := &graph.MockGraphDB{}
	pipeline := newTestPipeline(writer, db, scans, noOpRunPP)

	_, err := pipeline.Ingest(context.Background(), data)
	var rejection *CampaignArtifactRejectionError
	if !errors.As(err, &rejection) {
		t.Fatalf("error = %v, want CampaignArtifactRejectionError", err)
	}
	if len(scans.creates) != 0 ||
		len(writer.nodeCalls) != 0 ||
		len(writer.edgeCalls) != 0 ||
		len(db.CallsTo("Query")) != 0 {
		t.Fatal("generic-invalid campaign touched lifecycle or graph state")
	}
	if len(scans.rejections) != 1 ||
		scans.rejections[0].ReasonCodes[0] != campaignRejectionGenericIngestInvalid {
		t.Fatalf("unexpected rejection audit: %+v", scans.rejections)
	}
}

func TestPipelineTopologyTamperRejectedBeforeBeginScan(t *testing.T) {
	evidence := pipelineCampaignEvidence(campaign.OutcomeCredentialGatedReachVerified)
	evidence.Witness.CredentialValueHash = "tampered-public-hash"
	data := pipelineCampaignEnvelope("topology-tamper", evidence)

	writer := &fakeWriter{}
	scans := &fakeScanStore{}
	db := &graph.MockGraphDB{
		QueryResult: []map[string]any{{"matches": int64(0)}},
	}
	pipeline := newTestPipeline(writer, db, scans, noOpRunPP)

	_, err := pipeline.Ingest(context.Background(), data)
	var rejection *CampaignArtifactRejectionError
	if !errors.As(err, &rejection) {
		t.Fatalf("error = %v, want CampaignArtifactRejectionError", err)
	}
	if len(scans.creates) != 0 ||
		len(writer.nodeCalls) != 0 ||
		len(writer.edgeCalls) != 0 {
		t.Fatal("topology-tampered positive reached BeginScan or writer")
	}
	if len(scans.rejections) != 1 ||
		scans.rejections[0].ReasonCodes[0] != campaignRejectionTopologyMismatch {
		t.Fatalf("unexpected rejection audit: %+v", scans.rejections)
	}
}

func TestPipelineValidatedNegativeMayRetireExactCoverage(t *testing.T) {
	evidence := pipelineCampaignEvidence(campaign.OutcomeNotObserved)
	data := pipelineCampaignEnvelope("validated-negative", evidence)
	coverageKey := data.Meta.Collection.CoverageKeys[0]

	db := &graph.MockGraphDB{
		QueryFunc: func(_ context.Context, cypher string, _ map[string]any) ([]map[string]any, error) {
			switch {
			case cypher == campaignCurrentTopologyValidationQuery:
				return []map[string]any{{"matches": int64(1)}}, nil
			case strings.Contains(cypher, "incomplete_property_nodes"):
				return []map[string]any{{
					"incomplete_property_nodes":         int64(0),
					"incomplete_property_relationships": int64(0),
					"tokenless_nodes":                   int64(0),
					"tokenless_incident_relationships":  int64(0),
				}}, nil
			default:
				return []map[string]any{}, nil
			}
		},
	}
	writer := &fakeWriter{}
	scans := &fakeScanStore{}
	pipeline := newTestPipeline(writer, db, scans, noOpRunPP)

	result, err := pipeline.Ingest(context.Background(), data)
	if err != nil {
		t.Fatalf("validated negative ingest: %v", err)
	}
	if result == nil || len(scans.creates) != 1 ||
		len(writer.nodeCalls) != 1 || len(writer.edgeCalls) != 1 {
		t.Fatalf(
			"validated negative did not traverse the real pipeline: result=%+v creates=%d nodes=%d edges=%d",
			result, len(scans.creates), len(writer.nodeCalls), len(writer.edgeCalls),
		)
	}
	scopedCoverageKey := sdkingest.ScopedCoverageKey(
		sdkingest.ScopeCollectionPoint,
		data.Meta.Identity.CollectionPointID,
		coverageKey,
	)
	if !equalStrings(writer.nodeCalls[0].CompleteScopes, []string{scopedCoverageKey}) ||
		!equalStrings(writer.edgeCalls[0].CompleteScopes, []string{scopedCoverageKey}) {
		t.Fatalf("validated negative did not authorize exact-domain retirement")
	}
}

func TestPrevalidateCampaignArtifactsKeepAgentsIndependent(t *testing.T) {
	first := pipelineCampaignEvidence(campaign.OutcomeCredentialGatedReachVerified)
	second := pipelineCampaignEvidence(campaign.OutcomeCredentialGatedReachVerified)
	second.Witness.AgentID = "campaign-agent-b"
	second.Witness.EvidenceNodeIDs = append([]string(nil), first.Witness.EvidenceNodeIDs...)
	second.Witness.EvidenceNodeIDs[0] = second.Witness.AgentID

	var validatedAgents []string
	db := &graph.MockGraphDB{
		QueryFunc: func(_ context.Context, cypher string, params map[string]any) ([]map[string]any, error) {
			if cypher == campaignCurrentTopologyValidationQuery {
				agentID, ok := params["agent_id"].(string)
				if !ok {
					t.Fatalf("agent_id parameter has type %T", params["agent_id"])
				}
				validatedAgents = append(validatedAgents, agentID)
				return []map[string]any{{"matches": int64(1)}}, nil
			}
			return nil, nil
		},
	}
	pipeline := &Pipeline{graphDB: db}
	for index, evidence := range []campaign.Evidence{first, second} {
		data := pipelineCampaignEnvelope("agent-"+strconv.Itoa(index), evidence)
		if err := pipeline.prevalidateCampaignArtifact(context.Background(), data); err != nil {
			t.Fatalf("agent %d prevalidation: %v", index, err)
		}
	}
	if !equalStrings(validatedAgents, []string{
		first.Witness.AgentID,
		second.Witness.AgentID,
	}) {
		t.Fatalf("validated agents = %v", validatedAgents)
	}
}
