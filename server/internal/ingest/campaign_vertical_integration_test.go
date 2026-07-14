package ingest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/adithyan-ak/agenthound/modules/credreach"
	"github.com/adithyan-ak/agenthound/sdk/campaign"
	"github.com/adithyan-ak/agenthound/sdk/common"
	sdkingest "github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/server/internal/analysis"
	"github.com/adithyan-ak/agenthound/server/internal/appdb"
	"github.com/adithyan-ak/agenthound/server/model"
)

func TestIntegrationCampaignExportProbeIngestPromotesOnlySourceAgent(t *testing.T) {
	ctx, pipeline, db, _, pool := publicationIntegrationHarness(t, false)
	const (
		credentialMaterial = "campaign-vertical-secret"
		resourceURI        = "postgres://prod/customers"
		agentA             = "campaign-agent-a"
		agentB             = "campaign-agent-b"
		entryServer        = "campaign-entry-server"
		entryTool          = "campaign-entry-tool"
		resourceTool       = "campaign-resource-tool"
		credentialID       = "campaign-shared-credential"
		identityID         = "campaign-shared-identity"
	)

	mcpServer := mcpsdk.NewServer(
		&mcpsdk.Implementation{Name: "campaign-vertical", Version: "1.0.0"},
		nil,
	)
	mcpServer.AddResource(
		&mcpsdk.Resource{URI: resourceURI, Name: "customers"},
		func(_ context.Context, req *mcpsdk.ReadResourceRequest) (*mcpsdk.ReadResourceResult, error) {
			return &mcpsdk.ReadResourceResult{Contents: []*mcpsdk.ResourceContents{{
				URI: req.Params.URI, Text: "redacted-test-content",
			}}}, nil
		},
	)
	mcpHandler := mcpsdk.NewStreamableHTTPHandler(
		func(*http.Request) *mcpsdk.Server { return mcpServer },
		&mcpsdk.StreamableHTTPOptions{JSONResponse: true},
	)
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+credentialMaterial {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		mcpHandler.ServeHTTP(w, r)
	}))
	defer httpServer.Close()

	serverID := sdkingest.ResolveMCPServerIdentity("http", httpServer.URL).ObjectID
	resourceID := sdkingest.ComputeNodeID("MCPResource", serverID, resourceURI)
	scope := sdkingest.CanonicalCoverageKey(
		"mcp", "target", sdkingest.CanonicalURLScope(httpServer.URL),
	)
	base := common.NewIngestData("mcp", "campaign-vertical-base")
	base.Meta.Collection = &sdkingest.CollectionReport{
		State:        sdkingest.OutcomeComplete,
		CoverageKeys: []string{scope},
		Outcomes: []sdkingest.CollectionOutcome{{
			Collector: "mcp", CoverageKey: scope, Target: httpServer.URL,
			Method: "enumerate", State: sdkingest.OutcomeComplete, Items: 15,
		}},
	}
	node := func(id, kind string, properties map[string]any) sdkingest.Node {
		return sdkingest.Node{
			ID: id, Kinds: []string{kind}, Properties: properties,
			ObservationDomains: []string{scope},
		}
	}
	base.Graph.Nodes = []sdkingest.Node{
		node(agentA, "AgentInstance", map[string]any{"name": "source agent"}),
		node(agentB, "AgentInstance", map[string]any{"name": "other agent"}),
		node(entryServer, "MCPServer", map[string]any{
			"name": "entry", "transport": "http", "auth_method": "apiKey",
			"auth_assurance": "weak", "auth_evidence": "configured_credential",
		}),
		node(serverID, "MCPServer", map[string]any{
			"name": "resource", "transport": "http", "auth_method": "bearer",
			"auth_assurance": "moderate", "auth_evidence": "configured_credential",
		}),
		node(entryTool, "MCPTool", map[string]any{
			"name": "read config", "description": "read local configuration",
			"capability_surface": []string{"file_read"},
		}),
		node(resourceTool, "MCPTool", map[string]any{
			"name": "query customers", "description": "query customers",
			"capability_surface": []string{"database_access"},
		}),
		node(credentialID, "Credential", map[string]any{
			"name":       "DB_TOKEN",
			"value_hash": common.HashCredentialValue(credentialMaterial),
			"merge_key":  "value_hash", "identity_basis": "value_hash",
			"material_status": "observed", "exposure_status": "exposed",
		}),
		node(identityID, "Identity", map[string]any{"name": "database identity"}),
		node(resourceID, "MCPResource", map[string]any{
			"name": "customers", "uri": resourceURI, "uri_scheme": "postgres",
			"sensitivity": "critical", "is_template": false,
		}),
	}
	edge := func(source, target, kind, sourceKind, targetKind string) sdkingest.Edge {
		return sdkingest.Edge{
			Source: source, Target: target, Kind: kind,
			SourceKind: sourceKind, TargetKind: targetKind,
			Properties:         map[string]any{"risk_weight": 0.1},
			ObservationDomains: []string{scope},
		}
	}
	base.Graph.Edges = []sdkingest.Edge{
		edge(agentA, entryServer, "TRUSTS_SERVER", "AgentInstance", "MCPServer"),
		edge(agentB, entryServer, "TRUSTS_SERVER", "AgentInstance", "MCPServer"),
		edge(entryServer, entryTool, "PROVIDES_TOOL", "MCPServer", "MCPTool"),
		edge(serverID, resourceTool, "PROVIDES_TOOL", "MCPServer", "MCPTool"),
		edge(serverID, resourceID, "PROVIDES_RESOURCE", "MCPServer", "MCPResource"),
		edge(serverID, credentialID, "HAS_ENV_VAR", "MCPServer", "Credential"),
		edge(serverID, identityID, "AUTHENTICATES_WITH", "MCPServer", "Identity"),
		edge(identityID, credentialID, "USES_CREDENTIAL", "Identity", "Credential"),
	}

	baseResult, err := pipeline.Ingest(ctx, base)
	if err != nil {
		t.Fatalf("base ingest: %v", err)
	}
	if baseResult.PublishedRevision == nil {
		t.Fatalf("base graph did not publish: %+v", baseResult)
	}
	store := appdb.NewFindingStore(pool)
	baseFindings, _, err := store.ListPublished(ctx, "", true)
	if err != nil {
		t.Fatal(err)
	}
	var sourceFinding *model.Finding
	for i := range baseFindings {
		if baseFindings[i].EdgeKind == "CAN_REACH" &&
			baseFindings[i].SourceID == agentA &&
			baseFindings[i].TargetID == resourceID {
			sourceFinding = &baseFindings[i]
			break
		}
	}
	if sourceFinding == nil {
		t.Fatalf("source-agent prediction missing: %+v", baseFindings)
	}

	witness, err := analysis.BuildWitness(ctx, db, sourceFinding.ID)
	if err != nil {
		t.Fatalf("export witness: %v", err)
	}
	witness.PublicationRevision = int(*baseResult.PublishedRevision)
	if err := witness.Validate(); err != nil {
		t.Fatalf("exported witness invalid: %v", err)
	}

	run, err := (&credreach.Scenario{}).Run(ctx, campaign.RunInput{
		Witness: *witness, CredentialMaterial: credentialMaterial,
		Host: httpServer.URL, EngagementID: "ENG-VERTICAL",
		RunID: "run-vertical", Commit: true, Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("live credreach run: %v", err)
	}
	if run.Outcome != campaign.OutcomeCredentialGatedReachVerified {
		t.Fatalf("live outcome = %q report=%+v", run.Outcome, run.Report)
	}

	campaignScope := sdkingest.CanonicalCoverageKey(
		"scan",
		"campaign",
		strings.Join([]string{
			"cred-reach", strconv.Itoa(1), witness.AgentID, witness.CredentialID,
			witness.ServerID, witness.ResourceID,
		}, "\x00"),
	)
	campaignData := common.NewIngestData("scan", "campaign-vertical-evidence")
	campaignData.Meta.Extra = map[string]any{
		"campaign_scenario": "cred-reach", "campaign_scenario_version": 1,
		"engagement_id": "ENG-VERTICAL", "campaign_run_id": "run-vertical",
		"campaign_outcome": string(run.Outcome),
	}
	nodes, edges := run.Evidence.EvidenceGraph(campaignData.Meta.ScanID)
	campaignData.Graph.Nodes = nodes
	campaignData.Graph.Edges = edges
	campaignData.Meta.Collection = &sdkingest.CollectionReport{
		State:        sdkingest.OutcomeComplete,
		CoverageKeys: []string{campaignScope},
		Outcomes: []sdkingest.CollectionOutcome{{
			Collector: "scan", CoverageKey: campaignScope, Target: witness.ServerID,
			Method: "campaign:cred-reach", State: sdkingest.OutcomeComplete,
			Items: len(edges),
		}},
	}
	sdkingest.TagObservationDomain(&campaignData.Graph, campaignScope)
	if _, err := pipeline.Ingest(ctx, campaignData); err != nil {
		t.Fatalf("campaign evidence ingest: %v", err)
	}

	findings, _, err := store.ListPublished(ctx, "", true)
	if err != nil {
		t.Fatal(err)
	}
	var verifiedA, verifiedB int
	for _, finding := range findings {
		if finding.EdgeKind != "CAN_REACH" || finding.TargetID != resourceID {
			continue
		}
		switch finding.SourceID {
		case agentA:
			if finding.Evidence.State == model.FindingEvidenceVerified {
				verifiedA++
			}
		case agentB:
			if finding.Evidence.State == model.FindingEvidenceVerified {
				verifiedB++
			}
		}
	}
	if verifiedA != 1 || verifiedB != 0 {
		t.Fatalf("verified findings: source=%d other=%d all=%+v", verifiedA, verifiedB, findings)
	}
}
