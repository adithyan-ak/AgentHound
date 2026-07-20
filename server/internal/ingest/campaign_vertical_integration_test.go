package ingest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/adithyan-ak/agenthound/sdk/campaign"
	"github.com/adithyan-ak/agenthound/sdk/common"
	sdkingest "github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/server/internal/analysis"
	"github.com/adithyan-ak/agenthound/server/internal/appdb"
	"github.com/adithyan-ak/agenthound/server/internal/graph"
	"github.com/adithyan-ak/agenthound/server/model"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestIntegrationCompiledCampaignExportProbeIngestPromotesOnlySourceAgent(t *testing.T) {
	ctx, pipeline, db, _, pool := publicationIntegrationHarness(t, false)
	const (
		credentialMaterial = "campaign-vertical-secret"
		resourceURI        = "postgres://prod/customers"
		agentA             = "campaign-agent-a"
		agentB             = "campaign-agent-b"
		entryServer        = "campaign-entry-server"
		entryTool          = "campaign-entry-tool"
		alternateServer    = "campaign-entry-server-z"
		alternateTool      = "campaign-entry-tool-z"
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
	base.Meta.Origin = sdkingest.CollectionOrigin{
		HostID:         "campaign-fixture-host",
		NetworkRealmID: "campaign-fixture-realm",
	}
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
		node(alternateServer, "MCPServer", map[string]any{
			"name": "alternate entry", "transport": "http", "auth_method": "apiKey",
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
		node(alternateTool, "MCPTool", map[string]any{
			"name": "read alternate config", "description": "read local configuration",
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
		edge(agentA, alternateServer, "TRUSTS_SERVER", "AgentInstance", "MCPServer"),
		edge(agentB, alternateServer, "TRUSTS_SERVER", "AgentInstance", "MCPServer"),
		edge(entryServer, entryTool, "PROVIDES_TOOL", "MCPServer", "MCPTool"),
		edge(alternateServer, alternateTool, "PROVIDES_TOOL", "MCPServer", "MCPTool"),
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
	wantTopology := []string{
		agentA, entryServer, entryTool, serverID,
		credentialID, identityID, resourceTool, resourceID,
	}
	if !reflect.DeepEqual(witness.EvidenceNodeIDs, wantTopology) {
		t.Fatalf(
			"multipath witness topology = %v, want stable complete tuple %v",
			witness.EvidenceNodeIDs,
			wantTopology,
		)
	}

	campaignData := runCompiledCampaign(
		t,
		ctx,
		*witness,
		httpServer.URL,
		credentialMaterial,
	)
	campaignScope := campaignData.Meta.Collection.CoverageKeys[0]
	compiledEvidence, _, err := campaignEvidenceFromProperties(
		campaignData.Graph.Edges[0].Properties,
	)
	if err != nil {
		t.Fatalf("decode compiled campaign evidence: %v", err)
	}
	if compiledEvidence.Outcome != campaign.OutcomeCredentialGatedReachVerified {
		t.Fatalf("compiled campaign outcome = %q", compiledEvidence.Outcome)
	}
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

	evidenceRows, err := db.Query(ctx, `
MATCH (:AgentInstance {objectid: $agent_id})-[v:CREDENTIAL_REACH_VERIFIED]->
      (:MCPResource {objectid: $resource_id})
RETURN count(v) AS count`, map[string]any{
		"agent_id": agentA, "resource_id": resourceID,
	})
	if err != nil {
		t.Fatalf("count canonical campaign evidence: %v", err)
	}
	canonicalEvidenceCount, ok := int64Property(evidenceRows[0], "count")
	if !ok || canonicalEvidenceCount != 1 {
		t.Fatalf("canonical campaign evidence count = %v, want 1", evidenceRows)
	}
	var canonicalCoverageScanID string
	if err := pool.QueryRow(ctx,
		`SELECT scan_id FROM coverage_heads WHERE coverage_key = $1`,
		campaignScope,
	).Scan(&canonicalCoverageScanID); err != nil {
		t.Fatalf("read canonical campaign coverage: %v", err)
	}

	invalidPositive := campaignVerticalEnvelope("campaign-invalid-positive", compiledEvidence)
	invalidPositive.Graph.Edges[0].Properties[campaign.PropWitnessFingerprint] = "tampered"
	_, err = pipeline.Ingest(ctx, invalidPositive)
	var positiveRejection *CampaignArtifactRejectionError
	if !errors.As(err, &positiveRejection) {
		t.Fatalf("invalid positive error = %v, want campaign rejection", err)
	}
	assertCampaignCanonicalState(
		t, ctx, db, pool, agentA, resourceID, campaignScope,
		canonicalCoverageScanID,
	)
	assertSanitizedCampaignRejectionAudit(t, ctx, pool, positiveRejection.RejectionID)

	negative := compiledEvidence
	negative.RunID = "run-invalid-negative"
	negative.Outcome = campaign.OutcomeNotObserved
	negative.AuthedStatus = campaign.ProbeDenied
	invalidNegative := campaignVerticalEnvelope("campaign-invalid-negative", negative)
	artifact := negative.Artifact()
	artifact.Authenticated.Status = campaign.ProbeAllowed
	invalidNegative.Meta.Extra[campaign.EvidenceArtifactMetadataKey] = artifact
	_, err = pipeline.Ingest(ctx, invalidNegative)
	var negativeRejection *CampaignArtifactRejectionError
	if !errors.As(err, &negativeRejection) {
		t.Fatalf("invalid negative error = %v, want campaign rejection", err)
	}
	assertCampaignCanonicalState(
		t, ctx, db, pool, agentA, resourceID, campaignScope,
		canonicalCoverageScanID,
	)
	assertSanitizedCampaignRejectionAudit(t, ctx, pool, negativeRejection.RejectionID)
}

func runCompiledCampaign(
	t *testing.T,
	ctx context.Context,
	witness campaign.Witness,
	endpoint string,
	credentialMaterial string,
) *sdkingest.IngestData {
	t.Helper()

	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate integration test source")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", "..", ".."))
	tempDir := t.TempDir()
	binaryPath := filepath.Join(tempDir, "agenthound")
	build := exec.CommandContext(
		ctx,
		"go",
		"build",
		"-o",
		binaryPath,
		"./collector/cmd/agenthound",
	)
	build.Dir = repoRoot
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build compiled collector: %v: %s", err, output)
	}

	witnessPath := filepath.Join(tempDir, "witness.json")
	witnessJSON, err := json.MarshalIndent(witness, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(witnessPath, witnessJSON, 0o600); err != nil {
		t.Fatalf("write production witness: %v", err)
	}

	artifactPath := filepath.Join(tempDir, "campaign-artifact.json")
	homeDir := filepath.Join(tempDir, "home")
	if err := os.MkdirAll(homeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	run := exec.CommandContext(
		ctx,
		binaryPath,
		"campaign",
		endpoint,
		"--scenario",
		"cred-reach",
		"--witness",
		witnessPath,
		"--engagement-id",
		"ENG-COMPILED-E2E",
		"--commit",
		"--timeout",
		"5s",
		"--output",
		artifactPath,
	)
	run.Dir = repoRoot
	run.Env = environmentWithOverrides(map[string]string{
		"HOME":                           homeDir,
		"AGENTHOUND_HOST_ID":             "campaign-fixture-host",
		"AGENTHOUND_NETWORK_REALM_ID":    "campaign-fixture-realm",
		"AGENTHOUND_CAMPAIGN_AUTHORIZED": "AUTHORIZED",
		"AGENTHOUND_CAMPAIGN_CREDENTIAL": credentialMaterial,
	})
	runOutput, err := run.CombinedOutput()
	if bytes.Contains(runOutput, []byte(credentialMaterial)) {
		t.Fatal("compiled campaign output exposed credential material")
	}
	if err != nil {
		t.Fatalf("run compiled campaign: %v: %s", err, runOutput)
	}
	if !bytes.Contains(runOutput, []byte("[campaign] RUN_REPORT ")) {
		t.Fatalf("compiled campaign did not emit bounded run report: %s", runOutput)
	}
	if _, err := os.Stat(
		filepath.Join(homeDir, ".agenthound", "campaign-acknowledged"),
	); err != nil {
		t.Fatalf("compiled campaign did not exercise authorization gate: %v", err)
	}

	serialized, err := os.ReadFile(artifactPath)
	if err != nil {
		t.Fatalf("read compiled campaign artifact: %v", err)
	}
	if bytes.Contains(serialized, []byte(credentialMaterial)) {
		t.Fatal("serialized campaign artifact exposed credential material")
	}
	decoder := json.NewDecoder(bytes.NewReader(serialized))
	decoder.DisallowUnknownFields()
	var artifact sdkingest.IngestData
	if err := decoder.Decode(&artifact); err != nil {
		t.Fatalf("decode compiled campaign artifact: %v", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		t.Fatalf("compiled campaign artifact has trailing data: %v", err)
	}
	if artifact.Meta.Collection == nil ||
		len(artifact.Meta.Collection.CoverageKeys) != 1 ||
		len(artifact.Graph.Edges) != 1 {
		t.Fatalf("compiled campaign artifact is incomplete: %+v", artifact.Meta)
	}
	return &artifact
}

func environmentWithOverrides(overrides map[string]string) []string {
	base := os.Environ()
	result := make([]string, 0, len(base)+len(overrides))
	for _, entry := range base {
		key, _, _ := strings.Cut(entry, "=")
		if _, replaced := overrides[key]; replaced {
			continue
		}
		result = append(result, entry)
	}
	for key, value := range overrides {
		result = append(result, key+"="+value)
	}
	return result
}

func campaignVerticalEnvelope(
	scanID string,
	evidence campaign.Evidence,
) *sdkingest.IngestData {
	data := common.NewIngestData("scan", scanID)
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

func assertCampaignCanonicalState(
	t *testing.T,
	ctx context.Context,
	db *graph.DB,
	pool *pgxpool.Pool,
	agentID, resourceID, coverageKey, coverageScanID string,
) {
	t.Helper()
	rows, err := db.Query(ctx, `
MATCH (:AgentInstance {objectid: $agent_id})-[v:CREDENTIAL_REACH_VERIFIED]->
      (:MCPResource {objectid: $resource_id})
RETURN count(v) AS count`, map[string]any{
		"agent_id": agentID, "resource_id": resourceID,
	})
	if err != nil {
		t.Fatalf("count preserved campaign evidence: %v", err)
	}
	count, ok := int64Property(rows[0], "count")
	if !ok || count != 1 {
		t.Fatalf("canonical campaign evidence was not preserved: %v", rows)
	}
	var currentCoverageScanID string
	if err := pool.QueryRow(ctx,
		`SELECT scan_id FROM coverage_heads WHERE coverage_key = $1`,
		coverageKey,
	).Scan(&currentCoverageScanID); err != nil {
		t.Fatalf("read preserved campaign coverage: %v", err)
	}
	if currentCoverageScanID != coverageScanID {
		t.Fatalf(
			"campaign coverage changed after rejection: got %q want %q",
			currentCoverageScanID,
			coverageScanID,
		)
	}
}

func assertSanitizedCampaignRejectionAudit(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	rejectionID string,
) {
	t.Helper()
	scan, err := appdb.NewScanStore(pool).GetScan(ctx, rejectionID)
	if err != nil {
		t.Fatalf("read campaign rejection audit: %v", err)
	}
	if scan.Status != model.ScanStatusFailed ||
		scan.NodeWriteRows != 0 ||
		scan.EdgeWriteRows != 0 {
		t.Fatalf("unexpected campaign rejection scan: %+v", scan)
	}
	raw, ok := scan.Metadata["campaign_rejection"].(map[string]any)
	if !ok {
		t.Fatalf("campaign rejection metadata = %#v", scan.Metadata)
	}
	wantKeys := []string{
		"outcome", "reason_codes", "rejection_id", "run_id",
		"scenario_id", "scenario_version",
	}
	var gotKeys []string
	for key := range raw {
		gotKeys = append(gotKeys, key)
	}
	sort.Strings(gotKeys)
	if !reflect.DeepEqual(gotKeys, wantKeys) {
		t.Fatalf("campaign rejection metadata keys = %v, want %v", gotKeys, wantKeys)
	}
	if raw["rejection_id"] != rejectionID {
		t.Fatalf("campaign rejection id = %#v, want %q", raw["rejection_id"], rejectionID)
	}
	encoded, err := json.Marshal(scan.Metadata)
	if err != nil {
		t.Fatal(err)
	}
	for _, prohibited := range []string{
		"campaign_artifact", "witness", "fingerprint", "digest",
		"credential_value_hash", "evidence_node_ids",
	} {
		if strings.Contains(string(encoded), prohibited) {
			t.Fatalf("rejection audit contains prohibited field %q: %s", prohibited, encoded)
		}
	}
}
