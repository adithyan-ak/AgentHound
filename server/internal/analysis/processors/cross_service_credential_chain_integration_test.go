package processors

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

const crossServiceFixtureHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// TestIntegrationCrossServiceCredentialChainGlobalBlastRadius is the
// regression for the shared-secret aggregation grain. Two distinct config
// credential nodes carry the same value_hash and are reachable by two agents;
// agent A also has both paths, deliberately creating two candidates for the
// same (agent, upstream credential) edge. The processor must:
//   - count the two distinct agents globally for every correlated credential;
//   - choose the stable seven-node tuple for agent A rather than the last row;
//   - emit exactly one edge per agent/upstream with canonical evidence; and
//   - remain structurally and evidentially idempotent across repeated runs.
func TestIntegrationCrossServiceCredentialChainGlobalBlastRadius(t *testing.T) {
	uri := os.Getenv("AGENTHOUND_NEO4J_URI")
	if uri == "" {
		t.Skip("skipping integration test: AGENTHOUND_NEO4J_URI not set")
	}
	user := os.Getenv("AGENTHOUND_NEO4J_USER")
	pass := os.Getenv("AGENTHOUND_NEO4J_PASSWORD")

	ctx := context.Background()
	driver, err := graph.NewDriver(uri, user, pass)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer driver.Close(ctx)

	const fixtureScanID = "test-cross-service-global"
	db := graph.NewDB(graph.NewReader(driver), graph.NewWriter(driver))
	cleanup := func() {
		_, _ = db.ExecuteWrite(ctx,
			"MATCH (n) WHERE n.scan_id = $sid DETACH DELETE n",
			map[string]any{"sid": fixtureScanID})
	}
	cleanup()
	defer cleanup()

	nodes := []ingest.Node{
		processorFixtureNode("cscg-agent-a", "AgentInstance", "agent-a", fixtureScanID, nil),
		processorFixtureNode("cscg-agent-b", "AgentInstance", "agent-b", fixtureScanID, nil),
		processorFixtureNode("cscg-agent-decoy", "AgentInstance", "agent-decoy", fixtureScanID, nil),
		processorFixtureNode("cscg-server-a", "MCPServer", "server-a", fixtureScanID, nil),
		processorFixtureNode("cscg-server-b", "MCPServer", "server-b", fixtureScanID, nil),
		processorFixtureNode("cscg-server-decoy", "MCPServer", "server-decoy", fixtureScanID, nil),
		processorFixtureNode("cscg-identity-a", "Identity", "identity-a", fixtureScanID, nil),
		processorFixtureNode("cscg-identity-b", "Identity", "identity-b", fixtureScanID, nil),
		processorFixtureNode("cscg-identity-decoy", "Identity", "identity-decoy", fixtureScanID, nil),
		processorFixtureCredential("cscg-config-a", "config-a", fixtureScanID, crossServiceFixtureHash, "value_hash", "value_hash"),
		processorFixtureCredential("cscg-config-b", "config-b", fixtureScanID, crossServiceFixtureHash, "value_hash", "value_hash"),
		// Same crafted hash, but identity-only correlation is ineligible and
		// must neither add an agent nor receive blast-radius enrichment.
		processorFixtureCredential("cscg-config-decoy", "config-decoy", fixtureScanID, crossServiceFixtureHash, "identity", "identity"),
		processorFixtureCredential("cscg-master", "master", fixtureScanID, crossServiceFixtureHash, "value_hash", "value_hash"),
		processorFixtureNode("cscg-gateway", "LiteLLMGateway", "gateway", fixtureScanID, map[string]any{
			"endpoint": "http://litellm.invalid",
		}),
		processorFixtureNode("cscg-upstream", "Credential", "upstream", fixtureScanID, map[string]any{
			"type":            "apiKey",
			"provider":        "fixture-provider",
			"material_status": "masked",
			"exposure_status": "not_observed",
			"merge_key":       "identity",
			"identity_basis":  "provider_name",
		}),
	}
	// LiteLLMGateway is a concrete AIService implementation and must carry the
	// documented umbrella companion label in that order.
	for i := range nodes {
		if nodes[i].ID == "cscg-gateway" {
			nodes[i].Kinds = []string{"LiteLLMGateway", "AIService"}
		}
	}

	writer := graph.NewWriter(driver)
	if _, err := writer.WriteNodes(ctx, managedProcessorNodes(nodes), fixtureScanID); err != nil {
		t.Fatalf("write nodes: %v", err)
	}

	edges := []ingest.Edge{
		processorFixtureEdge("cscg-agent-a", "cscg-server-b", "TRUSTS_SERVER", "AgentInstance", "MCPServer"),
		// Insert the lexicographically later route first. Winner selection must
		// still choose server-a for agent-a.
		processorFixtureEdge("cscg-agent-a", "cscg-server-a", "TRUSTS_SERVER", "AgentInstance", "MCPServer"),
		processorFixtureEdge("cscg-agent-b", "cscg-server-b", "TRUSTS_SERVER", "AgentInstance", "MCPServer"),
		processorFixtureEdge("cscg-agent-decoy", "cscg-server-decoy", "TRUSTS_SERVER", "AgentInstance", "MCPServer"),
		processorFixtureEdge("cscg-server-a", "cscg-identity-a", "AUTHENTICATES_WITH", "MCPServer", "Identity"),
		processorFixtureEdge("cscg-server-b", "cscg-identity-b", "AUTHENTICATES_WITH", "MCPServer", "Identity"),
		processorFixtureEdge("cscg-server-decoy", "cscg-identity-decoy", "AUTHENTICATES_WITH", "MCPServer", "Identity"),
		processorFixtureEdge("cscg-identity-a", "cscg-config-a", "USES_CREDENTIAL", "Identity", "Credential"),
		processorFixtureEdge("cscg-identity-b", "cscg-config-b", "USES_CREDENTIAL", "Identity", "Credential"),
		processorFixtureEdge("cscg-identity-decoy", "cscg-config-decoy", "USES_CREDENTIAL", "Identity", "Credential"),
		processorFixtureEdge("cscg-gateway", "cscg-master", "EXPOSES_CREDENTIAL", "AIService", "Credential"),
		processorFixtureEdge("cscg-gateway", "cscg-upstream", "EXPOSES_CREDENTIAL", "AIService", "Credential"),
	}
	if _, err := writer.WriteEdges(ctx, managedProcessorEdges(edges), fixtureScanID); err != nil {
		t.Fatalf("write edges: %v", err)
	}

	processor := &CrossServiceCredentialChain{}
	stats, err := processor.Process(ctx, db, fixtureScanID+"-run-0")
	if err != nil {
		t.Fatalf("process first run: %v", err)
	}
	if stats.EdgesCreated != 2 {
		t.Fatalf("first run wrote %d CAN_REACH rows, want 2", stats.EdgesCreated)
	}

	wantNodes := map[string][]string{
		"cscg-agent-a": {
			"cscg-agent-a", "cscg-server-a", "cscg-identity-a",
			"cscg-config-a", "cscg-master", "cscg-gateway", "cscg-upstream",
		},
		"cscg-agent-b": {
			"cscg-agent-b", "cscg-server-b", "cscg-identity-b",
			"cscg-config-b", "cscg-master", "cscg-gateway", "cscg-upstream",
		},
	}
	wantSynthetic := map[string][]string{
		"cscg-agent-a": {
			"cscg-config-a", "cscg-master", "VALUE_HASH_MATCH",
			"identity_correlation", "value_hash", "cross_service_credential_chain",
		},
		"cscg-agent-b": {
			"cscg-config-b", "cscg-master", "VALUE_HASH_MATCH",
			"identity_correlation", "value_hash", "cross_service_credential_chain",
		},
	}
	wantRelationshipKinds := []string{
		"TRUSTS_SERVER", "AUTHENTICATES_WITH", "USES_CREDENTIAL",
		"EXPOSES_CREDENTIAL", "EXPOSES_CREDENTIAL",
	}

	firstEvidence := assertCrossServiceCredentialChainState(
		t, ctx, db, fixtureScanID+"-run-0", wantNodes, wantSynthetic, wantRelationshipKinds,
	)
	assertCrossServiceBlastRadius(t, ctx, db)

	// Repeated execution must update the epoch in place without adding edges
	// or changing the deterministic evidence winner.
	for run := 1; run <= 5; run++ {
		runID := fmt.Sprintf("%s-run-%d", fixtureScanID, run)
		stats, err = processor.Process(ctx, db, runID)
		if err != nil {
			t.Fatalf("process repeat %d: %v", run, err)
		}
		if stats.EdgesCreated != 2 {
			t.Fatalf("repeat %d wrote %d CAN_REACH rows, want 2", run, stats.EdgesCreated)
		}
		gotEvidence := assertCrossServiceCredentialChainState(
			t, ctx, db, runID, wantNodes, wantSynthetic, wantRelationshipKinds,
		)
		if !reflect.DeepEqual(gotEvidence, firstEvidence) {
			t.Fatalf("repeat %d changed evidence:\nfirst=%v\n got=%v", run, firstEvidence, gotEvidence)
		}
		assertCrossServiceBlastRadius(t, ctx, db)
	}
}

func processorFixtureNode(
	id, kind, name, scanID string,
	extra map[string]any,
) ingest.Node {
	properties := map[string]any{
		"objectid": id,
		"name":     name,
		"scan_id":  scanID,
	}
	for key, value := range extra {
		properties[key] = value
	}
	return ingest.Node{ID: id, Kinds: []string{kind}, Properties: properties}
}

func processorFixtureCredential(
	id, name, scanID, valueHash, mergeKey, identityBasis string,
) ingest.Node {
	return processorFixtureNode(id, "Credential", name, scanID, map[string]any{
		"type":            "apiKey",
		"value_hash":      valueHash,
		"merge_key":       mergeKey,
		"identity_basis":  identityBasis,
		"material_status": "observed",
		"exposure_status": "exposed",
	})
}

func processorFixtureEdge(source, target, kind, sourceKind, targetKind string) ingest.Edge {
	return ingest.Edge{
		Source: source, Target: target, Kind: kind,
		SourceKind: sourceKind, TargetKind: targetKind,
		Properties: map[string]any{"risk_weight": 0.1},
	}
}

func assertCrossServiceCredentialChainState(
	t *testing.T,
	ctx context.Context,
	db graph.GraphDB,
	wantScanID string,
	wantNodes, wantSynthetic map[string][]string,
	wantRelationshipKinds []string,
) map[string][]string {
	t.Helper()

	rows, err := db.Query(ctx, `
MATCH (a:AgentInstance)-[e:CAN_REACH]->(c:Credential {objectid: 'cscg-upstream'})
WHERE a.objectid STARTS WITH 'cscg-agent-'
RETURN a.objectid AS agent_id,
       e.scan_id AS scan_id,
       e.source_collector AS source_collector,
       e.is_composite AS is_composite,
       e.hops AS hops,
       e.confidence AS confidence,
       e.risk_weight AS risk_weight,
       e.evidence_version AS evidence_version,
       e.merge_value_hash AS merge_value_hash,
       e.via_server AS via_server,
       e.via_credential AS via_credential,
       e.via_gateway AS via_gateway,
       e.upstream_provider AS upstream_provider,
       e.evidence_node_ids AS evidence_node_ids,
       e.evidence_synthetic_edge AS evidence_synthetic_edge
ORDER BY agent_id`, nil)
	if err != nil {
		t.Fatalf("query CAN_REACH state: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d agent/upstream CAN_REACH edges, want 2: %v", len(rows), rows)
	}

	evidence := make(map[string][]string, len(rows))
	for _, row := range rows {
		agentID, _ := row["agent_id"].(string)
		if _, known := wantNodes[agentID]; !known {
			t.Fatalf("ineligible or unknown agent received CAN_REACH: %v", row)
		}
		if got, _ := row["scan_id"].(string); got != wantScanID {
			t.Errorf("%s scan_id = %q, want %q", agentID, got, wantScanID)
		}
		if got, _ := row["source_collector"].(string); got != "cross_service_credential_chain" {
			t.Errorf("%s source_collector = %q", agentID, got)
		}
		if got, _ := row["is_composite"].(bool); !got {
			t.Errorf("%s is_composite = false", agentID)
		}
		if got := toInt(row["hops"]); got != 6 {
			t.Errorf("%s hops = %d, want 6", agentID, got)
		}
		if got, _ := row["confidence"].(float64); got != 0.95 {
			t.Errorf("%s confidence = %v, want 0.95", agentID, row["confidence"])
		}
		if got, _ := row["risk_weight"].(float64); got != 0.1 {
			t.Errorf("%s risk_weight = %v, want 0.1", agentID, row["risk_weight"])
		}
		if got := toInt(row["evidence_version"]); got != 1 {
			t.Errorf("%s evidence_version = %d, want 1", agentID, got)
		}
		if got, _ := row["merge_value_hash"].(string); got != crossServiceFixtureHash {
			t.Errorf("%s merge_value_hash = %q, want fixture hash", agentID, got)
		}
		if got, _ := row["via_gateway"].(string); got != "gateway" {
			t.Errorf("%s via_gateway = %q, want gateway", agentID, got)
		}
		if got, _ := row["upstream_provider"].(string); got != "fixture-provider" {
			t.Errorf("%s upstream_provider = %q, want fixture-provider", agentID, got)
		}
		wantViaServer := map[string]string{"cscg-agent-a": "server-a", "cscg-agent-b": "server-b"}[agentID]
		wantViaCredential := map[string]string{"cscg-agent-a": "config-a", "cscg-agent-b": "config-b"}[agentID]
		if got, _ := row["via_server"].(string); got != wantViaServer {
			t.Errorf("%s via_server = %q, want %q", agentID, got, wantViaServer)
		}
		if got, _ := row["via_credential"].(string); got != wantViaCredential {
			t.Errorf("%s via_credential = %q, want %q", agentID, got, wantViaCredential)
		}
		nodeIDs := stringSliceProperty(row, "evidence_node_ids")
		if !reflect.DeepEqual(nodeIDs, wantNodes[agentID]) {
			t.Errorf("%s evidence nodes = %v, want %v", agentID, nodeIDs, wantNodes[agentID])
		}
		synthetic := stringSliceProperty(row, "evidence_synthetic_edge")
		if !reflect.DeepEqual(synthetic, wantSynthetic[agentID]) {
			t.Errorf("%s synthetic evidence = %v, want %v", agentID, synthetic, wantSynthetic[agentID])
		}
		evidence[agentID] = append(append([]string(nil), nodeIDs...), synthetic...)
	}

	kindRows, err := db.Query(ctx, `
MATCH (a:AgentInstance)-[e:CAN_REACH]->(:Credential {objectid: 'cscg-upstream'})
WHERE a.objectid STARTS WITH 'cscg-agent-'
UNWIND range(0, size(e.evidence_relationship_ids) - 1) AS evidence_index
MATCH ()-[raw]->()
WHERE id(raw) = e.evidence_relationship_ids[evidence_index]
WITH a, evidence_index, type(raw) AS relationship_kind
ORDER BY a.objectid, evidence_index
RETURN a.objectid AS agent_id, collect(relationship_kind) AS relationship_kinds
ORDER BY agent_id`, nil)
	if err != nil {
		t.Fatalf("query evidence relationship kinds: %v", err)
	}
	if len(kindRows) != 2 {
		t.Fatalf("got %d relationship-evidence rows, want 2: %v", len(kindRows), kindRows)
	}
	for _, row := range kindRows {
		agentID, _ := row["agent_id"].(string)
		gotKinds := stringSliceProperty(row, "relationship_kinds")
		if !reflect.DeepEqual(gotKinds, wantRelationshipKinds) {
			t.Errorf("%s evidence relationship kinds = %v, want %v", agentID, gotKinds, wantRelationshipKinds)
		}
		evidence[agentID] = append(evidence[agentID], gotKinds...)
	}
	return evidence
}

func assertCrossServiceBlastRadius(t *testing.T, ctx context.Context, db graph.GraphDB) {
	t.Helper()
	rows, err := db.Query(ctx, `
MATCH (c:Credential)
WHERE c.objectid IN ['cscg-config-a', 'cscg-config-b', 'cscg-config-decoy', 'cscg-master']
RETURN c.objectid AS credential_id, c.blast_radius AS blast_radius
ORDER BY credential_id`, nil)
	if err != nil {
		t.Fatalf("query blast radius: %v", err)
	}
	if len(rows) != 4 {
		t.Fatalf("got %d credential rows, want 4: %v", len(rows), rows)
	}
	for _, row := range rows {
		credentialID, _ := row["credential_id"].(string)
		if credentialID == "cscg-config-decoy" {
			if row["blast_radius"] != nil {
				t.Errorf("identity-only decoy blast_radius = %v, want null", row["blast_radius"])
			}
			continue
		}
		if got := toInt(row["blast_radius"]); got != 2 {
			t.Errorf("%s blast_radius = %d, want global distinct-agent count 2", credentialID, got)
		}
	}
}
