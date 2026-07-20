package processors

import (
	"context"
	"os"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

// TestIntegrationAuthStrengthEffectiveTuple proves the effective-auth
// precedence and trust-edge isolation against Neo4j. It is deliberately one
// matrix so every case is evaluated by the same materialization pass:
// observed anonymous wins globally, observed bearer wins node posture without
// rewriting unrelated configured paths, unknown observations fall back, stdio
// remains configured, and only exact bounded A2A probe evidence overrides its
// card declaration.
func TestIntegrationAuthStrengthEffectiveTuple(t *testing.T) {
	uri := os.Getenv("AGENTHOUND_NEO4J_URI")
	if uri == "" {
		t.Skip("skipping integration test: AGENTHOUND_NEO4J_URI not set")
	}
	ctx := context.Background()
	driver, err := graph.NewDriver(
		uri,
		os.Getenv("AGENTHOUND_NEO4J_USER"),
		os.Getenv("AGENTHOUND_NEO4J_PASSWORD"),
	)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer driver.Close(ctx)

	const scanID = "test-effective-auth"
	db := graph.NewDB(graph.NewReader(driver), graph.NewWriter(driver))
	cleanup := func() {
		_, _ = db.ExecuteWrite(ctx,
			"MATCH (n) WHERE n.scan_id = $sid DETACH DELETE n",
			map[string]any{"sid": scanID})
	}
	cleanup()
	defer cleanup()

	nodes := []ingest.Node{
		authTestAgent("auth-agent-anon-a", scanID),
		authTestAgent("auth-agent-anon-b", scanID),
		authTestAgent("auth-agent-bearer-a", scanID),
		authTestAgent("auth-agent-bearer-b", scanID),
		authTestAgent("auth-agent-fallback", scanID),
		authTestAgent("auth-agent-stdio", scanID),
		{
			ID: "auth-server-anon", Kinds: []string{"MCPServer"}, Properties: map[string]any{
				"name": "anonymous runtime", "transport": "http", "status": "reachable",
				"auth_method": "bearer", "auth_assurance": "moderate", "auth_evidence": "configured_credential",
				"observed_auth_method": "none", "observed_auth_assurance": "unauthenticated",
				"observed_auth_evidence": "anonymous_probe_succeeded", "scan_id": scanID,
			},
		},
		{
			ID: "auth-server-bearer", Kinds: []string{"MCPServer"}, Properties: map[string]any{
				"name": "bearer runtime", "transport": "http", "status": "reachable",
				"auth_method": "oauth", "auth_assurance": "strong", "auth_evidence": "configured_credential",
				"observed_auth_method": "bearer", "observed_auth_assurance": "moderate",
				"observed_auth_evidence": "configured_credential", "scan_id": scanID,
			},
		},
		{
			ID: "auth-server-fallback", Kinds: []string{"MCPServer"}, Properties: map[string]any{
				"name": "unknown runtime", "transport": "http", "status": "reachable",
				"auth_method": "apiKey", "auth_assurance": "weak", "auth_evidence": "configured_credential",
				"observed_auth_method": "unknown", "observed_auth_assurance": "unknown",
				"observed_auth_evidence": "configured_credential", "scan_id": scanID,
			},
		},
		{
			ID: "auth-server-stdio", Kinds: []string{"MCPServer"}, Properties: map[string]any{
				"name": "local process", "transport": "stdio", "status": "reachable",
				"auth_method": "unknown", "auth_assurance": "unknown", "auth_evidence": "local_process",
				"observed_auth_method": "unknown", "observed_auth_assurance": "unknown",
				"observed_auth_evidence": "local_process", "scan_id": scanID,
			},
		},
		{
			ID: "auth-a2a", Kinds: []string{"A2AAgent"}, Properties: map[string]any{
				"name": "A2A fallback", "auth_method": "mtls", "auth_assurance": "strong",
				"auth_evidence": "declared_security_scheme", "scan_id": scanID,
			},
		},
		{
			ID: "auth-a2a-observed", Kinds: []string{"A2AAgent"}, Properties: map[string]any{
				"name": "A2A observed anonymous", "auth_method": "apiKey", "auth_assurance": "weak",
				"auth_evidence": "declared_security_scheme", "scan_id": scanID,
				"auth_probe_method": "get_task_nonexistent", "auth_probe_status": "anonymous_protocol_access",
				"auth_probe_detail":    "task_not_found_v1",
				"observed_auth_method": "none", "observed_auth_assurance": "unauthenticated",
				"observed_auth_evidence": "anonymous_probe_succeeded",
			},
		},
		{
			ID: "auth-a2a-forged", Kinds: []string{"A2AAgent"}, Properties: map[string]any{
				"name": "A2A legacy malformed observation", "auth_method": "bearer", "auth_assurance": "moderate",
				"auth_evidence": "declared_security_scheme", "scan_id": scanID,
				"observed_auth_method": "none", "observed_auth_assurance": "unauthenticated",
				"observed_auth_evidence": "anonymous_probe_succeeded",
			},
		},
		{
			ID: "auth-a2a-raw-anon", Kinds: []string{"A2AAgent"}, Properties: map[string]any{
				"name": "A2A raw anonymous claim", "auth_method": "none", "auth_assurance": "unauthenticated",
				"auth_evidence": "anonymous_probe_succeeded", "scan_id": scanID,
			},
		},
	}
	writer := graph.NewWriter(driver)
	if _, err := writer.WriteNodes(ctx, managedProcessorNodes(nodes), scanID); err != nil {
		t.Fatalf("write nodes: %v", err)
	}
	edges := []ingest.Edge{
		authTestTrust("auth-agent-anon-a", "auth-server-anon", 0.5, true),
		authTestTrust("auth-agent-anon-b", "auth-server-anon", 0.7, true),
		authTestTrust("auth-agent-bearer-a", "auth-server-bearer", 0.7, true),
		authTestTrust("auth-agent-bearer-b", "auth-server-bearer", 0.5, false),
		authTestTrust("auth-agent-fallback", "auth-server-fallback", 0.3, true),
		authTestTrust("auth-agent-stdio", "auth-server-stdio", 0.5, false),
	}
	if _, err := writer.WriteEdges(ctx, managedProcessorEdges(edges), scanID); err != nil {
		t.Fatalf("write edges: %v", err)
	}

	if _, err := (&AuthStrength{}).Process(ctx, db, scanID); err != nil {
		t.Fatalf("materialize effective auth: %v", err)
	}

	rows, err := db.Query(ctx, `MATCH (n)
WHERE n.objectid IN $ids
RETURN n.objectid AS id,
       n.auth_assurance AS configured_assurance,
       n.effective_auth_method AS method,
       n.effective_auth_assurance AS assurance,
       n.effective_auth_evidence AS evidence,
       n.effective_auth_source AS source,
       n.auth_strength AS strength`, map[string]any{"ids": []string{
		"auth-server-anon", "auth-server-bearer", "auth-server-fallback",
		"auth-server-stdio", "auth-a2a", "auth-a2a-observed", "auth-a2a-forged",
		"auth-a2a-raw-anon",
	}})
	if err != nil {
		t.Fatalf("query effective nodes: %v", err)
	}
	byID := make(map[string]map[string]any, len(rows))
	for _, row := range rows {
		id, _ := row["id"].(string)
		byID[id] = row
	}
	assertEffectiveAuthRow(t, byID["auth-server-anon"], "moderate", "none", "unauthenticated", "anonymous_probe_succeeded", "observed", 100)
	assertEffectiveAuthRow(t, byID["auth-server-bearer"], "strong", "bearer", "moderate", "configured_credential", "observed", 50)
	assertEffectiveAuthRow(t, byID["auth-server-fallback"], "weak", "apiKey", "weak", "configured_credential", "configured", 70)
	assertEffectiveAuthRow(t, byID["auth-server-stdio"], "unknown", "unknown", "unknown", "local_process", "configured", nil)
	assertEffectiveAuthRow(t, byID["auth-a2a"], "strong", "mtls", "strong", "declared_security_scheme", "configured", 10)
	assertEffectiveAuthRow(t, byID["auth-a2a-observed"], "weak", "none", "unauthenticated", "anonymous_probe_succeeded", "observed", 100)
	assertEffectiveAuthRow(t, byID["auth-a2a-forged"], "moderate", "bearer", "moderate", "declared_security_scheme", "configured", 50)
	assertEffectiveAuthRow(t, byID["auth-a2a-raw-anon"], "unauthenticated", "none", "unknown", "anonymous_probe_succeeded", "configured", nil)

	edgeRows, err := db.Query(ctx, `MATCH (a:AgentInstance)-[t:TRUSTS_SERVER]->(:MCPServer)
WHERE a.objectid STARTS WITH 'auth-agent-'
RETURN a.objectid AS agent,
       t.risk_weight AS configured_weight,
       t.auth_assessment_complete AS configured_complete,
       t.effective_risk_weight AS effective_weight,
       t.effective_auth_assessment_complete AS effective_complete,
       t.effective_auth_source AS effective_source`, nil)
	if err != nil {
		t.Fatalf("query effective trust edges: %v", err)
	}
	edgesByAgent := make(map[string]map[string]any, len(edgeRows))
	for _, row := range edgeRows {
		agent, _ := row["agent"].(string)
		edgesByAgent[agent] = row
	}
	assertEffectiveTrustRow(t, edgesByAgent["auth-agent-anon-a"], 0.5, true, 0.1, true, "observed")
	assertEffectiveTrustRow(t, edgesByAgent["auth-agent-anon-b"], 0.7, true, 0.1, true, "observed")
	assertEffectiveTrustRow(t, edgesByAgent["auth-agent-bearer-a"], 0.7, true, 0.7, true, "configured")
	assertEffectiveTrustRow(t, edgesByAgent["auth-agent-bearer-b"], 0.5, false, 0.5, false, "configured")
	assertEffectiveTrustRow(t, edgesByAgent["auth-agent-fallback"], 0.3, true, 0.3, true, "configured")
	assertEffectiveTrustRow(t, edgesByAgent["auth-agent-stdio"], 0.5, false, 0.5, false, "configured")
}

func authTestAgent(id, scanID string) ingest.Node {
	return ingest.Node{ID: id, Kinds: []string{"AgentInstance"}, Properties: map[string]any{
		"name": id, "scan_id": scanID,
	}}
}

func authTestTrust(source, target string, weight float64, complete bool) ingest.Edge {
	return ingest.Edge{
		Source: source, Target: target, Kind: "TRUSTS_SERVER",
		SourceKind: "AgentInstance", TargetKind: "MCPServer",
		Properties: map[string]any{
			"risk_weight": weight, "auth_assessment_complete": complete,
		},
	}
}

func assertEffectiveAuthRow(
	t *testing.T,
	row map[string]any,
	configuredAssurance, method, assurance, evidence, source string,
	strength any,
) {
	t.Helper()
	if row == nil ||
		row["configured_assurance"] != configuredAssurance ||
		row["method"] != method || row["assurance"] != assurance ||
		row["evidence"] != evidence || row["source"] != source {
		t.Fatalf("effective auth row = %+v, want configured=%s effective=%s/%s/%s source=%s", row, configuredAssurance, method, assurance, evidence, source)
	}
	if strength == nil {
		if row["strength"] != nil {
			t.Fatalf("auth strength = %v, want nil", row["strength"])
		}
		return
	}
	want, _ := strength.(int)
	var got float64
	switch value := row["strength"].(type) {
	case float64:
		got = value
	case int64:
		got = float64(value)
	case int:
		got = float64(value)
	default:
		t.Fatalf("auth strength = %v (%T), want %d", row["strength"], row["strength"], want)
	}
	if got != float64(want) {
		t.Fatalf("auth strength = %v, want %d", row["strength"], want)
	}
}

func assertEffectiveTrustRow(
	t *testing.T,
	row map[string]any,
	configuredWeight float64,
	configuredComplete bool,
	effectiveWeight float64,
	effectiveComplete bool,
	effectiveSource string,
) {
	t.Helper()
	if row == nil ||
		row["configured_weight"] != configuredWeight ||
		row["configured_complete"] != configuredComplete ||
		row["effective_weight"] != effectiveWeight ||
		row["effective_complete"] != effectiveComplete ||
		row["effective_source"] != effectiveSource {
		t.Fatalf(
			"effective trust row = %+v, want configured=%g/%v effective=%g/%v source=%s",
			row, configuredWeight, configuredComplete, effectiveWeight, effectiveComplete, effectiveSource,
		)
	}
}
