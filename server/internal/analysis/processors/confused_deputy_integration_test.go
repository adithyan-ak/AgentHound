package processors

import (
	"context"
	"os"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

// TestIntegrationConfusedDeputyAuthGradient locks the categorical assurance
// predicate in confused_deputy.go. AuthStrength materializes assurance from
// method plus evidence, so explicit anonymous access requires a successful
// anonymous probe.
//   - POSITIVE: unauthenticated -> strong delegation fires once.
//   - FP-GUARD A: inverted gradient strong -> weak must not fire.
//   - FP-GUARD B: equal strong -> strong delegation must not fire.
func TestIntegrationConfusedDeputyAuthGradient(t *testing.T) {
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

	const scanID = "test-confused-deputy"
	db := graph.NewDB(graph.NewReader(driver), graph.NewWriter(driver))

	cleanup := func() {
		_, _ = db.ExecuteWrite(ctx,
			"MATCH (n) WHERE n.scan_id = $sid DETACH DELETE n",
			map[string]any{"sid": scanID})
	}
	cleanup()
	defer cleanup()

	// AuthStrength keys on the auth_method node property.
	nodes := []ingest.Node{
		{ID: "cd-weak", Kinds: []string{"A2AAgent"}, Properties: map[string]any{
			"objectid": "cd-weak", "name": "anon_agent",
			"auth_method": "none", "auth_evidence": "anonymous_probe_succeeded",
			"scan_id": scanID,
		}},
		{ID: "cd-strong", Kinds: []string{"A2AAgent"}, Properties: map[string]any{
			"objectid": "cd-strong", "name": "mtls_agent",
			"auth_method": "mtls", "scan_id": scanID,
		}},
		{ID: "cd-strong2", Kinds: []string{"A2AAgent"}, Properties: map[string]any{
			"objectid": "cd-strong2", "name": "oauth_agent",
			"auth_method": "oauth", "scan_id": scanID,
		}},
	}
	writer := graph.NewWriter(driver)
	if _, err := writer.WriteNodes(ctx, managedProcessorNodes(nodes), scanID); err != nil {
		t.Fatalf("write nodes: %v", err)
	}

	edges := []ingest.Edge{
		// POSITIVE: unauthenticated -> strong.
		{Source: "cd-weak", Target: "cd-strong", Kind: "DELEGATES_TO", SourceKind: "A2AAgent", TargetKind: "A2AAgent"},
		// FP-GUARD A: inverted, strong -> unauthenticated.
		{Source: "cd-strong", Target: "cd-weak", Kind: "DELEGATES_TO", SourceKind: "A2AAgent", TargetKind: "A2AAgent"},
		// FP-GUARD B: strong -> strong; low side is not weak.
		{Source: "cd-strong", Target: "cd-strong2", Kind: "DELEGATES_TO", SourceKind: "A2AAgent", TargetKind: "A2AAgent"},
	}
	if _, err := writer.WriteEdges(ctx, managedProcessorEdges(edges), scanID); err != nil {
		t.Fatalf("write edges: %v", err)
	}

	// Materialize auth_strength first, then run the detector.
	if _, err := (&AuthStrength{}).Process(ctx, db, scanID); err != nil {
		t.Fatalf("auth_strength process: %v", err)
	}
	if _, err := (&ConfusedDeputy{}).Process(ctx, db, scanID); err != nil {
		t.Fatalf("confused_deputy process: %v", err)
	}

	// POSITIVE: exactly one CONFUSED_DEPUTY weak -> strong.
	rows, err := db.Query(ctx,
		"MATCH (:A2AAgent {objectid:'cd-weak'})-[:CONFUSED_DEPUTY]->(a:A2AAgent {objectid:'cd-strong'}) RETURN count(a) AS n", nil)
	if err != nil {
		t.Fatalf("query positive confused_deputy: %v", err)
	}
	if got := toInt(rows[0]["n"]); got != 1 {
		t.Errorf("weak->strong got %d CONFUSED_DEPUTY edges, want 1", got)
	}

	// FP-GUARD: no CONFUSED_DEPUTY should originate from the strong agent
	// (covers both the inverted and the equal-gradient delegations).
	rows, err = db.Query(ctx,
		"MATCH (:A2AAgent {objectid:'cd-strong'})-[:CONFUSED_DEPUTY]->(a:A2AAgent) RETURN count(a) AS n", nil)
	if err != nil {
		t.Fatalf("query fp-guard confused_deputy: %v", err)
	}
	if got := toInt(rows[0]["n"]); got != 0 {
		t.Errorf("strong-source got %d CONFUSED_DEPUTY edges, want 0 (auth-gradient regression)", got)
	}
}
