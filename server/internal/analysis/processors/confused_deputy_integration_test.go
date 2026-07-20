package processors

import (
	"context"
	"os"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

// TestIntegrationConfusedDeputyAuthGradient locks the categorical assurance
// predicate in confused_deputy.go. AuthStrength materializes a paired effective
// tuple, so unauthenticated access requires the exact bounded A2A observation
// while configured weak authentication remains eligible.
//   - POSITIVE A: observed unauthenticated -> strong delegation fires once.
//   - POSITIVE B: configured weak -> strong delegation fires once.
//   - FP-GUARD A: configured no-auth without observation must not fire.
//   - FP-GUARD B: inverted gradient strong -> weak must not fire.
//   - FP-GUARD C: equal strong -> strong delegation must not fire.
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

	nodes := []ingest.Node{
		{ID: "cd-anon-observed", Kinds: []string{"A2AAgent"}, Properties: map[string]any{
			"objectid": "cd-anon-observed", "name": "observed_anon_agent",
			"auth_method": "apiKey", "auth_assurance": "weak",
			"auth_evidence":           "declared_security_scheme",
			"auth_probe_method":       "get_task_nonexistent",
			"auth_probe_status":       "anonymous_protocol_access",
			"auth_probe_detail":       "task_not_found_v1",
			"observed_auth_method":    "none",
			"observed_auth_assurance": "unauthenticated",
			"observed_auth_evidence":  "anonymous_probe_succeeded",
			"scan_id":                 scanID,
		}},
		{ID: "cd-weak", Kinds: []string{"A2AAgent"}, Properties: map[string]any{
			"objectid": "cd-weak", "name": "configured_weak_agent",
			"auth_method": "apiKey", "auth_assurance": "weak",
			"auth_evidence": "declared_security_scheme", "scan_id": scanID,
		}},
		{ID: "cd-unobserved-none", Kinds: []string{"A2AAgent"}, Properties: map[string]any{
			"objectid": "cd-unobserved-none", "name": "configured_no_auth_agent",
			"auth_method": "none", "auth_assurance": "unauthenticated",
			"auth_evidence": "unknown", "scan_id": scanID,
		}},
		{ID: "cd-strong", Kinds: []string{"A2AAgent"}, Properties: map[string]any{
			"objectid": "cd-strong", "name": "mtls_agent",
			"auth_method": "mtls", "auth_assurance": "strong",
			"auth_evidence": "declared_security_scheme", "scan_id": scanID,
		}},
		{ID: "cd-strong2", Kinds: []string{"A2AAgent"}, Properties: map[string]any{
			"objectid": "cd-strong2", "name": "oauth_agent",
			"auth_method": "oauth", "auth_assurance": "strong",
			"auth_evidence": "declared_security_scheme", "scan_id": scanID,
		}},
	}
	writer := graph.NewWriter(driver)
	if _, err := writer.WriteNodes(ctx, managedProcessorNodes(nodes), scanID); err != nil {
		t.Fatalf("write nodes: %v", err)
	}

	edges := []ingest.Edge{
		// POSITIVE A: runtime-observed anonymous -> strong.
		{Source: "cd-anon-observed", Target: "cd-strong", Kind: "DELEGATES_TO", SourceKind: "A2AAgent", TargetKind: "A2AAgent"},
		// POSITIVE B: configured weak -> strong.
		{Source: "cd-weak", Target: "cd-strong", Kind: "DELEGATES_TO", SourceKind: "A2AAgent", TargetKind: "A2AAgent"},
		// FP-GUARD A: a configured no-auth claim is not runtime proof.
		{Source: "cd-unobserved-none", Target: "cd-strong", Kind: "DELEGATES_TO", SourceKind: "A2AAgent", TargetKind: "A2AAgent"},
		// FP-GUARD B: inverted, strong -> weak.
		{Source: "cd-strong", Target: "cd-weak", Kind: "DELEGATES_TO", SourceKind: "A2AAgent", TargetKind: "A2AAgent"},
		// FP-GUARD C: strong -> strong; low side is not weak.
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

	for _, tc := range []struct {
		name, source string
	}{
		{name: "observed anonymous", source: "cd-anon-observed"},
		{name: "configured weak", source: "cd-weak"},
	} {
		rows, err := db.Query(ctx, `MATCH (:A2AAgent {objectid:$source})-[:CONFUSED_DEPUTY]->
  (a:A2AAgent {objectid:'cd-strong'}) RETURN count(a) AS n`, map[string]any{"source": tc.source})
		if err != nil {
			t.Fatalf("query %s positive confused_deputy: %v", tc.name, err)
		}
		if got := toInt(rows[0]["n"]); got != 1 {
			t.Errorf("%s -> strong got %d CONFUSED_DEPUTY edges, want 1", tc.name, got)
		}
	}

	// FP-GUARD: configured no-auth without the exact runtime observation does
	// not establish anonymous protocol access.
	rows, err := db.Query(ctx,
		"MATCH (:A2AAgent {objectid:'cd-unobserved-none'})-[:CONFUSED_DEPUTY]->(a:A2AAgent) RETURN count(a) AS n", nil)
	if err != nil {
		t.Fatalf("query configured-no-auth fp-guard: %v", err)
	}
	if got := toInt(rows[0]["n"]); got != 0 {
		t.Errorf("configured no-auth source got %d CONFUSED_DEPUTY edges, want 0", got)
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
