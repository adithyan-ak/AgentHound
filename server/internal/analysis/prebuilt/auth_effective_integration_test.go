package prebuilt

import (
	"context"
	"os"
	"testing"

	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

func TestIntegrationNoAuthQueriesRequireObservedEffectiveTuple(t *testing.T) {
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
	db := graph.NewDB(graph.NewReader(driver), graph.NewWriter(driver))

	const scanID = "test-prebuilt-effective-auth"
	cleanup := func() {
		_, _ = db.ExecuteWrite(ctx,
			"MATCH (n {scan_id: $scan_id}) DETACH DELETE n",
			map[string]any{"scan_id": scanID})
	}
	cleanup()
	defer cleanup()

	_, err = db.ExecuteWrite(ctx, `CREATE
  (:MCPServer {
    objectid: 'prebuilt-observed-anon', name: 'Observed anonymous', scan_id: $scan_id,
    effective_auth_method: 'none', effective_auth_assurance: 'unauthenticated',
    effective_auth_evidence: 'anonymous_probe_succeeded', effective_auth_source: 'observed'
  }),
  (:MCPServer {
    objectid: 'prebuilt-configured-none', name: 'Configured none', scan_id: $scan_id,
    effective_auth_method: 'none', effective_auth_assurance: 'unauthenticated',
    effective_auth_evidence: 'anonymous_probe_succeeded', effective_auth_source: 'configured'
  }),
  (:MCPServer {
    objectid: 'prebuilt-observed-unknown', name: 'Observed unknown', scan_id: $scan_id,
    effective_auth_method: 'unknown', effective_auth_assurance: 'unknown',
    effective_auth_evidence: 'unknown', effective_auth_source: 'configured'
  }),
  (:A2AAgent {
    objectid: 'prebuilt-a2a-observed-anon', name: 'Observed anonymous A2A', scan_id: $scan_id,
    effective_auth_method: 'none', effective_auth_assurance: 'unauthenticated',
    effective_auth_evidence: 'anonymous_probe_succeeded', effective_auth_source: 'observed'
  }),
  (:A2AAgent {
    objectid: 'prebuilt-a2a-configured-none', name: 'Configured none A2A', scan_id: $scan_id,
    effective_auth_method: 'none', effective_auth_assurance: 'unauthenticated',
    effective_auth_evidence: 'anonymous_probe_succeeded', effective_auth_source: 'configured'
  })
RETURN 5 AS created`, map[string]any{"scan_id": scanID})
	if err != nil {
		t.Fatalf("seed effective auth nodes: %v", err)
	}

	rows, err := db.Query(ctx, CypherNoAuthServers, nil)
	if err != nil {
		t.Fatalf("run no-auth prebuilt query: %v", err)
	}
	matched := make([]string, 0, len(rows))
	for _, row := range rows {
		id, _ := row["server_id"].(string)
		if id == "prebuilt-observed-anon" ||
			id == "prebuilt-configured-none" ||
			id == "prebuilt-observed-unknown" {
			matched = append(matched, id)
		}
	}
	if len(matched) != 1 || matched[0] != "prebuilt-observed-anon" {
		t.Fatalf("effective no-auth matches = %v, want only observed anonymous", matched)
	}

	a2aRows, err := db.Query(ctx, CypherNoAuthA2A, nil)
	if err != nil {
		t.Fatalf("run A2A no-auth prebuilt query: %v", err)
	}
	a2aMatched := make([]string, 0, len(a2aRows))
	for _, row := range a2aRows {
		id, _ := row["agent_id"].(string)
		if id == "prebuilt-a2a-observed-anon" || id == "prebuilt-a2a-configured-none" {
			a2aMatched = append(a2aMatched, id)
		}
	}
	if len(a2aMatched) != 1 || a2aMatched[0] != "prebuilt-a2a-observed-anon" {
		t.Fatalf("effective A2A no-auth matches = %v, want only observed anonymous", a2aMatched)
	}
}
