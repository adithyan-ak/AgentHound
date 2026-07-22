package analysis

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	sdkingest "github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

// TestIntegrationMoatDetectorsE2E is the registry-order regression for the four
// post-processor-produced moat edges shipped in PR #46. It loads one crafted
// scan, ingests it into a live Neo4j, runs the full RunPostProcessors pipeline
// in production order, and asserts every one of TAINTS, IFC_VIOLATION,
// POISONS_CONTEXT, CONFUSED_DEPUTY was emitted at least once. A reordering or
// dependency regression that starves any detector fails here.
//
// The fixture is self-guarded: we assert its node/edge counts inline rather
// than registering it with the ingest pipeline_test suite (whose ../../testdata
// path is broken — see the package note below).
func TestIntegrationMoatDetectorsE2E(t *testing.T) {
	uri := os.Getenv("AGENTHOUND_NEO4J_URI")
	if uri == "" {
		t.Skip("skipping integration test: AGENTHOUND_NEO4J_URI not set")
	}
	user := os.Getenv("AGENTHOUND_NEO4J_USER")
	pass := os.Getenv("AGENTHOUND_NEO4J_PASSWORD")

	raw, err := os.ReadFile("testdata/moat_detectors_scan.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var data sdkingest.IngestData
	if err := json.Unmarshal(raw, &data); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	if err := sdkingest.ScopeArtifact(&data); err != nil {
		t.Fatalf("scope fixture: %v", err)
	}

	// Self-guard: the fixture must keep the exact shape the four detectors
	// rely on. If an edit changes the node/edge inventory, fail loudly here
	// before the more opaque detector assertions below.
	if len(data.Graph.Nodes) != 10 {
		t.Fatalf("fixture nodes = %d, want 10", len(data.Graph.Nodes))
	}
	if len(data.Graph.Edges) != 8 {
		t.Fatalf("fixture edges = %d, want 8", len(data.Graph.Edges))
	}
	for i, edge := range data.Graph.Edges {
		if edge.Kind == "HAS_ACCESS_TO" {
			t.Fatalf("fixture edge %d seeds composite HAS_ACCESS_TO through the raw writer", i)
		}
	}

	scanID := data.Meta.ScanID

	ctx := context.Background()
	driver, err := graph.NewDriver(uri, user, pass)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer driver.Close(ctx)

	writer := graph.NewWriter(driver)
	db := graph.NewDB(graph.NewReader(driver), writer)

	cleanup := func() {
		_, _ = db.ExecuteWrite(ctx,
			"MATCH (n) WHERE n.scan_id = $sid DETACH DELETE n",
			map[string]any{"sid": scanID})
	}
	cleanup()
	defer cleanup()

	if _, err := writer.WriteNodes(ctx, data.Graph.Nodes, scanID); err != nil {
		t.Fatalf("write nodes: %v", err)
	}
	if _, err := writer.WriteEdges(ctx, data.Graph.Edges, scanID); err != nil {
		t.Fatalf("write edges: %v", err)
	}

	// A complete fixture domain starts a fresh global composite epoch.
	// INGESTS_UNTRUSTED is raw, so epoch retirement never touches it.
	completeDomains := sdkingest.CompleteCoverageDomains(data.Meta.Collection)
	if _, err := RunPostProcessors(ctx, db, scanID, completeDomains); err != nil {
		t.Fatalf("RunPostProcessors: %v", err)
	}

	countEdge := func(kind string) int {
		rows, err := db.Query(ctx,
			"MATCH ()-[r:"+kind+"]->() WHERE r.scan_id = $sid RETURN count(r) AS n",
			map[string]any{"sid": scanID})
		if err != nil {
			t.Fatalf("count %s: %v", kind, err)
		}
		return moatToInt(rows[0]["n"])
	}

	for _, kind := range []string{"TAINTS", "IFC_VIOLATION", "POISONS_CONTEXT", "CONFUSED_DEPUTY"} {
		if got := countEdge(kind); got < 1 {
			t.Errorf("%s edges = %d after full pipeline, want >= 1", kind, got)
		}
	}

	rows, err := db.Query(ctx, `
MATCH (t:MCPTool {objectid: $tool_id})
      -[r:HAS_ACCESS_TO {is_composite: true}]->
      (:MCPResource {objectid: $resource_id})
WHERE r.scan_id = $sid
RETURN count(r) AS n`,
		map[string]any{
			"sid": scanID,
			"tool_id": sdkingest.ScopedNodeID(
				sdkingest.ScopeNetworkContext,
				data.Meta.Identity.NetworkContextID,
				"moat-sensitive",
			),
			"resource_id": sdkingest.ScopedNodeID(
				sdkingest.ScopeNetworkContext,
				data.Meta.Identity.NetworkContextID,
				"moat-res",
			),
		})
	if err != nil {
		t.Fatalf("count regenerated HAS_ACCESS_TO: %v", err)
	}
	if got := moatToInt(rows[0]["n"]); got != 1 {
		t.Errorf("regenerated composite HAS_ACCESS_TO edges = %d, want 1", got)
	}

	// INGESTS_UNTRUSTED is seeded raw and must SURVIVE the scan's stale-edge
	// cleanup — it is the substrate TAINTS and IFC_VIOLATION both depend on.
	rows, err = db.Query(ctx,
		"MATCH ()-[r:INGESTS_UNTRUSTED]->() WHERE r.scan_id = $sid RETURN count(r) AS n",
		map[string]any{"sid": scanID})
	if err != nil {
		t.Fatalf("count INGESTS_UNTRUSTED: %v", err)
	}
	if got := moatToInt(rows[0]["n"]); got != 1 {
		t.Errorf("INGESTS_UNTRUSTED edges = %d, want 1 (raw seeded edge must survive)", got)
	}
}

func moatToInt(v any) int {
	switch n := v.(type) {
	case int64:
		return int(n)
	case int:
		return n
	case float64:
		return int(n)
	default:
		return -1
	}
}
