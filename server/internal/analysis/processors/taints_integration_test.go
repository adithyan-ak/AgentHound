package processors

import (
	"context"
	"os"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

// TestIntegrationTaintsSchemaOverlapThreshold locks the >= 2 shared-schema-key
// threshold in taints.go. A cross-server pair where the untrusted-ingesting
// source shares 2+ schema_keys with a sink fires exactly one TAINTS edge; the
// FP-guard pair sharing only a single key must fire none (a single common key
// like "id" is not signal).
func TestIntegrationTaintsSchemaOverlapThreshold(t *testing.T) {
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

	const scanID = "test-taints-threshold"
	db := graph.NewDB(graph.NewReader(driver), graph.NewWriter(driver))

	cleanup := func() {
		_, _ = db.ExecuteWrite(ctx,
			"MATCH (n) WHERE n.scan_id = $sid DETACH DELETE n",
			map[string]any{"sid": scanID})
	}
	cleanup()
	defer cleanup()

	// server-a hosts the untrusted-ingesting source. server-b hosts two
	// sinks: a positive sink sharing two schema_keys, and an FP-guard sink
	// sharing only one.
	nodes := []ingest.Node{
		{ID: "tn-srv-a", Kinds: []string{"MCPServer"}, Properties: map[string]any{
			"objectid": "tn-srv-a", "name": "server-a", "scan_id": scanID,
		}},
		{ID: "tn-srv-b", Kinds: []string{"MCPServer"}, Properties: map[string]any{
			"objectid": "tn-srv-b", "name": "server-b", "scan_id": scanID,
		}},
		{ID: "tn-src", Kinds: []string{"MCPTool"}, Properties: map[string]any{
			"objectid": "tn-src", "name": "untrusted_src",
			"schema_keys": []string{"query", "table", "filter"},
			"scan_id":     scanID,
		}},
		// shares "query" + "table" with src -> overlap 2 -> fires.
		{ID: "tn-snk-hit", Kinds: []string{"MCPTool"}, Properties: map[string]any{
			"objectid": "tn-snk-hit", "name": "sink_hit",
			"schema_keys": []string{"query", "table", "unrelated"},
			"scan_id":     scanID,
		}},
		// shares only "query" with src -> overlap 1 -> must NOT fire.
		{ID: "tn-snk-miss", Kinds: []string{"MCPTool"}, Properties: map[string]any{
			"objectid": "tn-snk-miss", "name": "sink_miss",
			"schema_keys": []string{"query", "other", "more"},
			"scan_id":     scanID,
		}},
		{ID: "tn-res", Kinds: []string{"MCPResource"}, Properties: map[string]any{
			"objectid": "tn-res", "name": "untrusted-feed", "scan_id": scanID,
		}},
	}
	writer := graph.NewWriter(driver)
	if _, err := writer.WriteNodes(ctx, managedProcessorNodes(nodes), scanID); err != nil {
		t.Fatalf("write nodes: %v", err)
	}

	edges := []ingest.Edge{
		{Source: "tn-srv-a", Target: "tn-src", Kind: "PROVIDES_TOOL", SourceKind: "MCPServer", TargetKind: "MCPTool"},
		{Source: "tn-srv-b", Target: "tn-snk-hit", Kind: "PROVIDES_TOOL", SourceKind: "MCPServer", TargetKind: "MCPTool"},
		{Source: "tn-srv-b", Target: "tn-snk-miss", Kind: "PROVIDES_TOOL", SourceKind: "MCPServer", TargetKind: "MCPTool"},
		{Source: "tn-src", Target: "tn-res", Kind: "INGESTS_UNTRUSTED", SourceKind: "MCPTool", TargetKind: "MCPResource"},
	}
	if _, err := writer.WriteEdges(ctx, managedProcessorEdges(edges), scanID); err != nil {
		t.Fatalf("write edges: %v", err)
	}

	if _, err := (&Taints{}).Process(ctx, db, scanID); err != nil {
		t.Fatalf("taints process: %v", err)
	}

	// POSITIVE: the 2-key-overlap sink gets exactly one TAINTS edge.
	rows, err := db.Query(ctx,
		"MATCH (:MCPTool {objectid:'tn-src'})-[:TAINTS]->(t:MCPTool {objectid:'tn-snk-hit'}) RETURN count(t) AS n", nil)
	if err != nil {
		t.Fatalf("query positive taints: %v", err)
	}
	if got := toInt(rows[0]["n"]); got != 1 {
		t.Errorf("2-key-overlap sink got %d TAINTS edges, want 1", got)
	}

	// FP-GUARD: the 1-key-overlap sink must get zero (locks the >= 2 threshold).
	rows, err = db.Query(ctx,
		"MATCH (:MCPTool {objectid:'tn-src'})-[:TAINTS]->(t:MCPTool {objectid:'tn-snk-miss'}) RETURN count(t) AS n", nil)
	if err != nil {
		t.Fatalf("query fp-guard taints: %v", err)
	}
	if got := toInt(rows[0]["n"]); got != 0 {
		t.Errorf("1-key-overlap sink got %d TAINTS edges, want 0 (>= 2 threshold regression)", got)
	}
}
