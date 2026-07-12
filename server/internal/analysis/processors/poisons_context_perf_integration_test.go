package processors

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

// TestIntegrationPoisonsContextPerSourceCap is the authoritative regression
// gate for the POISONS_CONTEXT per-(agent, source) fan-out cap in shadows.go:
//
//	MATCH (a:AgentInstance)-[:TRUSTS_SERVER]->(:MCPServer)-[:PROVIDES_TOOL]->(src:MCPTool)
//	MATCH (a)-[:TRUSTS_SERVER]->(:MCPServer)-[:PROVIDES_TOOL]->(snk:MCPTool)
//	WITH a, src, collect(DISTINCT snk) AS sinks
//	WHERE size(sinks) <= 20
//	UNWIND sinks AS snk ...
//
// Two invariants are load-bearing and verified here:
//   - The cap TRUNCATES to 20, it does not suppress: a (agent, source) pair
//     with <= 20 eligible co-resident sinks emits one edge per sink; a pair
//     with 21+ eligible sinks emits exactly 20 (the first 20 by objectid),
//     never zero. Silent suppression would blind the detector in its worst
//     case (a poisoner co-resident with the most high-cap sinks) and hand an
//     attacker an evasion primitive (add a 21st sink → finding vanishes). We
//     assert both the at-cap and over-cap sides.
//   - The query is AGENT-SCOPED: src and snk must be co-resident under one
//     AgentInstance's trusted servers. The seed builds that full
//     AgentInstance-[:TRUSTS_SERVER]->MCPServer-[:PROVIDES_TOOL]->MCPTool path;
//     without it the scoped query emits nothing. Agent-scoping also makes this
//     test hermetic — sinks under other agents/scans are never collected, so
//     the assertion is stable regardless of foreign graph data.
//
// We deliberately do NOT assert any per-agent <= 200 bound — shadows.go does
// not enforce that. The 200 figure is the operator runtime heuristic in
// scripts/perf-check.sh; the per-(agent, source) cap below is the real invariant.
func TestIntegrationPoisonsContextPerSourceCap(t *testing.T) {
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

	db := graph.NewDB(graph.NewReader(driver), graph.NewWriter(driver))

	// seedSource builds a full agent co-residency path — one AgentInstance
	// trusting one MCPServer that provides an injection-bearing source plus
	// `sinkCount` eligible high-capability sinks — under the given scan, runs
	// Shadows, and returns the number of POISONS_CONTEXT edges from that source.
	seedSource := func(t *testing.T, scanID, srcID string, sinkCount int) int {
		t.Helper()
		cleanup := func() {
			_, _ = db.ExecuteWrite(ctx,
				"MATCH (n) WHERE n.scan_id = $sid DETACH DELETE n",
				map[string]any{"sid": scanID})
		}
		cleanup()
		t.Cleanup(cleanup)

		agentID := srcID + "-agent"
		srvID := srcID + "-srv"
		nodes := []ingest.Node{
			{ID: agentID, Kinds: []string{"AgentInstance"}, Properties: map[string]any{
				"objectid": agentID, "name": "host_agent", "scan_id": scanID,
			}},
			{ID: srvID, Kinds: []string{"MCPServer"}, Properties: map[string]any{
				"objectid": srvID, "name": "host_server", "scan_id": scanID,
			}},
			// The source bears injection patterns but carries no eligible
			// capability itself, so it never counts as its own sink.
			{ID: srcID, Kinds: []string{"MCPTool"}, Properties: map[string]any{
				"objectid": srcID, "name": "poisoner",
				"has_injection_patterns": true,
				"capability_surface":     []string{"database_access"},
				"scan_id":                scanID,
			}},
		}
		edges := []ingest.Edge{
			{Source: agentID, Target: srvID, Kind: "TRUSTS_SERVER", SourceKind: "AgentInstance", TargetKind: "MCPServer"},
			{Source: srvID, Target: srcID, Kind: "PROVIDES_TOOL", SourceKind: "MCPServer", TargetKind: "MCPTool"},
		}
		for i := 0; i < sinkCount; i++ {
			id := fmt.Sprintf("%s-snk-%02d", srcID, i)
			nodes = append(nodes, ingest.Node{
				ID: id, Kinds: []string{"MCPTool"}, Properties: map[string]any{
					"objectid": id, "name": fmt.Sprintf("sink_%02d", i),
					"has_injection_patterns": false,
					"capability_surface":     []string{"shell_access"},
					"scan_id":                scanID,
				},
			})
			edges = append(edges, ingest.Edge{
				Source: srvID, Target: id, Kind: "PROVIDES_TOOL", SourceKind: "MCPServer", TargetKind: "MCPTool",
			})
		}
		writer := graph.NewWriter(driver)
		if _, err := writer.WriteNodes(ctx, managedProcessorNodes(nodes), scanID); err != nil {
			t.Fatalf("write nodes: %v", err)
		}
		if _, err := writer.WriteEdges(ctx, managedProcessorEdges(edges), scanID); err != nil {
			t.Fatalf("write edges: %v", err)
		}

		if _, err := (&Shadows{}).Process(ctx, db, scanID); err != nil {
			t.Fatalf("shadows process: %v", err)
		}

		rows, err := db.Query(ctx,
			"MATCH (s:MCPTool {objectid:$id})-[:POISONS_CONTEXT]->(:MCPTool) RETURN count(*) AS n",
			map[string]any{"id": srcID})
		if err != nil {
			t.Fatalf("query poisons_context: %v", err)
		}
		return toInt(rows[0]["n"])
	}

	// AT-CAP: exactly 20 eligible sinks -> all 20 edges emitted.
	if got := seedSource(t, "test-poisons-atcap", "pc-atcap-src", 20); got != 20 {
		t.Errorf("at-cap source (20 sinks) emitted %d POISONS_CONTEXT edges, want 20", got)
	}

	// OVER-CAP canary: 21 eligible sinks -> TRUNCATED to 20, never zero. If
	// someone reverts to the suppressing `WHERE size(sinks) <= 20` guard,
	// this flips to 0 and fails loudly; if the cap is removed entirely it
	// flips to 21 and also fails. Either way the truncation invariant holds.
	if got := seedSource(t, "test-poisons-overcap", "pc-overcap-src", 21); got != 20 {
		t.Errorf("over-cap source (21 sinks) emitted %d POISONS_CONTEXT edges, want 20 (truncate-not-suppress)", got)
	}
}
