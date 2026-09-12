package processors

import (
	"context"
	"os"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

func TestIntegrationPoisonedInstructionsReachOnlyExplicitDestructiveSink(t *testing.T) {
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

	const scanID = "test-poisoned-instruction-destructive-path"
	cleanup := func() {
		_, _ = db.ExecuteWrite(ctx,
			"MATCH (n) WHERE n.scan_id = $scan_id DETACH DELETE n",
			map[string]any{"scan_id": scanID})
	}
	cleanup()
	t.Cleanup(cleanup)

	nodes := []ingest.Node{
		{ID: "a-agent", Kinds: []string{"AgentInstance"}, Properties: map[string]any{
			"objectid": "a-agent", "name": "Agent A", "scan_id": scanID,
		}},
		{ID: "b-agent", Kinds: []string{"AgentInstance"}, Properties: map[string]any{
			"objectid": "b-agent", "name": "Agent B", "scan_id": scanID,
		}},
		{ID: "instruction", Kinds: []string{"InstructionFile"}, Properties: map[string]any{
			"objectid": "instruction", "path": "/work/AGENTS.md", "scan_id": scanID,
			"instruction_verdict": "poisoning", "instruction_scope": "exact_project",
		}},
		{ID: "server", Kinds: []string{"MCPServer"}, Properties: map[string]any{
			"objectid": "server", "name": "Server", "scan_id": scanID,
		}},
		{ID: "destructive", Kinds: []string{"MCPTool"}, Properties: map[string]any{
			"objectid": "destructive", "name": "Destructive", "scan_id": scanID,
			"mcp_annotation_destructive_hint": true,
		}},
		{ID: "read-only-conflict", Kinds: []string{"MCPTool"}, Properties: map[string]any{
			"objectid": "read-only-conflict", "name": "Conflict", "scan_id": scanID,
			"mcp_annotation_destructive_hint": true, "mcp_annotation_read_only_hint": true,
		}},
		{ID: "missing-hint", Kinds: []string{"MCPTool"}, Properties: map[string]any{
			"objectid": "missing-hint", "name": "delete_all", "scan_id": scanID,
		}},
	}
	edges := []ingest.Edge{
		{Source: "a-agent", Target: "instruction", Kind: "LOADS_INSTRUCTIONS", SourceKind: "AgentInstance", TargetKind: "InstructionFile"},
		{Source: "b-agent", Target: "instruction", Kind: "LOADS_INSTRUCTIONS", SourceKind: "AgentInstance", TargetKind: "InstructionFile"},
		{Source: "a-agent", Target: "server", Kind: "TRUSTS_SERVER", SourceKind: "AgentInstance", TargetKind: "MCPServer"},
		{Source: "b-agent", Target: "server", Kind: "TRUSTS_SERVER", SourceKind: "AgentInstance", TargetKind: "MCPServer"},
		{Source: "server", Target: "destructive", Kind: "PROVIDES_TOOL", SourceKind: "MCPServer", TargetKind: "MCPTool"},
		{Source: "server", Target: "read-only-conflict", Kind: "PROVIDES_TOOL", SourceKind: "MCPServer", TargetKind: "MCPTool"},
		{Source: "server", Target: "missing-hint", Kind: "PROVIDES_TOOL", SourceKind: "MCPServer", TargetKind: "MCPTool"},
	}
	writer := graph.NewWriter(driver)
	if _, err := writer.WriteNodes(ctx, managedProcessorNodes(nodes), scanID); err != nil {
		t.Fatalf("write nodes: %v", err)
	}
	if _, err := writer.WriteEdges(ctx, managedProcessorEdges(edges), scanID); err != nil {
		t.Fatalf("write edges: %v", err)
	}

	if _, err := (&PoisonedInstructions{}).Process(ctx, db, scanID); err != nil {
		t.Fatalf("process poisoned instructions: %v", err)
	}
	rows, err := db.Query(ctx, `
MATCH (:InstructionFile {objectid: 'instruction'})-[e:POISONS_CONTEXT]->(sink:MCPTool)
RETURN sink.objectid AS sink, e.evidence_node_ids AS evidence_node_ids
ORDER BY sink`, nil)
	if err != nil {
		t.Fatalf("query destructive paths: %v", err)
	}
	if len(rows) != 1 || rows[0]["sink"] != "destructive" {
		t.Fatalf("destructive instruction paths = %+v, want only explicit non-read-only sink", rows)
	}
	evidenceIDs, ok := rows[0]["evidence_node_ids"].([]any)
	if !ok || len(evidenceIDs) != 4 || evidenceIDs[0] != "a-agent" {
		t.Fatalf("deterministic evidence nodes = %#v, want a-agent witness first", rows[0]["evidence_node_ids"])
	}
}
