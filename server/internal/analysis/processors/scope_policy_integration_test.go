package processors

import (
	"context"
	"os"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

func TestIntegrationShadowsHonorsScopeCompatibility(t *testing.T) {
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

	const scanID = "test-scope-policy"
	db := graph.NewDB(graph.NewReader(driver), graph.NewWriter(driver))
	cleanup := func() {
		_, _ = db.ExecuteWrite(ctx,
			"MATCH (n) WHERE n.scan_id = $sid DETACH DELETE n",
			map[string]any{"sid": scanID})
	}
	cleanup()
	defer cleanup()

	networkProps := func(id, name, point, network string) map[string]any {
		return map[string]any{
			"objectid": id, "name": name, "scan_id": scanID,
			"identity_scope": "network_context", "identity_scope_id": network,
			"collection_point_id": point, "network_context_id": network,
		}
	}
	artifactProps := func(id, name, artifact string) map[string]any {
		return map[string]any{
			"objectid": id, "name": name, "scan_id": scanID,
			"identity_scope": "artifact", "identity_scope_id": artifact,
			"artifact_scope_id": artifact,
		}
	}
	nodes := []ingest.Node{
		{ID: "scope-server-source", Kinds: []string{"MCPServer"}, Properties: networkProps("scope-server-source", "source-server", "point-a", "network-a")},
		{ID: "scope-server-same", Kinds: []string{"MCPServer"}, Properties: networkProps("scope-server-same", "same-server", "point-a", "network-a")},
		{ID: "scope-server-other", Kinds: []string{"MCPServer"}, Properties: networkProps("scope-server-other", "other-server", "point-b", "network-b")},
		{ID: "scope-tool-source", Kinds: []string{"MCPTool"}, Properties: networkProps("scope-tool-source", "source", "point-a", "network-a")},
		{ID: "scope-tool-same", Kinds: []string{"MCPTool"}, Properties: networkProps("scope-tool-same", "same_target", "point-a", "network-a")},
		{ID: "scope-tool-other", Kinds: []string{"MCPTool"}, Properties: networkProps("scope-tool-other", "other_target", "point-b", "network-b")},
		{ID: "scope-server-weak-a", Kinds: []string{"MCPServer"}, Properties: artifactProps("scope-server-weak-a", "weak-a", "artifact-a")},
		{ID: "scope-server-weak-b", Kinds: []string{"MCPServer"}, Properties: artifactProps("scope-server-weak-b", "weak-b", "artifact-b")},
		{ID: "scope-tool-weak-source", Kinds: []string{"MCPTool"}, Properties: artifactProps("scope-tool-weak-source", "weak_source", "artifact-a")},
		{ID: "scope-tool-weak-target", Kinds: []string{"MCPTool"}, Properties: artifactProps("scope-tool-weak-target", "weak_target", "artifact-b")},
	}
	nodes[3].Properties["description"] = "Use same_target or other_target."
	nodes[8].Properties["description"] = "Use weak_target."

	writer := graph.NewWriter(driver)
	if _, err := writer.WriteNodes(ctx, managedProcessorNodes(nodes), scanID); err != nil {
		t.Fatalf("write nodes: %v", err)
	}
	edges := []ingest.Edge{
		{Source: "scope-server-source", Target: "scope-tool-source", Kind: "PROVIDES_TOOL", SourceKind: "MCPServer", TargetKind: "MCPTool"},
		{Source: "scope-server-same", Target: "scope-tool-same", Kind: "PROVIDES_TOOL", SourceKind: "MCPServer", TargetKind: "MCPTool"},
		{Source: "scope-server-other", Target: "scope-tool-other", Kind: "PROVIDES_TOOL", SourceKind: "MCPServer", TargetKind: "MCPTool"},
		{Source: "scope-server-weak-a", Target: "scope-tool-weak-source", Kind: "PROVIDES_TOOL", SourceKind: "MCPServer", TargetKind: "MCPTool"},
		{Source: "scope-server-weak-b", Target: "scope-tool-weak-target", Kind: "PROVIDES_TOOL", SourceKind: "MCPServer", TargetKind: "MCPTool"},
	}
	if _, err := writer.WriteEdges(ctx, managedProcessorEdges(edges), scanID); err != nil {
		t.Fatalf("write edges: %v", err)
	}
	if _, err := (&Shadows{}).Process(ctx, db, scanID); err != nil {
		t.Fatalf("shadows process: %v", err)
	}

	rows, err := db.Query(ctx, `
MATCH (:MCPTool {objectid:'scope-tool-source'})-[r:SHADOWS]->(target:MCPTool)
RETURN collect(target.objectid) AS targets`, nil)
	if err != nil {
		t.Fatalf("query network results: %v", err)
	}
	targets, _ := rows[0]["targets"].([]any)
	if len(targets) != 1 || targets[0] != "scope-tool-same" {
		t.Fatalf("network-scoped SHADOWS targets = %v, want only scope-tool-same", targets)
	}

	rows, err = db.Query(ctx, `
MATCH (:MCPTool {objectid:'scope-tool-weak-source'})-[r:SHADOWS]->(:MCPTool)
RETURN count(r) AS n`, nil)
	if err != nil {
		t.Fatalf("query weak results: %v", err)
	}
	if got := toInt(rows[0]["n"]); got != 0 {
		t.Fatalf("cross-artifact weak SHADOWS edges = %d, want 0", got)
	}
}
