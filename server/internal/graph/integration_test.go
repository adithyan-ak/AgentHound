package graph

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

func skipIfNoNeo4j(t *testing.T) {
	t.Helper()
	if os.Getenv("AGENTHOUND_NEO4J_URI") == "" {
		t.Skip("skipping integration test: AGENTHOUND_NEO4J_URI not set")
	}
}

func testDriver(t *testing.T) context.Context {
	t.Helper()
	skipIfNoNeo4j(t)
	return context.Background()
}

func TestIntegrationSchemaInit(t *testing.T) {
	ctx := testDriver(t)

	uri := os.Getenv("AGENTHOUND_NEO4J_URI")
	user := os.Getenv("AGENTHOUND_NEO4J_USER")
	pass := os.Getenv("AGENTHOUND_NEO4J_PASSWORD")

	driver, err := NewDriver(uri, user, pass)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer driver.Close(ctx)

	// Should succeed on first run
	if err := InitSchema(ctx, driver); err != nil {
		t.Fatalf("init schema: %v", err)
	}

	// Should be idempotent
	if err := InitSchema(ctx, driver); err != nil {
		t.Fatalf("init schema (idempotent): %v", err)
	}
}

func TestIntegrationVersionDetection(t *testing.T) {
	ctx := testDriver(t)

	uri := os.Getenv("AGENTHOUND_NEO4J_URI")
	user := os.Getenv("AGENTHOUND_NEO4J_USER")
	pass := os.Getenv("AGENTHOUND_NEO4J_PASSWORD")

	driver, err := NewDriver(uri, user, pass)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer driver.Close(ctx)

	major, minor, err := DetectVersion(ctx, driver)
	if err != nil {
		t.Fatalf("detect version: %v", err)
	}

	if major < 4 {
		t.Errorf("expected major >= 4, got %d.%d", major, minor)
	}
	t.Logf("Neo4j version: %d.%d", major, minor)
}

func TestIntegrationWriteAndRead(t *testing.T) {
	ctx := testDriver(t)

	uri := os.Getenv("AGENTHOUND_NEO4J_URI")
	user := os.Getenv("AGENTHOUND_NEO4J_USER")
	pass := os.Getenv("AGENTHOUND_NEO4J_PASSWORD")

	driver, err := NewDriver(uri, user, pass)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer driver.Close(ctx)

	if err := InitSchema(ctx, driver); err != nil {
		t.Fatalf("schema: %v", err)
	}

	// Clean up test data
	reader := NewReader(driver)
	_, _ = reader.Query(ctx, "MATCH (n) WHERE n.scan_id = 'test-integration' DETACH DELETE n", nil)

	writer := NewWriter(driver)

	nodes := []ingest.Node{
		{ID: "test-srv-001", Kinds: []string{"MCPServer"}, Properties: map[string]any{
			"objectid": "test-srv-001", "name": "test-server", "transport": "stdio",
		}},
		{ID: "test-tool-001", Kinds: []string{"MCPTool"}, Properties: map[string]any{
			"objectid": "test-tool-001", "name": "execute_sql", "description_hash": "abc123",
		}},
	}

	nWritten, err := writer.WriteNodes(ctx, nodes, "test-integration")
	if err != nil {
		t.Fatalf("write nodes: %v", err)
	}
	if nWritten != 2 {
		t.Errorf("nodes written: got %d, want 2", nWritten)
	}

	edges := []ingest.Edge{
		{Source: "test-srv-001", Target: "test-tool-001", Kind: "PROVIDES_TOOL", Properties: map[string]any{
			"confidence": 1.0, "is_composite": false,
		}},
	}

	eWritten, err := writer.WriteEdges(ctx, edges, "test-integration")
	if err != nil {
		t.Fatalf("write edges: %v", err)
	}
	if eWritten != 1 {
		t.Errorf("edges written: got %d, want 1", eWritten)
	}

	// Read back
	node, nodeEdges, err := reader.GetNode(ctx, "test-srv-001")
	if err != nil {
		t.Fatalf("get node: %v", err)
	}
	if node == nil {
		t.Fatal("node not found")
	}
	if node.Properties["name"] != "test-server" {
		t.Errorf("name: got %v, want test-server", node.Properties["name"])
	}
	if len(nodeEdges) != 1 {
		t.Errorf("edges: got %d, want 1", len(nodeEdges))
	}

	// Stats
	stats, err := reader.GetStats(ctx)
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if stats.TotalNodes < 2 {
		t.Errorf("total nodes: got %d, want >= 2", stats.TotalNodes)
	}

	// Merge test: overwrite node with new properties
	updatedNodes := []ingest.Node{
		{ID: "test-srv-001", Kinds: []string{"MCPServer"}, Properties: map[string]any{
			"objectid": "test-srv-001", "name": "test-server-updated", "protocol_version": "2025-11-05",
		}},
	}
	nWritten, err = writer.WriteNodes(ctx, updatedNodes, "test-integration")
	if err != nil {
		t.Fatalf("merge nodes: %v", err)
	}
	if nWritten != 1 {
		t.Errorf("merge written: got %d, want 1", nWritten)
	}

	// Verify merge
	node, _, err = reader.GetNode(ctx, "test-srv-001")
	if err != nil {
		t.Fatalf("get merged node: %v", err)
	}
	if node.Properties["name"] != "test-server-updated" {
		t.Errorf("merged name: got %v, want test-server-updated", node.Properties["name"])
	}
	if node.Properties["protocol_version"] != "2025-11-05" {
		t.Errorf("new property missing: %v", node.Properties)
	}

	// Clean up
	_, _ = reader.Query(ctx, "MATCH (n) WHERE n.scan_id = 'test-integration' DETACH DELETE n", nil)
}

func TestIntegrationEmptyGraph(t *testing.T) {
	ctx := testDriver(t)

	uri := os.Getenv("AGENTHOUND_NEO4J_URI")
	user := os.Getenv("AGENTHOUND_NEO4J_USER")
	pass := os.Getenv("AGENTHOUND_NEO4J_PASSWORD")

	driver, err := NewDriver(uri, user, pass)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer driver.Close(ctx)

	writer := NewWriter(driver)

	// Writing empty slices should succeed
	n, err := writer.WriteNodes(ctx, nil, "test-empty")
	if err != nil {
		t.Fatalf("write empty nodes: %v", err)
	}
	if n != 0 {
		t.Errorf("expected 0 nodes written, got %d", n)
	}

	e, err := writer.WriteEdges(ctx, nil, "test-empty")
	if err != nil {
		t.Fatalf("write empty edges: %v", err)
	}
	if e != 0 {
		t.Errorf("expected 0 edges written, got %d", e)
	}
}

func TestIntegrationListNodes(t *testing.T) {
	ctx := testDriver(t)

	uri := os.Getenv("AGENTHOUND_NEO4J_URI")
	user := os.Getenv("AGENTHOUND_NEO4J_USER")
	pass := os.Getenv("AGENTHOUND_NEO4J_PASSWORD")

	driver, err := NewDriver(uri, user, pass)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer driver.Close(ctx)

	if err := InitSchema(ctx, driver); err != nil {
		t.Fatalf("schema: %v", err)
	}

	reader := NewReader(driver)

	// List with invalid kind should error
	_, err = reader.ListNodes(ctx, "InvalidKind", 10)
	if err == nil {
		t.Error("expected error for invalid kind")
	}

	// List with valid kind should work (even if empty)
	nodes, err := reader.ListNodes(ctx, "MCPServer", 10)
	if err != nil {
		t.Fatalf("list nodes: %v", err)
	}
	t.Logf("MCPServer nodes: %d", len(nodes))
}

func TestIntegrationReaderPing(t *testing.T) {
	ctx := testDriver(t)

	uri := os.Getenv("AGENTHOUND_NEO4J_URI")
	user := os.Getenv("AGENTHOUND_NEO4J_USER")
	pass := os.Getenv("AGENTHOUND_NEO4J_PASSWORD")

	driver, err := NewDriver(uri, user, pass)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer driver.Close(ctx)

	reader := NewReader(driver)
	if err := reader.Ping(ctx); err != nil {
		t.Fatalf("ping: %v", err)
	}
}

func TestIntegrationReaderListEdges(t *testing.T) {
	ctx := testDriver(t)

	uri := os.Getenv("AGENTHOUND_NEO4J_URI")
	user := os.Getenv("AGENTHOUND_NEO4J_USER")
	pass := os.Getenv("AGENTHOUND_NEO4J_PASSWORD")

	driver, err := NewDriver(uri, user, pass)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer driver.Close(ctx)

	if err := InitSchema(ctx, driver); err != nil {
		t.Fatalf("schema: %v", err)
	}

	reader := NewReader(driver)
	writer := NewWriter(driver)

	// Clean up any leftover test data
	_, _ = reader.Query(ctx, "MATCH (n) WHERE n.scan_id = 'test-listedges' DETACH DELETE n", nil)

	nodes := []ingest.Node{
		{ID: "test-edge-srv-001", Kinds: []string{"MCPServer"}, Properties: map[string]any{
			"objectid": "test-edge-srv-001", "name": "edge-test-server", "transport": "stdio",
		}},
		{ID: "test-edge-tool-001", Kinds: []string{"MCPTool"}, Properties: map[string]any{
			"objectid": "test-edge-tool-001", "name": "edge-test-tool",
		}},
	}
	if _, err := writer.WriteNodes(ctx, nodes, "test-listedges"); err != nil {
		t.Fatalf("write nodes: %v", err)
	}

	edges := []ingest.Edge{
		{Source: "test-edge-srv-001", Target: "test-edge-tool-001", Kind: "PROVIDES_TOOL", Properties: map[string]any{
			"confidence": 1.0, "is_composite": false,
		}},
	}
	if _, err := writer.WriteEdges(ctx, edges, "test-listedges"); err != nil {
		t.Fatalf("write edges: %v", err)
	}

	// List by kind
	listed, err := reader.ListEdges(ctx, "PROVIDES_TOOL", "", "", 10)
	if err != nil {
		t.Fatalf("list edges by kind: %v", err)
	}
	if len(listed) < 1 {
		t.Error("expected at least 1 PROVIDES_TOOL edge")
	}

	// List by source
	listed, err = reader.ListEdges(ctx, "", "test-edge-srv-001", "", 10)
	if err != nil {
		t.Fatalf("list edges by source: %v", err)
	}
	if len(listed) < 1 {
		t.Error("expected at least 1 edge from test-edge-srv-001")
	}
	for _, e := range listed {
		if e.Source != "test-edge-srv-001" {
			t.Errorf("source: got %q, want test-edge-srv-001", e.Source)
		}
	}

	// Invalid kind should error
	_, err = reader.ListEdges(ctx, "InvalidEdge", "", "", 10)
	if err == nil {
		t.Error("expected error for invalid edge kind")
	}

	// Clean up
	_, _ = reader.Query(ctx, "MATCH (n) WHERE n.scan_id = 'test-listedges' DETACH DELETE n", nil)
}

func TestIntegrationReaderQuery(t *testing.T) {
	ctx := testDriver(t)

	uri := os.Getenv("AGENTHOUND_NEO4J_URI")
	user := os.Getenv("AGENTHOUND_NEO4J_USER")
	pass := os.Getenv("AGENTHOUND_NEO4J_PASSWORD")

	driver, err := NewDriver(uri, user, pass)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer driver.Close(ctx)

	if err := InitSchema(ctx, driver); err != nil {
		t.Fatalf("schema: %v", err)
	}

	reader := NewReader(driver)
	writer := NewWriter(driver)

	// Clean up any leftover test data
	_, _ = reader.Query(ctx, "MATCH (n) WHERE n.scan_id = 'test-query' DETACH DELETE n", nil)

	nodes := []ingest.Node{
		{ID: "test-query-001", Kinds: []string{"MCPServer"}, Properties: map[string]any{
			"objectid": "test-query-001", "name": "query-test-server", "transport": "http",
		}},
	}
	if _, err := writer.WriteNodes(ctx, nodes, "test-query"); err != nil {
		t.Fatalf("write nodes: %v", err)
	}

	rows, err := reader.Query(ctx, "MATCH (n {objectid: $id}) RETURN n.name AS name", map[string]any{"id": "test-query-001"})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows: got %d, want 1", len(rows))
	}
	name, ok := rows[0]["name"]
	if !ok {
		t.Fatal("row missing 'name' key")
	}
	if name != "query-test-server" {
		t.Errorf("name: got %v, want query-test-server", name)
	}

	// Clean up
	_, _ = reader.Query(ctx, "MATCH (n) WHERE n.scan_id = 'test-query' DETACH DELETE n", nil)
}

func TestIntegrationWriterBatchSplit(t *testing.T) {
	ctx := testDriver(t)

	uri := os.Getenv("AGENTHOUND_NEO4J_URI")
	user := os.Getenv("AGENTHOUND_NEO4J_USER")
	pass := os.Getenv("AGENTHOUND_NEO4J_PASSWORD")

	driver, err := NewDriver(uri, user, pass)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer driver.Close(ctx)

	if err := InitSchema(ctx, driver); err != nil {
		t.Fatalf("schema: %v", err)
	}

	reader := NewReader(driver)
	writer := NewWriter(driver)

	// Clean up any leftover test data
	_, _ = reader.Query(ctx, "MATCH (n) WHERE n.scan_id = 'test-batch' DETACH DELETE n", nil)

	const nodeCount = 1050
	nodes := make([]ingest.Node, nodeCount)
	for i := range nodes {
		id := fmt.Sprintf("test-batch-%04d", i)
		nodes[i] = ingest.Node{
			ID:    id,
			Kinds: []string{"MCPTool"},
			Properties: map[string]any{
				"objectid": id,
				"name":     fmt.Sprintf("batch-tool-%04d", i),
			},
		}
	}

	nWritten, err := writer.WriteNodes(ctx, nodes, "test-batch")
	if err != nil {
		t.Fatalf("write batch nodes: %v", err)
	}
	if nWritten != nodeCount {
		t.Errorf("nodes written: got %d, want %d", nWritten, nodeCount)
	}

	// Verify via count query
	rows, err := reader.Query(ctx, "MATCH (n) WHERE n.scan_id = 'test-batch' RETURN count(n) AS cnt", nil)
	if err != nil {
		t.Fatalf("count query: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("count rows: got %d, want 1", len(rows))
	}
	cnt, _ := rows[0]["cnt"].(int64)
	if cnt != nodeCount {
		t.Errorf("node count in db: got %d, want %d", cnt, nodeCount)
	}

	// Clean up
	_, _ = reader.Query(ctx, "MATCH (n) WHERE n.scan_id = 'test-batch' DETACH DELETE n", nil)
}

func TestIntegrationWriterEdgesFallback(t *testing.T) {
	ctx := testDriver(t)

	uri := os.Getenv("AGENTHOUND_NEO4J_URI")
	user := os.Getenv("AGENTHOUND_NEO4J_USER")
	pass := os.Getenv("AGENTHOUND_NEO4J_PASSWORD")

	driver, err := NewDriver(uri, user, pass)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer driver.Close(ctx)

	if err := InitSchema(ctx, driver); err != nil {
		t.Fatalf("schema: %v", err)
	}

	reader := NewReader(driver)
	writer := NewWriter(driver)

	// Clean up any leftover test data
	_, _ = reader.Query(ctx, "MATCH (n) WHERE n.scan_id = 'test-fallback' DETACH DELETE n", nil)

	nodes := []ingest.Node{
		{ID: "test-fb-srv-001", Kinds: []string{"MCPServer"}, Properties: map[string]any{
			"objectid": "test-fb-srv-001", "name": "fallback-server", "transport": "stdio",
		}},
		{ID: "test-fb-tool-001", Kinds: []string{"MCPTool"}, Properties: map[string]any{
			"objectid": "test-fb-tool-001", "name": "fallback-tool",
		}},
	}
	if _, err := writer.WriteNodes(ctx, nodes, "test-fallback"); err != nil {
		t.Fatalf("write nodes: %v", err)
	}

	// Force fallback path by disabling APOC
	writer.hasAPOC = false
	writer.apocOnce.Do(func() {}) // prevent re-detection

	edges := []ingest.Edge{
		{Source: "test-fb-srv-001", Target: "test-fb-tool-001", Kind: "PROVIDES_TOOL", Properties: map[string]any{
			"confidence": 0.9, "is_composite": false,
		}},
	}

	eWritten, err := writer.WriteEdges(ctx, edges, "test-fallback")
	if err != nil {
		t.Fatalf("write edges fallback: %v", err)
	}
	if eWritten != 1 {
		t.Errorf("edges written: got %d, want 1", eWritten)
	}

	// Verify edge exists by reading it back
	listed, err := reader.ListEdges(ctx, "PROVIDES_TOOL", "test-fb-srv-001", "", 10)
	if err != nil {
		t.Fatalf("list edges: %v", err)
	}
	found := false
	for _, e := range listed {
		if e.Source == "test-fb-srv-001" && e.Target == "test-fb-tool-001" {
			found = true
			break
		}
	}
	if !found {
		t.Error("fallback-written edge not found")
	}

	// Clean up
	_, _ = reader.Query(ctx, "MATCH (n) WHERE n.scan_id = 'test-fallback' DETACH DELETE n", nil)
}

func TestIntegrationReaderBlastRadius(t *testing.T) {
	ctx := testDriver(t)

	uri := os.Getenv("AGENTHOUND_NEO4J_URI")
	user := os.Getenv("AGENTHOUND_NEO4J_USER")
	pass := os.Getenv("AGENTHOUND_NEO4J_PASSWORD")

	driver, err := NewDriver(uri, user, pass)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer driver.Close(ctx)

	if err := InitSchema(ctx, driver); err != nil {
		t.Fatalf("schema: %v", err)
	}

	reader := NewReader(driver)
	writer := NewWriter(driver)

	// Clean up any leftover test data
	_, _ = reader.Query(ctx, "MATCH (n) WHERE n.scan_id = 'test-blast' DETACH DELETE n", nil)

	// Build a chain: agent -> server -> tool -> resource
	// plus an unrelated island node to prove it isn't included.
	nodes := []ingest.Node{
		{ID: "blast-agent-001", Kinds: []string{"AgentInstance"}, Properties: map[string]any{
			"objectid": "blast-agent-001", "name": "blast-agent",
		}},
		{ID: "blast-srv-001", Kinds: []string{"MCPServer"}, Properties: map[string]any{
			"objectid": "blast-srv-001", "name": "blast-srv", "transport": "stdio",
		}},
		{ID: "blast-tool-001", Kinds: []string{"MCPTool"}, Properties: map[string]any{
			"objectid": "blast-tool-001", "name": "blast-tool",
		}},
		{ID: "blast-res-001", Kinds: []string{"MCPResource"}, Properties: map[string]any{
			"objectid": "blast-res-001", "name": "blast-res", "uri": "file:///secret",
		}},
		{ID: "blast-island-001", Kinds: []string{"MCPServer"}, Properties: map[string]any{
			"objectid": "blast-island-001", "name": "blast-island", "transport": "stdio",
		}},
	}
	if _, err := writer.WriteNodes(ctx, nodes, "test-blast"); err != nil {
		t.Fatalf("write nodes: %v", err)
	}

	edges := []ingest.Edge{
		{Source: "blast-agent-001", Target: "blast-srv-001", Kind: "TRUSTS_SERVER", Properties: map[string]any{"confidence": 1.0}},
		{Source: "blast-srv-001", Target: "blast-tool-001", Kind: "PROVIDES_TOOL", Properties: map[string]any{"confidence": 1.0}},
		{Source: "blast-tool-001", Target: "blast-res-001", Kind: "HAS_ACCESS_TO", Properties: map[string]any{"confidence": 0.9, "is_composite": true}},
	}
	if _, err := writer.WriteEdges(ctx, edges, "test-blast"); err != nil {
		t.Fatalf("write edges: %v", err)
	}

	// Outbound blast radius from the agent should hit 3 more nodes at hops 1..3.
	result, err := reader.GetBlastRadius(ctx, "blast-agent-001", "out", 5)
	if err != nil {
		t.Fatalf("blast radius: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil blast result")
	}
	if len(result.Nodes) != 4 {
		t.Errorf("node count: got %d, want 4 (agent + srv + tool + res)", len(result.Nodes))
	}
	if len(result.Edges) < 3 {
		t.Errorf("edge count: got %d, want >= 3", len(result.Edges))
	}

	// Center must be ring 0
	if got := result.Rings[0]; len(got) != 1 || got[0] != "blast-agent-001" {
		t.Errorf("ring 0: got %v, want [blast-agent-001]", got)
	}
	// Ring 1 should contain the server
	if got := result.Rings[1]; len(got) != 1 || got[0] != "blast-srv-001" {
		t.Errorf("ring 1: got %v, want [blast-srv-001]", got)
	}
	// Ring 2 should contain the tool
	if got := result.Rings[2]; len(got) != 1 || got[0] != "blast-tool-001" {
		t.Errorf("ring 2: got %v, want [blast-tool-001]", got)
	}
	// Ring 3 should contain the resource
	if got := result.Rings[3]; len(got) != 1 || got[0] != "blast-res-001" {
		t.Errorf("ring 3: got %v, want [blast-res-001]", got)
	}

	// Island must not appear
	for _, n := range result.Nodes {
		if n.ID == "blast-island-001" {
			t.Error("unrelated island node leaked into blast radius result")
		}
	}

	// Inbound direction from the resource should walk back up.
	inResult, err := reader.GetBlastRadius(ctx, "blast-res-001", "in", 5)
	if err != nil {
		t.Fatalf("blast radius inbound: %v", err)
	}
	if inResult == nil || len(inResult.Nodes) != 4 {
		t.Errorf("inbound node count: got %d, want 4", len(inResult.Nodes))
	}

	// Nonexistent node returns nil.
	missing, err := reader.GetBlastRadius(ctx, "blast-nonexistent-999", "out", 5)
	if err != nil {
		t.Fatalf("blast radius nonexistent: %v", err)
	}
	if missing != nil {
		t.Error("expected nil result for nonexistent source node")
	}

	// maxHops clamping: request 99, should not error.
	_, err = reader.GetBlastRadius(ctx, "blast-agent-001", "out", 99)
	if err != nil {
		t.Fatalf("blast radius maxHops clamping: %v", err)
	}

	// Unknown direction is normalized to "out" (no error).
	_, err = reader.GetBlastRadius(ctx, "blast-agent-001", "sideways", 5)
	if err != nil {
		t.Fatalf("blast radius unknown direction: %v", err)
	}

	// Clean up
	_, _ = reader.Query(ctx, "MATCH (n) WHERE n.scan_id = 'test-blast' DETACH DELETE n", nil)
}
