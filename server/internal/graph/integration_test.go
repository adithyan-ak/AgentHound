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

func TestIntegrationPublicInventoryExcludesInternalAndReservedNodes(t *testing.T) {
	ctx := testDriver(t)
	driver, err := NewDriver(
		os.Getenv("AGENTHOUND_NEO4J_URI"),
		os.Getenv("AGENTHOUND_NEO4J_USER"),
		os.Getenv("AGENTHOUND_NEO4J_PASSWORD"),
	)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer driver.Close(ctx)
	if err := InitSchema(ctx, driver); err != nil {
		t.Fatalf("schema: %v", err)
	}

	reader := NewReader(driver)
	const prefix = "public-inventory-exclusion-seed"
	ids := []string{
		prefix + "-public",
		prefix + "-schema",
		prefix + "-resource-group",
		prefix + "-trust-zone",
	}
	cleanup := func() {
		_, _ = reader.Query(
			ctx,
			"MATCH (n) WHERE n.objectid IN $ids DETACH DELETE n",
			map[string]any{"ids": ids},
		)
	}
	cleanup()
	defer cleanup()

	beforeStats, err := reader.GetStats(ctx)
	if err != nil {
		t.Fatalf("stats before seed: %v", err)
	}
	_, beforePage, err := reader.ListNodesPage(ctx, "", 1, 0, "")
	if err != nil {
		t.Fatalf("node page before seed: %v", err)
	}

	_, err = reader.Query(ctx, `
CREATE (:MCPServer {objectid: $public_id, name: $public_name})
CREATE (:SchemaVersion {objectid: $schema_id, name: $schema_name})
CREATE (:ResourceGroup {objectid: $group_id, name: $group_name})
CREATE (:TrustZone {objectid: $zone_id, name: $zone_name})`, map[string]any{
		"public_id":   ids[0],
		"schema_id":   ids[1],
		"group_id":    ids[2],
		"zone_id":     ids[3],
		"public_name": prefix + "-public",
		"schema_name": prefix + "-schema",
		"group_name":  prefix + "-resource-group",
		"zone_name":   prefix + "-trust-zone",
	})
	if err != nil {
		t.Fatalf("seed inventory nodes: %v", err)
	}

	afterStats, err := reader.GetStats(ctx)
	if err != nil {
		t.Fatalf("stats after seed: %v", err)
	}
	if afterStats.TotalNodes != beforeStats.TotalNodes+1 {
		t.Fatalf(
			"public total changed by %d, want 1; internal/reserved nodes leaked",
			afterStats.TotalNodes-beforeStats.TotalNodes,
		)
	}
	for _, internal := range []string{"SchemaVersion", "ResourceGroup", "TrustZone"} {
		if _, ok := afterStats.NodeCounts[internal]; ok {
			t.Fatalf("internal/reserved kind %q leaked into stats: %+v", internal, afterStats.NodeCounts)
		}
	}

	_, afterPage, err := reader.ListNodesPage(ctx, "", 1, 0, "")
	if err != nil {
		t.Fatalf("node page after seed: %v", err)
	}
	if afterPage.Total != beforePage.Total+1 {
		t.Fatalf(
			"public node-list total changed by %d, want 1",
			afterPage.Total-beforePage.Total,
		)
	}

	results, err := reader.SearchNodes(ctx, prefix, 10)
	if err != nil {
		t.Fatalf("search seeded inventory: %v", err)
	}
	if len(results) != 1 || results[0].ID != ids[0] {
		t.Fatalf("public search results = %+v, want only %q", results, ids[0])
	}
	for _, internalID := range ids[1:] {
		node, _, err := reader.GetNode(ctx, internalID)
		if err != nil {
			t.Fatalf("get internal node %q: %v", internalID, err)
		}
		if node != nil {
			t.Fatalf("internal/reserved node %q leaked from public get", internalID)
		}
	}
}

func TestIntegrationObservationReconciliation(t *testing.T) {
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
	db := NewDB(reader, writer)
	ids := []string{"reconcile-srv", "reconcile-tool", "reconcile-shared"}
	_, _ = reader.Query(ctx,
		`MATCH (n) WHERE n.objectid IN $ids DETACH DELETE n`,
		map[string]any{"ids": ids},
	)
	defer func() {
		_, _ = reader.Query(ctx,
			`MATCH (n) WHERE n.objectid IN $ids DETACH DELETE n`,
			map[string]any{"ids": ids},
		)
	}()

	nodes := []ingest.Node{
		{
			ID: "reconcile-srv", Kinds: []string{"MCPServer"},
			ObservationDomains: []string{"mcp"},
		},
		{
			ID: "reconcile-tool", Kinds: []string{"MCPTool"},
			ObservationDomains: []string{"mcp"},
		},
		{
			ID: "reconcile-shared", Kinds: []string{"Host"},
			ObservationDomains: []string{"config", "mcp"},
		},
	}
	if _, err := writer.WriteNodes(ctx, nodes, "reconcile-old"); err != nil {
		t.Fatalf("write nodes: %v", err)
	}
	if _, err := writer.WriteEdges(ctx, []ingest.Edge{{
		Source: "reconcile-srv", Target: "reconcile-tool", Kind: "PROVIDES_TOOL",
		ObservationDomains: []string{"mcp"},
	}}, "reconcile-old"); err != nil {
		t.Fatalf("write edge: %v", err)
	}

	if _, err := ReconcileObservations(ctx, db, "reconcile-current", []string{"mcp"}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	rows, err := reader.Query(ctx, `MATCH (n)
	WHERE n.objectid IN $ids
	RETURN collect(n.objectid) AS ids, collect(n.observation_tokens) AS tokens`,
		map[string]any{"ids": ids},
	)
	if err != nil {
		t.Fatalf("query reconciled nodes: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %v", rows)
	}
	gotIDs, _ := rows[0]["ids"].([]any)
	if len(gotIDs) != 1 || gotIDs[0] != "reconcile-shared" {
		t.Fatalf("remaining ids = %v, want shared node only", gotIDs)
	}
	tokenSets, _ := rows[0]["tokens"].([]any)
	if len(tokenSets) != 1 {
		t.Fatalf("remaining token sets = %v", tokenSets)
	}
	sharedTokens, _ := tokenSets[0].([]any)
	if len(sharedTokens) != 1 || sharedTokens[0] != "config\x1freconcile-old" {
		t.Fatalf("shared tokens = %v, want config owner", sharedTokens)
	}
	edgeRows, err := reader.Query(ctx,
		`MATCH ()-[r:PROVIDES_TOOL]->() WHERE r.scan_id = 'reconcile-old' RETURN count(r) AS count`,
		nil,
	)
	if err != nil {
		t.Fatalf("query stale edges: %v", err)
	}
	if count, _ := edgeRows[0]["count"].(int64); count != 0 {
		t.Fatalf("stale relationship count = %d, want 0", count)
	}
}

func TestIntegrationCompleteObservationReplacesStaleManagedProperties(t *testing.T) {
	ctx := testDriver(t)
	driver, err := NewDriver(
		os.Getenv("AGENTHOUND_NEO4J_URI"),
		os.Getenv("AGENTHOUND_NEO4J_USER"),
		os.Getenv("AGENTHOUND_NEO4J_PASSWORD"),
	)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer driver.Close(ctx)

	reader := NewReader(driver)
	writer := NewWriter(driver)
	scope := "mcp:target:sha256:property-replacement"
	ids := []string{"managed-property-replacement", "legacy-property-migration"}
	_, _ = reader.Query(
		ctx,
		`MATCH (n) WHERE n.objectid IN $ids DETACH DELETE n`,
		map[string]any{"ids": ids},
	)
	defer func() {
		_, _ = reader.Query(
			ctx,
			`MATCH (n) WHERE n.objectid IN $ids DETACH DELETE n`,
			map[string]any{"ids": ids},
		)
	}()

	first := ingest.Node{
		ID:                 ids[0],
		Kinds:              []string{"MCPServer"},
		ObservationDomains: []string{scope},
		Properties: map[string]any{
			"name":           "server",
			"stale_property": "must-disappear",
		},
	}
	if _, err := writer.WriteObservationNodes(
		ctx,
		[]ingest.Node{first},
		"property-scan-1",
		[]string{scope},
	); err != nil {
		t.Fatalf("write first managed observation: %v", err)
	}
	second := first
	second.Properties = map[string]any{"name": "server-updated"}
	if _, err := writer.WriteObservationNodes(
		ctx,
		[]ingest.Node{second},
		"property-scan-2",
		[]string{scope},
	); err != nil {
		t.Fatalf("write replacement observation: %v", err)
	}

	if _, err := writer.WriteNodes(
		ctx,
		[]ingest.Node{{
			ID:    ids[1],
			Kinds: []string{"MCPServer"},
			Properties: map[string]any{
				"name":           "legacy",
				"stale_property": "legacy-stale",
			},
		}},
		"legacy-property-scan",
	); err != nil {
		t.Fatalf("create legacy observation: %v", err)
	}
	if _, err := writer.WriteObservationNodes(
		ctx,
		[]ingest.Node{{
			ID:                 ids[1],
			Kinds:              []string{"MCPServer"},
			ObservationDomains: []string{scope},
			Properties:         map[string]any{"name": "migrated"},
		}},
		"property-scan-2",
		[]string{scope},
	); err != nil {
		t.Fatalf("migrate legacy observation: %v", err)
	}

	rows, err := reader.Query(
		ctx,
		`MATCH (n) WHERE n.objectid IN $ids
		RETURN n.objectid AS id,
		       n.stale_property AS stale_property,
		       n.legacy_observation AS legacy_observation,
		       n.observation_properties_complete AS properties_complete`,
		map[string]any{"ids": ids},
	)
	if err != nil {
		t.Fatalf("read property replacement: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows = %v, want two nodes", rows)
	}
	for _, row := range rows {
		if row["stale_property"] != nil {
			t.Fatalf("stale property survived on %v: %v", row["id"], row)
		}
		if legacy, _ := row["legacy_observation"].(bool); legacy {
			t.Fatalf("complete re-observation remained legacy: %v", row)
		}
		if complete, _ := row["properties_complete"].(bool); !complete {
			t.Fatalf("replacement did not mark properties complete: %v", row)
		}
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
	assertChainEdges := func(t *testing.T, edges []ingest.Edge) {
		t.Helper()
		got := make(map[string]bool, len(edges))
		for _, edge := range edges {
			got[fmt.Sprintf("%s->%s:%s", edge.Source, edge.Target, edge.Kind)] = true
		}
		for _, want := range []string{
			"blast-agent-001->blast-srv-001:TRUSTS_SERVER",
			"blast-srv-001->blast-tool-001:PROVIDES_TOOL",
			"blast-tool-001->blast-res-001:HAS_ACCESS_TO",
		} {
			if !got[want] {
				t.Errorf("in-scope edges = %v, missing stored direction %s", got, want)
			}
		}
	}
	assertChainEdges(t, result.Edges)

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
	if inResult != nil {
		assertChainEdges(t, inResult.Edges)
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

func TestIntegrationMCPStdioV1CompatibilityMigratesOneToOneWithoutFanOut(t *testing.T) {
	ctx := testDriver(t)
	driver, err := NewDriver(
		os.Getenv("AGENTHOUND_NEO4J_URI"),
		os.Getenv("AGENTHOUND_NEO4J_USER"),
		os.Getenv("AGENTHOUND_NEO4J_PASSWORD"),
	)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer driver.Close(ctx)

	reader := NewReader(driver)
	writer := NewWriter(driver)
	db := NewDB(reader, writer)

	ambiguousLegacy := ingest.ComputeLegacyMCPServerID("stdio", "node", "a.js", "b.js")
	ambiguousA := ingest.ComputeMCPServerID("stdio", "node", "a.js", "b.js")
	ambiguousB := ingest.ComputeMCPServerID("stdio", "node", "b.js", "a.js")
	oneToOneLegacy := ingest.ComputeLegacyMCPServerID("stdio", "npx", "pkg")
	oneToOneCurrent := ingest.ComputeMCPServerID("stdio", "npx", "pkg")
	ambiguousTool := "identity-compat-ambiguous-tool"
	incomingAgent := "identity-compat-incoming-agent"
	outgoingTool := "identity-compat-outgoing-tool"
	sharedTool := "identity-compat-shared-tool"
	ids := []string{
		ambiguousLegacy,
		ambiguousA,
		ambiguousB,
		oneToOneLegacy,
		oneToOneCurrent,
		ambiguousTool,
		incomingAgent,
		outgoingTool,
		sharedTool,
	}
	_, _ = reader.Query(
		ctx,
		`MATCH (n) WHERE n.objectid IN $ids DETACH DELETE n`,
		map[string]any{"ids": ids},
	)
	defer func() {
		_, _ = reader.Query(
			ctx,
			`MATCH (n) WHERE n.objectid IN $ids DETACH DELETE n`,
			map[string]any{"ids": ids},
		)
	}()

	_, err = reader.Query(ctx, `
CREATE (ambiguous_legacy:MCPServer {
  objectid: $ambiguous_legacy,
  transport: 'stdio',
  id_scheme: $v1_scheme
})
CREATE (ambiguous_a:MCPServer {
  objectid: $ambiguous_a,
  transport: 'stdio',
  id_scheme: $v2_scheme,
  legacy_objectid: $ambiguous_legacy
})
CREATE (ambiguous_b:MCPServer {
  objectid: $ambiguous_b,
  transport: 'stdio',
  id_scheme: $v2_scheme,
  legacy_objectid: $ambiguous_legacy
})
CREATE (legacy:MCPServer {
  objectid: $legacy,
  transport: 'stdio',
  id_scheme: $v1_scheme,
  legacy_only_property: 'legacy-node',
  conflicting_property: 'legacy-value',
  observation_tokens: ['owner-legacy', 'owner-overlap'],
  observation_managed: true,
  legacy_observation: false,
  observation_properties_complete: true
})
CREATE (current:MCPServer {
  objectid: $current,
  transport: 'stdio',
  id_scheme: $v2_scheme,
  legacy_objectid: $legacy,
  current_only_property: 'current-node',
  conflicting_property: 'current-value',
  observation_tokens: ['owner-current', 'owner-overlap'],
  observation_managed: true,
  legacy_observation: false,
  observation_properties_complete: true
})
CREATE (ambiguous_tool:MCPTool {objectid: $ambiguous_tool})
CREATE (incoming_agent:AgentInstance {objectid: $incoming_agent})
CREATE (outgoing_tool:MCPTool {objectid: $outgoing_tool})
CREATE (shared_tool:MCPTool {objectid: $shared_tool})
CREATE (ambiguous_legacy)-[:PROVIDES_TOOL {
  ambiguous_property: 'untouched',
  observation_tokens: ['owner-ambiguous'],
  observation_managed: true,
  legacy_observation: false,
  observation_properties_complete: true
}]->(ambiguous_tool)
CREATE (incoming_agent)-[:TRUSTS_SERVER {
  incoming_property: 'kept',
  observation_tokens: ['owner-incoming'],
  observation_managed: true,
  legacy_observation: false,
  observation_properties_complete: true
}]->(legacy)
CREATE (legacy)-[:PROVIDES_TOOL {
  outgoing_property: 'kept',
  observation_tokens: ['owner-outgoing'],
  observation_managed: true,
  legacy_observation: false,
  observation_properties_complete: true
}]->(outgoing_tool)
CREATE (legacy)-[:PROVIDES_TOOL {
  legacy_shared_property: 'kept',
  conflicting_property: 'legacy-value',
  observation_tokens: ['owner-shared-legacy', 'owner-overlap'],
  observation_managed: true,
  legacy_observation: false,
  observation_properties_complete: true
}]->(shared_tool)
CREATE (current)-[:PROVIDES_TOOL {
  current_shared_property: 'kept',
  conflicting_property: 'current-value',
  observation_tokens: ['owner-shared-current', 'owner-overlap'],
  observation_managed: true,
  legacy_observation: false,
  observation_properties_complete: true
}]->(shared_tool)
CREATE (legacy)-[:SAME_AUTH_DOMAIN {
  self_property: 'kept',
  observation_tokens: ['owner-self'],
  observation_managed: true,
  legacy_observation: false,
  observation_properties_complete: true
}]->(legacy)`, map[string]any{
		"ambiguous_legacy": ambiguousLegacy,
		"ambiguous_a":      ambiguousA,
		"ambiguous_b":      ambiguousB,
		"legacy":           oneToOneLegacy,
		"current":          oneToOneCurrent,
		"ambiguous_tool":   ambiguousTool,
		"incoming_agent":   incomingAgent,
		"outgoing_tool":    outgoingTool,
		"shared_tool":      sharedTool,
		"v1_scheme":        ingest.MCPStdioIdentitySchemeV1,
		"v2_scheme":        ingest.MCPStdioIdentitySchemeV2,
	})
	if err != nil {
		t.Fatalf("seed compatibility graph: %v", err)
	}

	aliases := []ingest.IdentityAlias{
		{
			LegacyID:   ambiguousLegacy,
			CurrentIDs: []string{ambiguousA},
			State:      ingest.IdentityAliasOneToOne,
		},
		{
			LegacyID:   oneToOneLegacy,
			CurrentIDs: []string{oneToOneCurrent},
			State:      ingest.IdentityAliasOneToOne,
		},
	}
	resolved, stats, err := ReconcileMCPStdioIdentities(
		ctx,
		db,
		aliases,
	)
	if err != nil {
		t.Fatalf("reconcile compatibility: %v", err)
	}
	if len(resolved) != 2 ||
		stats.AmbiguousAliases != 1 ||
		stats.OneToOneAliases != 1 ||
		stats.LegacyNodesMigrated != 1 {
		t.Fatalf("resolved compatibility = %+v stats=%+v", resolved, stats)
	}

	assertTokens := func(label string, value any, want ...string) {
		t.Helper()
		got := stringValues(value)
		if len(got) != len(want) {
			t.Fatalf("%s tokens = %q, want %q", label, got, want)
		}
		counts := make(map[string]int, len(got))
		for _, token := range got {
			counts[token]++
		}
		for _, token := range want {
			if counts[token] != 1 {
				t.Fatalf("%s tokens = %q, want each of %q once", label, got, want)
			}
		}
	}
	assertGraph := func() {
		t.Helper()

		legacy, _, err := reader.GetNode(ctx, oneToOneLegacy)
		if err != nil {
			t.Fatalf("read retired one-to-one legacy node: %v", err)
		}
		if legacy != nil {
			t.Fatalf("one-to-one legacy node was not retired: %+v", legacy)
		}

		current, _, err := reader.GetNode(ctx, oneToOneCurrent)
		if err != nil {
			t.Fatalf("read migrated current node: %v", err)
		}
		if current == nil {
			t.Fatal("migrated current node missing")
		}
		props := current.Properties
		if props["objectid"] != oneToOneCurrent ||
			props["id_scheme"] != ingest.MCPStdioIdentitySchemeV2 ||
			props["legacy_objectid"] != oneToOneLegacy ||
			props["legacy_alias_state"] != string(ingest.IdentityAliasOneToOne) ||
			props["identity_compatibility"] != string(ingest.IdentityAliasOneToOne) ||
			props["identity_alias_target"] != oneToOneCurrent ||
			props["identity_quarantined"] != false ||
			props["legacy_identity_quarantined"] != false {
			t.Fatalf("migrated identity metadata = %+v", props)
		}
		if props["legacy_only_property"] != "legacy-node" ||
			props["current_only_property"] != "current-node" ||
			props["conflicting_property"] != "current-value" {
			t.Fatalf("migrated node properties = %+v", props)
		}
		assertTokens(
			"migrated node",
			props["observation_tokens"],
			"owner-current",
			"owner-overlap",
			"owner-legacy",
		)

		ambiguousNode, ambiguousEdges, err := reader.GetNode(ctx, ambiguousLegacy)
		if err != nil {
			t.Fatalf("read ambiguous legacy node: %v", err)
		}
		if ambiguousNode == nil ||
			ambiguousNode.Properties["identity_compatibility"] != string(ingest.IdentityAliasAmbiguous) ||
			ambiguousNode.Properties["identity_quarantined"] != true {
			t.Fatalf("ambiguous legacy node was not quarantined: %+v", ambiguousNode)
		}
		if len(ambiguousEdges) != 1 ||
			ambiguousEdges[0].Source != ambiguousLegacy ||
			ambiguousEdges[0].Target != ambiguousTool ||
			ambiguousEdges[0].Properties["ambiguous_property"] != "untouched" {
			t.Fatalf("ambiguous legacy relationship changed: %+v", ambiguousEdges)
		}
		for _, currentID := range []string{ambiguousA, ambiguousB} {
			candidate, edges, err := reader.GetNode(ctx, currentID)
			if err != nil {
				t.Fatalf("read current candidate %s: %v", currentID, err)
			}
			if candidate == nil ||
				candidate.Properties["legacy_alias_state"] != string(ingest.IdentityAliasAmbiguous) ||
				candidate.Properties["legacy_identity_quarantined"] != true {
				t.Fatalf("current candidate was not quarantined: %+v", candidate)
			}
			if len(edges) != 0 {
				t.Fatalf("ambiguous relationship fanned out to %s: %+v", currentID, edges)
			}
		}

		rows, err := reader.Query(ctx, `
MATCH (source)-[relationship]->(target)
WHERE source.objectid IN $ids OR target.objectid IN $ids
RETURN source.objectid AS source,
       target.objectid AS target,
       type(relationship) AS kind,
       properties(relationship) AS properties`, map[string]any{"ids": ids})
		if err != nil {
			t.Fatalf("read migrated relationships: %v", err)
		}
		if len(rows) != 5 {
			t.Fatalf("relationship count = %d, want 5: %+v", len(rows), rows)
		}
		relationshipCounts := make(map[string]int, len(rows))
		relationshipProperties := make(map[string]map[string]any, len(rows))
		for _, row := range rows {
			source, _ := row["source"].(string)
			target, _ := row["target"].(string)
			kind, _ := row["kind"].(string)
			key := source + "\x00" + kind + "\x00" + target
			relationshipCounts[key]++
			properties, _ := row["properties"].(map[string]any)
			relationshipProperties[key] = properties
		}
		assertRelationship := func(
			source, kind, target, property string,
			wantTokens ...string,
		) map[string]any {
			t.Helper()
			key := source + "\x00" + kind + "\x00" + target
			if relationshipCounts[key] != 1 {
				t.Fatalf("%s relationship count = %d, want 1", key, relationshipCounts[key])
			}
			properties := relationshipProperties[key]
			if properties[property] != "kept" {
				t.Fatalf("%s properties = %+v, missing %s", key, properties, property)
			}
			assertTokens(key, properties["observation_tokens"], wantTokens...)
			return properties
		}
		assertRelationship(
			incomingAgent,
			"TRUSTS_SERVER",
			oneToOneCurrent,
			"incoming_property",
			"owner-incoming",
		)
		assertRelationship(
			oneToOneCurrent,
			"PROVIDES_TOOL",
			outgoingTool,
			"outgoing_property",
			"owner-outgoing",
		)
		sharedProperties := assertRelationship(
			oneToOneCurrent,
			"PROVIDES_TOOL",
			sharedTool,
			"legacy_shared_property",
			"owner-shared-current",
			"owner-overlap",
			"owner-shared-legacy",
		)
		if sharedProperties["current_shared_property"] != "kept" ||
			sharedProperties["conflicting_property"] != "current-value" {
			t.Fatalf("shared relationship properties = %+v", sharedProperties)
		}
		assertRelationship(
			oneToOneCurrent,
			"SAME_AUTH_DOMAIN",
			oneToOneCurrent,
			"self_property",
			"owner-self",
		)
		ambiguousProperties := assertRelationship(
			ambiguousLegacy,
			"PROVIDES_TOOL",
			ambiguousTool,
			"ambiguous_property",
			"owner-ambiguous",
		)
		if ambiguousProperties["ambiguous_property"] != "untouched" {
			t.Fatalf("ambiguous relationship properties = %+v", ambiguousProperties)
		}
	}
	assertGraph()

	resolved, rerunStats, err := ReconcileMCPStdioIdentities(ctx, db, aliases)
	if err != nil {
		t.Fatalf("rerun compatibility reconciliation: %v", err)
	}
	if len(resolved) != 2 ||
		rerunStats.AmbiguousAliases != 1 ||
		rerunStats.OneToOneAliases != 1 ||
		rerunStats.LegacyNodesMigrated != 0 {
		t.Fatalf("rerun compatibility = %+v stats=%+v", resolved, rerunStats)
	}
	assertGraph()
}
