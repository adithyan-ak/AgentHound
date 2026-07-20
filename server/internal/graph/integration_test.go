package graph

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/server/internal/binding"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

const integrationStoragePairID = "7bc1f56e-c890-4de5-9cc5-921797176fa6"

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

func integrationWrite(
	ctx context.Context,
	driver neo4j.DriverWithContext,
	cypher string,
	params map[string]any,
) (int, error) {
	return NewDB(NewReader(driver), NewWriter(driver)).ExecuteWrite(
		ctx,
		cypher,
		params,
	)
}

func TestIntegrationStorageBindingLifecycle(t *testing.T) {
	if os.Getenv("AGENTHOUND_FRESH_DB_INTEGRATION") != "1" {
		t.Skip("set AGENTHOUND_FRESH_DB_INTEGRATION=1 for fresh-database storage binding integration")
	}
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

	cleanup := func() {
		_, _ = integrationWrite(ctx, driver, `
MATCH (n)
WHERE n:AgentHoundStorageBinding OR n:BindingProductFixture
DETACH DELETE n`, nil)
	}
	cleanup()
	defer cleanup()

	store := NewStorageBindingStore(driver)
	inspection, err := store.Inspect(ctx)
	if err != nil {
		t.Fatalf("inspect pristine graph: %v", err)
	}
	if inspection.Marker != nil || !inspection.ProductEmpty {
		t.Fatalf("pristine inspection = %+v, want unbound and product-empty", inspection)
	}
	if err := store.EnsureConstraint(ctx); err != nil {
		t.Fatalf("ensure binding constraint: %v", err)
	}
	if err := store.EnsureConstraint(ctx); err != nil {
		t.Fatalf("ensure binding constraint idempotently: %v", err)
	}

	origin := ingest.CollectionOrigin{HostID: "host-a", NetworkRealmID: "realm-a"}
	marker, err := binding.NewMarker(origin, integrationStoragePairID)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Install(ctx, marker); err != nil {
		t.Fatalf("install marker: %v", err)
	}
	if err := store.Install(ctx, marker); err != nil {
		t.Fatalf("idempotent marker install: %v", err)
	}
	actual, err := store.ReadStorageBinding(ctx)
	if err != nil || !actual.Equal(marker) {
		t.Fatalf("read marker = %+v, %v", actual, err)
	}
	other, err := binding.NewMarker(origin, "ee2f3afe-209e-42fb-8685-af55caa7e58d")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Install(ctx, other); err == nil {
		t.Fatal("conflicting storage pair unexpectedly replaced immutable marker")
	}

	if _, err := integrationWrite(ctx, driver, "CREATE (:BindingProductFixture)", nil); err != nil {
		t.Fatalf("create product fixture: %v", err)
	}
	if _, err := integrationWrite(ctx, driver, "MATCH (b:AgentHoundStorageBinding) DELETE b", nil); err != nil {
		t.Fatalf("remove marker for legacy-state proof: %v", err)
	}
	inspection, err = store.Inspect(ctx)
	if err != nil {
		t.Fatalf("inspect legacy graph: %v", err)
	}
	if inspection.Marker != nil || inspection.ProductEmpty {
		t.Fatalf("legacy inspection = %+v, want unbound and nonempty", inspection)
	}
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

func TestIntegrationNeo4jVersionMatrix(t *testing.T) {
	ctx := testDriver(t)

	expectedMajorValue := os.Getenv("AGENTHOUND_EXPECTED_NEO4J_MAJOR")
	if expectedMajorValue == "" {
		t.Skip("AGENTHOUND_EXPECTED_NEO4J_MAJOR is required for the version-matrix integration")
	}
	expectedMajor, err := strconv.Atoi(expectedMajorValue)
	if err != nil {
		t.Fatalf("parse AGENTHOUND_EXPECTED_NEO4J_MAJOR=%q: %v", expectedMajorValue, err)
	}

	driver, err := NewDriver(
		os.Getenv("AGENTHOUND_NEO4J_URI"),
		os.Getenv("AGENTHOUND_NEO4J_USER"),
		os.Getenv("AGENTHOUND_NEO4J_PASSWORD"),
	)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer driver.Close(ctx)

	major, minor, err := DetectVersion(ctx, driver)
	if err != nil {
		t.Fatalf("detect version: %v", err)
	}
	if major != expectedMajor {
		t.Fatalf(
			"detected Neo4j %d.%d, matrix expected major %d",
			major,
			minor,
			expectedMajor,
		)
	}
	if err := InitSchema(ctx, driver); err != nil {
		t.Fatalf("initialize schema on Neo4j %d.%d: %v", major, minor, err)
	}
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
	_, _ = integrationWrite(ctx, driver, "MATCH (n) WHERE n.scan_id = 'test-integration' DETACH DELETE n", nil)

	writer := NewWriter(driver)

	nodes := []ingest.Node{
		{ID: "test-srv-001", Kinds: []string{"MCPServer"}, Properties: map[string]any{
			"objectid": "test-srv-001", "name": "test-server", "transport": "stdio",
		}},
		{ID: "test-tool-001", Kinds: []string{"MCPTool"}, Properties: map[string]any{
			"objectid": "test-tool-001", "name": "execute_sql", "description_hash": "abc123",
		}},
	}

	nWritten, err := writer.WriteNodes(ctx, managedIntegrationNodes(nodes), "test-integration")
	if err != nil {
		t.Fatalf("write nodes: %v", err)
	}
	if nWritten != 2 {
		t.Errorf("nodes written: got %d, want 2", nWritten)
	}

	edges := []ingest.Edge{
		{Source: "test-srv-001", Target: "test-tool-001", Kind: "PROVIDES_TOOL",
			SourceKind: "MCPServer", TargetKind: "MCPTool", Properties: map[string]any{
				"confidence": 1.0, "is_composite": false,
			}},
	}

	eWritten, err := writer.WriteEdges(ctx, managedIntegrationEdges(edges), "test-integration")
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
	nWritten, err = writer.WriteNodes(ctx, managedIntegrationNodes(updatedNodes), "test-integration")
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
	_, _ = integrationWrite(ctx, driver, "MATCH (n) WHERE n.scan_id = 'test-integration' DETACH DELETE n", nil)
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
		_, _ = integrationWrite(
			ctx,
			driver,
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

	_, err = integrationWrite(ctx, driver, `
CREATE (:MCPServer {objectid: $public_id, name: $public_name})
CREATE (:SchemaVersion {objectid: $schema_id, name: $schema_name})`, map[string]any{
		"public_id":   ids[0],
		"schema_id":   ids[1],
		"public_name": prefix + "-public",
		"schema_name": prefix + "-schema",
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
			"public total changed by %d, want 1; internal nodes leaked",
			afterStats.TotalNodes-beforeStats.TotalNodes,
		)
	}
	for _, internal := range []string{"SchemaVersion"} {
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
	_, _ = db.ExecuteWrite(ctx,
		`MATCH (n) WHERE n.objectid IN $ids DETACH DELETE n`,
		map[string]any{"ids": ids},
	)
	defer func() {
		_, _ = db.ExecuteWrite(ctx,
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
	if _, err := writer.WriteNodes(ctx, managedIntegrationNodes(nodes), "reconcile-old"); err != nil {
		t.Fatalf("write nodes: %v", err)
	}
	if _, err := writer.WriteEdges(ctx, []ingest.Edge{{
		Source: "reconcile-srv", Target: "reconcile-tool", Kind: "PROVIDES_TOOL",
		SourceKind:         "MCPServer",
		TargetKind:         "MCPTool",
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

func TestIntegrationDependencyEdgeRetiresWhenEitherDomainChanges(t *testing.T) {
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

	writer := NewWriter(driver)
	db := NewDB(NewReader(driver), writer)
	const sourceID = "dependency-agent-a"
	const targetID = "dependency-agent-b"
	ids := []string{sourceID, targetID}
	cleanup := func() {
		_, _ = db.ExecuteWrite(
			ctx,
			"MATCH (n) WHERE n.objectid IN $ids DETACH DELETE n",
			map[string]any{"ids": ids},
		)
	}
	cleanup()
	defer cleanup()

	domainA := "a2a:target:sha256:dependency-a"
	domainB := "a2a:target:sha256:dependency-b"
	nodes := []ingest.Node{
		{
			ID: sourceID, Kinds: []string{"A2AAgent"},
			ObservationDomains: []string{domainA},
		},
		{
			ID: targetID, Kinds: []string{"A2AAgent"},
			ObservationDomains: []string{domainB},
		},
	}
	if _, err := writer.WriteObservationNodes(
		ctx,
		nodes,
		"dependency-old",
		[]string{domainA, domainB},
	); err != nil {
		t.Fatalf("write dependency nodes: %v", err)
	}
	edge := ingest.Edge{
		Source:               sourceID,
		Target:               targetID,
		Kind:                 "DELEGATES_TO",
		SourceKind:           "A2AAgent",
		TargetKind:           "A2AAgent",
		Properties:           map[string]any{"risk_weight": 0.1},
		ObservationDomains:   []string{domainA, domainB},
		ObservationSemantics: ingest.ObservationSemanticsAllDependencies,
	}
	if _, err := writer.WriteObservationEdges(
		ctx,
		[]ingest.Edge{edge},
		"dependency-old",
		[]string{domainA, domainB},
	); err != nil {
		t.Fatalf("write dependency edge: %v", err)
	}

	if _, err := ReconcileObservations(
		ctx,
		db,
		"dependency-current",
		[]string{domainA},
	); err != nil {
		t.Fatalf("reconcile one dependency: %v", err)
	}
	rows, err := db.Query(
		ctx,
		`MATCH (:A2AAgent {objectid: $source})-[r:DELEGATES_TO]->
		       (:A2AAgent {objectid: $target})
		 RETURN count(r) AS count`,
		map[string]any{"source": sourceID, "target": targetID},
	)
	if err != nil {
		t.Fatalf("query dependency edge: %v", err)
	}
	if count, _ := rows[0]["count"].(int64); count != 0 {
		t.Fatalf("stale all-dependency relationship count = %d, want 0", count)
	}
}

func TestIntegrationObservationCompletenessRejectsTokenlessAgentSequence(t *testing.T) {
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

	writer := NewWriter(driver)
	db := NewDB(NewReader(driver), writer)
	const (
		agentID       = "tokenless-sequence-agent"
		instructionID = "tokenless-sequence-instruction"
	)
	ids := []string{agentID, instructionID}
	cleanup := func() {
		_, _ = db.ExecuteWrite(
			ctx,
			"MATCH (n) WHERE n.objectid IN $ids DETACH DELETE n",
			map[string]any{"ids": ids},
		)
	}
	cleanup()
	defer cleanup()
	baseline, err := GetObservationCompleteness(ctx, db)
	if err != nil {
		t.Fatalf("get baseline observation completeness: %v", err)
	}

	configScope := "config:path:sha256:tokenless-config"
	instructionScope := "config:path:sha256:tokenless-instruction"
	if _, err := writer.WriteObservationNodes(
		ctx,
		[]ingest.Node{
			{
				ID:                 agentID,
				Kinds:              []string{"AgentInstance"},
				ObservationDomains: []string{configScope},
				Properties:         map[string]any{"name": "agent"},
			},
			{
				ID:                 instructionID,
				Kinds:              []string{"InstructionFile"},
				ObservationDomains: []string{instructionScope},
				Properties:         map[string]any{"path": "/tmp/CLAUDE.md"},
			},
		},
		"tokenless-old",
		[]string{configScope, instructionScope},
	); err != nil {
		t.Fatalf("write observation nodes: %v", err)
	}
	if _, err := writer.WriteObservationEdges(
		ctx,
		[]ingest.Edge{{
			Source:             agentID,
			Target:             instructionID,
			Kind:               "LOADS_INSTRUCTIONS",
			SourceKind:         "AgentInstance",
			TargetKind:         "InstructionFile",
			Properties:         map[string]any{"risk_weight": 0.1},
			ObservationDomains: []string{instructionScope},
		}},
		"tokenless-old",
		[]string{configScope, instructionScope},
	); err != nil {
		t.Fatalf("write observation edge: %v", err)
	}
	if _, err := ReconcileObservations(
		ctx,
		db,
		"tokenless-current",
		[]string{configScope},
	); err != nil {
		t.Fatalf("retire config observation: %v", err)
	}

	completeness, err := GetObservationCompleteness(ctx, db)
	if err != nil {
		t.Fatalf("get observation completeness: %v", err)
	}
	if completeness.TokenlessNodes != baseline.TokenlessNodes+1 ||
		completeness.TokenlessIncidentRelationships !=
			baseline.TokenlessIncidentRelationships+1 ||
		completeness.Complete() {
		t.Fatalf(
			"tokenless publication backstop = %+v, baseline %+v",
			completeness,
			baseline,
		)
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
	ids := []string{"managed-property-replacement"}
	_, _ = integrationWrite(
		ctx,
		driver,
		`MATCH (n) WHERE n.objectid IN $ids DETACH DELETE n`,
		map[string]any{"ids": ids},
	)
	defer func() {
		_, _ = integrationWrite(
			ctx,
			driver,
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

	rows, err := reader.Query(
		ctx,
		`MATCH (n) WHERE n.objectid IN $ids
		RETURN n.objectid AS id,
		       n.stale_property AS stale_property,
		       n.observation_properties_complete AS properties_complete`,
		map[string]any{"ids": ids},
	)
	if err != nil {
		t.Fatalf("read property replacement: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %v, want one node", rows)
	}
	for _, row := range rows {
		if row["stale_property"] != nil {
			t.Fatalf("stale property survived on %v: %v", row["id"], row)
		}
		if complete, _ := row["properties_complete"].(bool); !complete {
			t.Fatalf("replacement did not mark properties complete: %v", row)
		}
	}
}

func TestIntegrationReferenceOwnerPreservesThenRetiresAuthoritativeProperties(t *testing.T) {
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

	writer := NewWriter(driver)
	db := NewDB(NewReader(driver), writer)
	const nodeID = "shared-reference-retirement"
	cleanup := func() {
		_, _ = db.ExecuteWrite(
			ctx,
			"MATCH (n {objectid: $id}) DETACH DELETE n",
			map[string]any{"id": nodeID},
		)
	}
	cleanup()
	defer cleanup()

	authoritativeScope := "scan:network:sha256:authoritative"
	referenceScope := "scan:loot:sha256:reference"
	authoritative := ingest.Node{
		ID:                 nodeID,
		Kinds:              []string{"LiteLLMGateway", "AIService"},
		ObservationDomains: []string{authoritativeScope},
		Properties: map[string]any{
			"objectid":       nodeID,
			"endpoint":       "http://127.0.0.1:4000",
			"auth_method":    "master_key",
			"discovered_via": "network_scan",
		},
	}
	if _, err := writer.WriteObservationNodes(
		ctx,
		[]ingest.Node{authoritative},
		"authoritative-scan",
		[]string{authoritativeScope},
	); err != nil {
		t.Fatalf("write authoritative observation: %v", err)
	}
	if _, err := ReconcileObservations(
		ctx,
		db,
		"authoritative-scan",
		[]string{authoritativeScope},
	); err != nil {
		t.Fatalf("reconcile authoritative observation: %v", err)
	}

	reference := ingest.Node{
		ID:                 nodeID,
		Kinds:              []string{"LiteLLMGateway", "AIService"},
		ObservationDomains: []string{referenceScope},
		Properties:         map[string]any{"objectid": nodeID},
		PropertySemantics:  ingest.NodePropertySemanticsReferenceOnly,
	}
	if _, err := writer.WriteObservationNodes(
		ctx,
		[]ingest.Node{reference},
		"reference-scan",
		[]string{referenceScope},
	); err != nil {
		t.Fatalf("write reference observation: %v", err)
	}
	if _, err := ReconcileObservations(
		ctx,
		db,
		"reference-scan",
		[]string{referenceScope},
	); err != nil {
		t.Fatalf("reconcile reference observation: %v", err)
	}

	rows, err := db.Query(
		ctx,
		`MATCH (n:LiteLLMGateway {objectid: $id})
		 RETURN n.endpoint AS endpoint,
		        n.auth_method AS auth_method,
		        n.discovered_via AS discovered_via,
		        n.observation_tokens AS tokens,
		        n.observation_reference_tokens AS reference_tokens,
		        n.observation_properties_complete AS properties_complete`,
		map[string]any{"id": nodeID},
	)
	if err != nil {
		t.Fatalf("query shared-owner node: %v", err)
	}
	if len(rows) != 1 ||
		rows[0]["endpoint"] != "http://127.0.0.1:4000" ||
		rows[0]["auth_method"] != "master_key" ||
		rows[0]["discovered_via"] != "network_scan" ||
		rows[0]["properties_complete"] != true {
		t.Fatalf("reference observation changed authoritative properties: %+v", rows)
	}
	tokens, _ := rows[0]["tokens"].([]any)
	referenceTokens, _ := rows[0]["reference_tokens"].([]any)
	if len(tokens) != 2 || len(referenceTokens) != 1 {
		t.Fatalf("shared ownership tokens = %v, reference tokens = %v", tokens, referenceTokens)
	}

	if _, err := ReconcileObservations(
		ctx,
		db,
		"authoritative-retired",
		[]string{authoritativeScope},
	); err != nil {
		t.Fatalf("retire authoritative owner: %v", err)
	}
	rows, err = db.Query(
		ctx,
		`MATCH (n:LiteLLMGateway {objectid: $id})
		 RETURN properties(n) AS properties`,
		map[string]any{"id": nodeID},
	)
	if err != nil {
		t.Fatalf("query reference fallback: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("reference fallback node missing: %+v", rows)
	}
	properties, _ := rows[0]["properties"].(map[string]any)
	if properties["objectid"] != nodeID ||
		properties["endpoint"] != nil ||
		properties["auth_method"] != nil ||
		properties["discovered_via"] != nil ||
		properties["observation_properties_complete"] != true {
		t.Fatalf("authoritative retirement retained stale rich properties: %+v", properties)
	}
	remainingTokens, _ := properties["observation_tokens"].([]any)
	remainingReferenceTokens, _ := properties["observation_reference_tokens"].([]any)
	if len(remainingTokens) != 1 || len(remainingReferenceTokens) != 1 {
		t.Fatalf(
			"reference fallback ownership tokens = %v, reference tokens = %v",
			remainingTokens,
			remainingReferenceTokens,
		)
	}
}

func TestIntegrationCompatibleDistinctOwnersRemainCompleteUntilOneRetires(t *testing.T) {
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

	writer := NewWriter(driver)
	db := NewDB(NewReader(driver), writer)
	const (
		nodeID      = "compatible-shared-owner"
		targetID    = "compatible-shared-target"
		configScope = "config:path:sha256:compatible-owner"
		mcpScope    = "mcp:target:sha256:compatible-owner"
	)
	cleanup := func() {
		_, _ = db.ExecuteWrite(
			ctx,
			"MATCH (n) WHERE n.objectid IN $ids DETACH DELETE n",
			map[string]any{"ids": []string{nodeID, targetID}},
		)
	}
	cleanup()
	defer cleanup()

	configNodes := []ingest.Node{
		{
			ID: nodeID, Kinds: []string{"MCPServer"},
			ObservationDomains: []string{configScope},
			Properties: map[string]any{
				"endpoint": "http://mcp.example/mcp", "transport": "http",
			},
		},
		{
			ID: targetID, Kinds: []string{"Host"},
			ObservationDomains: []string{configScope},
			Properties:         map[string]any{"hostname": "mcp.example"},
		},
	}
	configEdge := ingest.Edge{
		Source: nodeID, Target: targetID, Kind: "RUNS_ON",
		SourceKind: "MCPServer", TargetKind: "Host",
		ObservationDomains: []string{configScope},
		Properties: map[string]any{
			"scan_id": "config-scan", "last_seen": "old",
			"confidence": 1.0, "risk_weight": 0.0, "is_composite": false,
		},
	}
	if _, err := writer.WriteObservationNodes(ctx, configNodes, "config-scan", []string{configScope}); err != nil {
		t.Fatalf("write config nodes: %v", err)
	}
	if _, err := writer.WriteObservationEdges(ctx, []ingest.Edge{configEdge}, "config-scan", []string{configScope}); err != nil {
		t.Fatalf("write config edge: %v", err)
	}

	mcpNodes := []ingest.Node{
		{
			ID: nodeID, Kinds: []string{"MCPServer"},
			ObservationDomains: []string{mcpScope},
			Properties: map[string]any{
				"endpoint": "http://mcp.example/mcp", "transport": "http",
				"protocol_version": "2025-06-18",
			},
		},
		{
			ID: targetID, Kinds: []string{"Host"},
			ObservationDomains: []string{mcpScope},
			Properties: map[string]any{
				"hostname": "mcp.example", "scope": "public",
			},
		},
	}
	mcpEdge := configEdge
	mcpEdge.ObservationDomains = []string{mcpScope}
	mcpEdge.Properties = map[string]any{
		"scan_id": "mcp-scan", "last_seen": "new",
		"confidence": 1.0, "risk_weight": 0.0, "is_composite": false,
	}
	if _, err := writer.WriteObservationNodes(ctx, mcpNodes, "mcp-scan", []string{mcpScope}); err != nil {
		t.Fatalf("write MCP nodes: %v", err)
	}
	if _, err := writer.WriteObservationEdges(ctx, []ingest.Edge{mcpEdge}, "mcp-scan", []string{mcpScope}); err != nil {
		t.Fatalf("write MCP edge: %v", err)
	}
	if _, err := ReconcileObservations(ctx, db, "mcp-scan", []string{mcpScope}); err != nil {
		t.Fatalf("reconcile MCP owner: %v", err)
	}

	rows, err := db.Query(ctx, `
		MATCH (server:MCPServer {objectid: $server})-[r:RUNS_ON]->(host:Host {objectid: $host})
		RETURN server.observation_properties_complete AS server_complete,
		       host.observation_properties_complete AS host_complete,
		       r.observation_properties_complete AS edge_complete,
		       server.protocol_version AS protocol_version`,
		map[string]any{"server": nodeID, "host": targetID})
	if err != nil {
		t.Fatalf("query compatible merge: %v", err)
	}
	if len(rows) != 1 || rows[0]["server_complete"] != true ||
		rows[0]["host_complete"] != true || rows[0]["edge_complete"] != true ||
		rows[0]["protocol_version"] != "2025-06-18" {
		t.Fatalf("compatible owners did not form a complete union: %+v", rows)
	}

	if _, err := ReconcileObservations(ctx, db, "mcp-absent", []string{mcpScope}); err != nil {
		t.Fatalf("retire MCP owner: %v", err)
	}
	rows, err = db.Query(ctx, `
		MATCH (server:MCPServer {objectid: $server})-[r:RUNS_ON]->(host:Host {objectid: $host})
		RETURN server.observation_properties_complete AS server_complete,
		       host.observation_properties_complete AS host_complete,
		       r.observation_properties_complete AS edge_complete`,
		map[string]any{"server": nodeID, "host": targetID})
	if err != nil {
		t.Fatalf("query retired owner: %v", err)
	}
	if len(rows) != 1 || rows[0]["server_complete"] != false ||
		rows[0]["host_complete"] != false || rows[0]["edge_complete"] != false {
		t.Fatalf("retiring a co-owner must downgrade merged properties: %+v", rows)
	}
}

func TestIntegrationCompleteObservationReplacesOnlyManagedLabels(t *testing.T) {
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

	writer := NewWriter(driver)
	reader := NewReader(driver)
	ids := []string{"managed-label-replacement", "shared-label-additive"}
	cleanup := func() {
		_, _ = integrationWrite(
			ctx,
			driver,
			"MATCH (n) WHERE n.objectid IN $ids DETACH DELETE n",
			map[string]any{"ids": ids},
		)
	}
	cleanup()
	defer cleanup()

	scopeA := "a2a:target:sha256:label-a"
	scopeB := "a2a:target:sha256:label-b"
	first := []ingest.Node{
		{
			ID: ids[0], Kinds: []string{"OllamaInstance", "AIService"},
			ObservationDomains: []string{scopeA},
		},
		{
			ID: ids[1], Kinds: []string{"OllamaInstance", "AIService"},
			ObservationDomains: []string{scopeA},
		},
	}
	if _, err := writer.WriteObservationNodes(
		ctx,
		first,
		"label-scan-1",
		[]string{scopeA},
	); err != nil {
		t.Fatalf("write initial labels: %v", err)
	}
	if _, err := integrationWrite(
		ctx,
		driver,
		"MATCH (n {objectid: $id}) SET n:SchemaVersion RETURN count(n)",
		map[string]any{"id": ids[0]},
	); err != nil {
		t.Fatalf("seed internal label: %v", err)
	}

	second := []ingest.Node{
		{
			ID: ids[0], Kinds: []string{"OllamaInstance"},
			ObservationDomains: []string{scopeA},
		},
		{
			ID: ids[1], Kinds: []string{"OllamaInstance"},
			ObservationDomains: []string{scopeB},
		},
	}
	if _, err := writer.WriteObservationNodes(
		ctx,
		second,
		"label-scan-2",
		[]string{scopeA, scopeB},
	); err != nil {
		t.Fatalf("write label updates: %v", err)
	}

	rows, err := reader.Query(
		ctx,
		"MATCH (n) WHERE n.objectid IN $ids RETURN n.objectid AS id, labels(n) AS labels",
		map[string]any{"ids": ids},
	)
	if err != nil {
		t.Fatalf("read labels: %v", err)
	}
	labelsByID := make(map[string]map[string]bool, len(rows))
	for _, row := range rows {
		id, _ := row["id"].(string)
		labelsByID[id] = make(map[string]bool)
		rawLabels, _ := row["labels"].([]any)
		for _, rawLabel := range rawLabels {
			label, _ := rawLabel.(string)
			labelsByID[id][label] = true
		}
	}
	replaced := labelsByID[ids[0]]
	if replaced["AIService"] ||
		!replaced["OllamaInstance"] ||
		!replaced["SchemaVersion"] {
		t.Fatalf("complete replacement labels = %v", replaced)
	}
	additive := labelsByID[ids[1]]
	if !additive["AIService"] || !additive["OllamaInstance"] {
		t.Fatalf("shared-owner additive labels = %v", additive)
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
	_, _ = integrationWrite(ctx, driver, "MATCH (n) WHERE n.scan_id = 'test-listedges' DETACH DELETE n", nil)

	nodes := []ingest.Node{
		{ID: "test-edge-srv-001", Kinds: []string{"MCPServer"}, Properties: map[string]any{
			"objectid": "test-edge-srv-001", "name": "edge-test-server", "transport": "stdio",
		}},
		{ID: "test-edge-tool-001", Kinds: []string{"MCPTool"}, Properties: map[string]any{
			"objectid": "test-edge-tool-001", "name": "edge-test-tool",
		}},
	}
	if _, err := writer.WriteNodes(ctx, managedIntegrationNodes(nodes), "test-listedges"); err != nil {
		t.Fatalf("write nodes: %v", err)
	}

	edges := []ingest.Edge{
		{Source: "test-edge-srv-001", Target: "test-edge-tool-001", Kind: "PROVIDES_TOOL",
			SourceKind: "MCPServer", TargetKind: "MCPTool", Properties: map[string]any{
				"confidence": 1.0, "is_composite": false,
			}},
	}
	if _, err := writer.WriteEdges(ctx, managedIntegrationEdges(edges), "test-listedges"); err != nil {
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
	_, _ = integrationWrite(ctx, driver, "MATCH (n) WHERE n.scan_id = 'test-listedges' DETACH DELETE n", nil)
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
	_, _ = integrationWrite(ctx, driver, "MATCH (n) WHERE n.scan_id = 'test-query' DETACH DELETE n", nil)

	nodes := []ingest.Node{
		{ID: "test-query-001", Kinds: []string{"MCPServer"}, Properties: map[string]any{
			"objectid": "test-query-001", "name": "query-test-server", "transport": "http",
		}},
	}
	if _, err := writer.WriteNodes(ctx, managedIntegrationNodes(nodes), "test-query"); err != nil {
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
	_, _ = integrationWrite(ctx, driver, "MATCH (n) WHERE n.scan_id = 'test-query' DETACH DELETE n", nil)
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
	_, _ = integrationWrite(ctx, driver, "MATCH (n) WHERE n.scan_id = 'test-batch' DETACH DELETE n", nil)

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

	nWritten, err := writer.WriteNodes(ctx, managedIntegrationNodes(nodes), "test-batch")
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
	_, _ = integrationWrite(ctx, driver, "MATCH (n) WHERE n.scan_id = 'test-batch' DETACH DELETE n", nil)
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
	_, _ = integrationWrite(ctx, driver, "MATCH (n) WHERE n.scan_id = 'test-fallback' DETACH DELETE n", nil)

	nodes := []ingest.Node{
		{ID: "test-fb-srv-001", Kinds: []string{"MCPServer"}, Properties: map[string]any{
			"objectid": "test-fb-srv-001", "name": "fallback-server", "transport": "stdio",
		}},
		{ID: "test-fb-tool-001", Kinds: []string{"MCPTool"}, Properties: map[string]any{
			"objectid": "test-fb-tool-001", "name": "fallback-tool",
		}},
	}
	if _, err := writer.WriteNodes(ctx, managedIntegrationNodes(nodes), "test-fallback"); err != nil {
		t.Fatalf("write nodes: %v", err)
	}

	// Force fallback path by disabling APOC
	writer.hasAPOC = false
	writer.apocOnce.Do(func() {}) // prevent re-detection

	edges := []ingest.Edge{
		{Source: "test-fb-srv-001", Target: "test-fb-tool-001", Kind: "PROVIDES_TOOL",
			SourceKind: "MCPServer", TargetKind: "MCPTool", Properties: map[string]any{
				"confidence": 0.9, "is_composite": false,
			}},
	}

	eWritten, err := writer.WriteEdges(ctx, managedIntegrationEdges(edges), "test-fallback")
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
	_, _ = integrationWrite(ctx, driver, "MATCH (n) WHERE n.scan_id = 'test-fallback' DETACH DELETE n", nil)
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
	_, _ = integrationWrite(ctx, driver, "MATCH (n) WHERE n.scan_id = 'test-blast' DETACH DELETE n", nil)

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
	if _, err := writer.WriteNodes(ctx, managedIntegrationNodes(nodes), "test-blast"); err != nil {
		t.Fatalf("write nodes: %v", err)
	}

	rawEdges := []ingest.Edge{
		{Source: "blast-agent-001", Target: "blast-srv-001", Kind: "TRUSTS_SERVER", SourceKind: "AgentInstance", TargetKind: "MCPServer", Properties: map[string]any{"confidence": 1.0}},
		{Source: "blast-srv-001", Target: "blast-tool-001", Kind: "PROVIDES_TOOL", SourceKind: "MCPServer", TargetKind: "MCPTool", Properties: map[string]any{"confidence": 1.0}},
	}
	if _, err := writer.WriteEdges(ctx, managedIntegrationEdges(rawEdges), "test-blast"); err != nil {
		t.Fatalf("write raw edges: %v", err)
	}
	compositeEdges := []ingest.Edge{{
		Source: "blast-tool-001", Target: "blast-res-001", Kind: "HAS_ACCESS_TO",
		SourceKind: "MCPTool", TargetKind: "MCPResource",
		Properties: map[string]any{"confidence": 0.9, "is_composite": true},
	}}
	if _, err := writer.WriteCompositeEdges(ctx, compositeEdges, "test-blast"); err != nil {
		t.Fatalf("write composite edges: %v", err)
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
	_, _ = integrationWrite(ctx, driver, "MATCH (n) WHERE n.scan_id = 'test-blast' DETACH DELETE n", nil)
}

func managedIntegrationNodes(nodes []ingest.Node) []ingest.Node {
	result := append([]ingest.Node(nil), nodes...)
	for i := range result {
		if len(result[i].ObservationDomains) == 0 {
			result[i].ObservationDomains = []string{"integration-domain"}
		}
	}
	return result
}

func managedIntegrationEdges(edges []ingest.Edge) []ingest.Edge {
	result := append([]ingest.Edge(nil), edges...)
	for i := range result {
		if len(result[i].ObservationDomains) == 0 {
			result[i].ObservationDomains = []string{"integration-domain"}
		}
	}
	return result
}
