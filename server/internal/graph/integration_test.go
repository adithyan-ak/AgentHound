package graph

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
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

func TestIntegrationSchemaInitRejectsLegacyUnfingerprintedOwners(t *testing.T) {
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

	const (
		sourceID = "legacy-fingerprint-schema-source"
		targetID = "legacy-fingerprint-schema-target"
		domainA  = "config:path:sha256:legacy-schema-a"
		domainB  = "mcp:target:sha256:legacy-schema-b"
	)
	cleanup := func() {
		_, _ = integrationWrite(ctx, driver, `
			MATCH (n)
			WHERE n.objectid IN $ids OR n:SchemaVersion
			DETACH DELETE n`, map[string]any{"ids": []string{sourceID, targetID}})
		_ = runDDL(ctx, driver, fmt.Sprintf(
			"CREATE (:SchemaVersion {version: %d})",
			graphSchemaVersion,
		))
	}
	cleanup()
	defer cleanup()
	if err := InitSchema(ctx, driver); err != nil {
		t.Fatalf("initialize current schema: %v", err)
	}

	if _, err := integrationWrite(ctx, driver, `
		MATCH (schema:SchemaVersion) DELETE schema
		CREATE (:SchemaVersion {version: 1})
		CREATE (source:MCPServer {
		  objectid: $source,
		  observation_tokens: $source_tokens,
		  observation_reference_tokens: [],
		  observation_fact_fingerprints: $source_fingerprints,
		  observation_properties_complete: true
		})
		CREATE (target:Host {
		  objectid: $target,
		  observation_tokens: $target_tokens,
		  observation_reference_tokens: [],
		  observation_fact_fingerprints: $target_fingerprints,
		  observation_properties_complete: true
		})
		CREATE (source)-[:RUNS_ON {
		  observation_tokens: $source_tokens,
		  observation_semantics: $semantics,
		  observation_fact_fingerprints: $source_fingerprints,
		  observation_properties_complete: true
		}]->(target)
		RETURN 1`, map[string]any{
		"source":              sourceID,
		"target":              targetID,
		"source_tokens":       []string{observationToken(domainA, "legacy"), observationToken(domainB, "legacy")},
		"target_tokens":       []string{observationToken(domainA, "legacy")},
		"source_fingerprints": []string{observationFingerprintDomainPrefix(domainA) + "legacy-digest"},
		"target_fingerprints": []string{observationFingerprintDomainPrefix(domainA) + "legacy-digest"},
		"semantics":           string(ingest.ObservationSemanticsAnyOwner),
	}); err != nil {
		t.Fatalf("seed legacy graph: %v", err)
	}

	err = InitSchema(ctx, driver)
	if err == nil {
		t.Fatal("InitSchema accepted schema-1 facts with unfingerprinted owners")
	}
	for _, want := range []string{
		"Neo4j graph schema 1",
		"1 authoritative nodes",
		"1 raw relationships",
		"automatic upgrade to schema 2 cannot preserve shared-owner evidence safely",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("InitSchema error %q missing %q", err, want)
		}
	}

	state, err := readObservationFingerprintSchemaState(ctx, driver)
	if err != nil {
		t.Fatalf("read rejected schema state: %v", err)
	}
	if state.Version != 1 || state.UnfingerprintedNodes != 1 ||
		state.UnfingerprintedRelationships != 1 {
		t.Fatalf("rejected schema state = %+v", state)
	}

	// Once a database was created under schema 2, a deliberately invalidated
	// owner may have no current fingerprint. Startup must still succeed so a
	// later joint refresh or retirement can repair that fail-closed fact.
	if _, err := integrationWrite(ctx, driver,
		"MATCH (schema:SchemaVersion) SET schema.version = $version RETURN count(schema)",
		map[string]any{"version": graphSchemaVersion},
	); err != nil {
		t.Fatalf("mark current schema: %v", err)
	}
	if err := InitSchema(ctx, driver); err != nil {
		t.Fatalf("schema 2 rejected an intentionally invalidated owner: %v", err)
	}

	// A binary must never rewrite an unknown future schema marker down to the
	// version it happens to understand.
	futureVersion := int64(graphSchemaVersion + 1)
	if _, err := integrationWrite(ctx, driver,
		"MATCH (schema:SchemaVersion) SET schema.version = $version RETURN count(schema)",
		map[string]any{"version": futureVersion},
	); err != nil {
		t.Fatalf("mark future schema: %v", err)
	}
	err = InitSchema(ctx, driver)
	if err == nil || !strings.Contains(
		err.Error(),
		"graph schema 3 is newer than the maximum schema 2",
	) {
		t.Fatalf("future schema rejection = %v", err)
	}
	state, err = readObservationFingerprintSchemaState(ctx, driver)
	if err != nil {
		t.Fatalf("read future schema state: %v", err)
	}
	if state.Version != futureVersion {
		t.Fatalf("future schema was mutated to version %d", state.Version)
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
	const observationDomain = "integration-domain"

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

	nWritten, err := writer.WriteObservationNodes(
		ctx,
		managedIntegrationNodes(nodes),
		"test-integration",
		[]string{observationDomain},
	)
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

	eWritten, err := writer.WriteObservationEdges(
		ctx,
		managedIntegrationEdges(edges),
		"test-integration",
		[]string{observationDomain},
	)
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
	nWritten, err = writer.WriteObservationNodes(
		ctx,
		managedIntegrationNodes(updatedNodes),
		"test-integration",
		[]string{observationDomain},
	)
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
	domainC := "a2a:target:sha256:dependency-c"
	domainD := "a2a:target:sha256:dependency-d"
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
	assertDependencyEdge := func(
		scanID string,
		riskWeight float64,
		leftDomain string,
		rightDomain string,
	) {
		t.Helper()
		rows, err := db.Query(ctx, `
			MATCH (:A2AAgent {objectid: $source})-[r:DELEGATES_TO]->
			      (:A2AAgent {objectid: $target})
			RETURN r.risk_weight AS risk_weight,
			       r.observation_properties_complete AS complete,
			       r.observation_dependency_tokens = $tokens AS tokens_exact,
			       size(coalesce(r.observation_tokens, [])) = 0 AS ordinary_tokens_empty,
			       size(coalesce(r.observation_fact_fingerprints, [])) = 2
			         AND any(fingerprint IN r.observation_fact_fingerprints WHERE
			           fingerprint STARTS WITH $fingerprint_a)
			         AND any(fingerprint IN r.observation_fact_fingerprints WHERE
			           fingerprint STARTS WITH $fingerprint_b) AS fingerprints_exact`,
			map[string]any{
				"source":        sourceID,
				"target":        targetID,
				"tokens":        []string{observationToken(leftDomain, scanID), observationToken(rightDomain, scanID)},
				"fingerprint_a": observationFingerprintDomainPrefix(leftDomain),
				"fingerprint_b": observationFingerprintDomainPrefix(rightDomain),
			},
		)
		if err != nil {
			t.Fatalf("query dependency edge: %v", err)
		}
		if len(rows) != 1 {
			t.Fatalf("dependency rows = %+v", rows)
		}
		row := rows[0]
		if row["risk_weight"] != riskWeight || row["complete"] != true ||
			row["tokens_exact"] != true || row["ordinary_tokens_empty"] != true ||
			row["fingerprints_exact"] != true {
			t.Fatalf("dependency edge state = %+v, want scan %s risk %v", row, scanID, riskWeight)
		}
	}
	assertDependencyEdge("dependency-old", 0.1, domainA, domainB)

	// A complete refresh of both dependencies must keep one fully certified
	// relationship with only the current epoch's ownership evidence.
	if _, err := writer.WriteObservationEdges(
		ctx,
		[]ingest.Edge{edge},
		"dependency-exact",
		[]string{domainA, domainB},
	); err != nil {
		t.Fatalf("refresh exact dependency edge: %v", err)
	}
	if _, err := ReconcileObservations(
		ctx,
		db,
		"dependency-exact",
		[]string{domainA, domainB},
	); err != nil {
		t.Fatalf("reconcile exact dependencies: %v", err)
	}
	assertDependencyEdge("dependency-exact", 0.1, domainA, domainB)

	// A jointly observed property change is also authoritative when every
	// dependency domain is complete in the same epoch.
	changedEdge := edge
	changedEdge.Properties = map[string]any{"risk_weight": 0.2}
	if _, err := writer.WriteObservationEdges(
		ctx,
		[]ingest.Edge{changedEdge},
		"dependency-changed",
		[]string{domainA, domainB},
	); err != nil {
		t.Fatalf("refresh changed dependency edge: %v", err)
	}
	if _, err := ReconcileObservations(
		ctx,
		db,
		"dependency-changed",
		[]string{domainA, domainB},
	); err != nil {
		t.Fatalf("reconcile changed dependencies: %v", err)
	}
	assertDependencyEdge("dependency-changed", 0.2, domainA, domainB)

	// If one member of a jointly owned relationship moves to another complete
	// target scope, the current A+C evidence replaces A+B atomically. Retaining
	// B until reconciliation would make the missing-dependency pass delete the
	// relationship that this same artifact explicitly observed.
	transferredEdge := changedEdge
	transferredEdge.ObservationDomains = []string{domainA, domainC}
	transferredEdge.Properties = map[string]any{"risk_weight": 0.3}
	if _, err := writer.WriteObservationEdges(
		ctx,
		[]ingest.Edge{transferredEdge},
		"dependency-transferred",
		[]string{domainA, domainC},
	); err != nil {
		t.Fatalf("transfer dependency owner set: %v", err)
	}
	if _, err := ReconcileObservations(
		ctx,
		db,
		"dependency-transferred",
		[]string{domainA, domainC},
	); err != nil {
		t.Fatalf("reconcile transferred dependencies: %v", err)
	}
	assertDependencyEdge("dependency-transferred", 0.3, domainA, domainC)

	// Repeating the same complete A+C group is idempotent: it rotates the
	// epoch tokens, but neither accumulates owner evidence nor downgrades the
	// relationship.
	if _, err := writer.WriteObservationEdges(
		ctx,
		[]ingest.Edge{transferredEdge},
		"dependency-transferred-repeat",
		[]string{domainA, domainC},
	); err != nil {
		t.Fatalf("repeat transferred dependency owner set: %v", err)
	}
	if _, err := ReconcileObservations(
		ctx,
		db,
		"dependency-transferred-repeat",
		[]string{domainA, domainC},
	); err != nil {
		t.Fatalf("reconcile repeated transferred dependencies: %v", err)
	}
	assertDependencyEdge("dependency-transferred-repeat", 0.3, domainA, domainC)

	// Seeing A+D while only A is complete must fail closed. The writer may
	// retain the partial owner token as evidence, but it cannot install D's
	// semantic fingerprint or replace the last coherent A+C properties.
	partialEdge := transferredEdge
	partialEdge.ObservationDomains = []string{domainA, domainD}
	partialEdge.Properties = map[string]any{"risk_weight": 0.4}
	if _, err := writer.WriteObservationEdges(
		ctx,
		[]ingest.Edge{partialEdge},
		"dependency-partial",
		[]string{domainA},
	); err != nil {
		t.Fatalf("write partial dependency owner set: %v", err)
	}
	if _, err := ReconcileObservations(
		ctx,
		db,
		"dependency-partial",
		[]string{domainA},
	); err != nil {
		t.Fatalf("reconcile partial dependency owner set: %v", err)
	}
	rows, err := db.Query(ctx, `
		MATCH (:A2AAgent {objectid: $source})-[r:DELEGATES_TO]->
		      (:A2AAgent {objectid: $target})
		RETURN r.risk_weight AS risk_weight,
		       r.observation_properties_complete AS complete,
		       size(coalesce(r.observation_fact_fingerprints, [])) = 2
		         AND any(fingerprint IN r.observation_fact_fingerprints WHERE
		           fingerprint STARTS WITH $fingerprint_a)
		         AND any(fingerprint IN r.observation_fact_fingerprints WHERE
		           fingerprint STARTS WITH $fingerprint_c) AS coherent_fingerprints_preserved,
		       none(fingerprint IN coalesce(r.observation_fact_fingerprints, []) WHERE
		         fingerprint STARTS WITH $fingerprint_d) AS no_partial_fingerprint`,
		map[string]any{
			"source":        sourceID,
			"target":        targetID,
			"fingerprint_a": observationFingerprintDomainPrefix(domainA),
			"fingerprint_c": observationFingerprintDomainPrefix(domainC),
			"fingerprint_d": observationFingerprintDomainPrefix(domainD),
		},
	)
	if err != nil {
		t.Fatalf("query partial dependency edge: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("partial dependency rows = %+v", rows)
	}
	partialState := rows[0]
	if partialState["risk_weight"] != float64(0.3) ||
		partialState["complete"] != false ||
		partialState["coherent_fingerprints_preserved"] != true ||
		partialState["no_partial_fingerprint"] != true {
		t.Fatalf("partial dependency edge state = %+v, want preserved A+C properties and no D fingerprint", partialState)
	}

	// Once A+D is jointly complete, it atomically replaces every partial and
	// prior-group token/fingerprint and publishes the new semantic properties.
	if _, err := writer.WriteObservationEdges(
		ctx,
		[]ingest.Edge{partialEdge},
		"dependency-recovered",
		[]string{domainA, domainD},
	); err != nil {
		t.Fatalf("recover complete dependency owner set: %v", err)
	}
	if _, err := ReconcileObservations(
		ctx,
		db,
		"dependency-recovered",
		[]string{domainA, domainD},
	); err != nil {
		t.Fatalf("reconcile recovered dependency owner set: %v", err)
	}
	assertDependencyEdge("dependency-recovered", 0.4, domainA, domainD)

	if _, err := ReconcileObservations(
		ctx,
		db,
		"dependency-current",
		[]string{domainA},
	); err != nil {
		t.Fatalf("reconcile one dependency: %v", err)
	}
	rows, err = db.Query(
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

func TestIntegrationExactOwnerTransferPreservesOnlyRedundantFacts(t *testing.T) {
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
	tests := []struct {
		name             string
		retiredOnlyValue bool
		stripFingerprint bool
		wantComplete     bool
	}{
		{name: "exact", wantComplete: true},
		{name: "unique-retired-property", retiredOnlyValue: true},
		{name: "missing-retired-fingerprint", stripFingerprint: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serverID := "owner-transfer-server-" + tt.name
			hostID := "owner-transfer-host-" + tt.name
			oldDomain := "config:path:sha256:owner-transfer-old-" + tt.name
			newDomain := "config:path:sha256:owner-transfer-new-" + tt.name
			completeDomains := []string{oldDomain, newDomain}
			cleanup := func() {
				_, _ = db.ExecuteWrite(
					ctx,
					"MATCH (n) WHERE n.objectid IN $ids DETACH DELETE n",
					map[string]any{"ids": []string{serverID, hostID}},
				)
			}
			cleanup()
			defer cleanup()

			serverProperties := map[string]any{
				"endpoint":  "node owner-transfer.js",
				"transport": "stdio",
			}
			hostProperties := map[string]any{
				"hostname": "localhost",
				"scope":    "local",
			}
			edgeProperties := map[string]any{
				"confidence":   1.0,
				"is_composite": false,
				"last_seen":    "old",
				"risk_weight":  0.0,
				"scan_id":      "owner-transfer-old-" + tt.name,
			}
			if tt.retiredOnlyValue {
				serverProperties["retired_only"] = "must-not-certify"
				hostProperties["retired_only"] = "must-not-certify"
				edgeProperties["retired_only"] = "must-not-certify"
			}

			oldNodes := []ingest.Node{
				{
					ID: serverID, Kinds: []string{"MCPServer"},
					ObservationDomains: []string{oldDomain},
					Properties:         serverProperties,
				},
				{
					ID: hostID, Kinds: []string{"Host"},
					ObservationDomains: []string{oldDomain},
					Properties:         hostProperties,
				},
			}
			oldEdge := ingest.Edge{
				Source: serverID, Target: hostID, Kind: "RUNS_ON",
				SourceKind: "MCPServer", TargetKind: "Host",
				ObservationDomains: []string{oldDomain},
				Properties:         edgeProperties,
			}
			firstScan := "owner-transfer-first-" + tt.name
			if _, err := writer.WriteObservationNodes(
				ctx, oldNodes, firstScan, completeDomains,
			); err != nil {
				t.Fatalf("write old owner nodes: %v", err)
			}
			if _, err := writer.WriteObservationEdges(
				ctx, []ingest.Edge{oldEdge}, firstScan, completeDomains,
			); err != nil {
				t.Fatalf("write old owner edge: %v", err)
			}
			if _, err := ReconcileObservations(
				ctx, db, firstScan, completeDomains,
			); err != nil {
				t.Fatalf("reconcile old owner: %v", err)
			}

			if tt.stripFingerprint {
				if _, err := db.ExecuteWrite(ctx, `
					MATCH (server:MCPServer {objectid: $server})-[r:RUNS_ON]->
					      (host:Host {objectid: $host})
					REMOVE server.observation_fact_fingerprints,
					       host.observation_fact_fingerprints,
					       r.observation_fact_fingerprints`, map[string]any{
					"server": serverID,
					"host":   hostID,
				}); err != nil {
					t.Fatalf("strip legacy fingerprints: %v", err)
				}
			}

			newNodes := []ingest.Node{
				{
					ID: serverID, Kinds: []string{"MCPServer"},
					ObservationDomains: []string{newDomain},
					Properties: map[string]any{
						"endpoint": "node owner-transfer.js", "transport": "stdio",
					},
				},
				{
					ID: hostID, Kinds: []string{"Host"},
					ObservationDomains: []string{newDomain},
					Properties: map[string]any{
						"hostname": "localhost", "scope": "local",
					},
				},
			}
			newEdge := oldEdge
			newEdge.ObservationDomains = []string{newDomain}
			newEdge.Properties = map[string]any{
				"confidence":   1.0,
				"is_composite": false,
				"last_seen":    "new",
				"risk_weight":  0.0,
				"scan_id":      "owner-transfer-new-" + tt.name,
			}
			secondScan := "owner-transfer-second-" + tt.name
			if _, err := writer.WriteObservationNodes(
				ctx, newNodes, secondScan, completeDomains,
			); err != nil {
				t.Fatalf("write new owner nodes: %v", err)
			}
			if _, err := writer.WriteObservationEdges(
				ctx, []ingest.Edge{newEdge}, secondScan, completeDomains,
			); err != nil {
				t.Fatalf("write new owner edge: %v", err)
			}
			if _, err := ReconcileObservations(
				ctx, db, secondScan, completeDomains,
			); err != nil {
				t.Fatalf("reconcile owner transfer: %v", err)
			}

			rows, err := db.Query(ctx, `
				MATCH (server:MCPServer {objectid: $server})-[r:RUNS_ON]->
				      (host:Host {objectid: $host})
				RETURN server.observation_properties_complete AS server_complete,
				       host.observation_properties_complete AS host_complete,
				       r.observation_properties_complete AS edge_complete,
				       server.observation_tokens = [$new_token] AS server_token_exact,
				       host.observation_tokens = [$new_token] AS host_token_exact,
				       r.observation_tokens = [$new_token] AS edge_token_exact,
				       size(server.observation_fact_fingerprints) = 1 AND
				         all(fingerprint IN server.observation_fact_fingerprints WHERE
				           fingerprint STARTS WITH $new_fingerprint_prefix) AS server_fingerprint_exact,
				       size(host.observation_fact_fingerprints) = 1 AND
				         all(fingerprint IN host.observation_fact_fingerprints WHERE
				           fingerprint STARTS WITH $new_fingerprint_prefix) AS host_fingerprint_exact,
				       size(r.observation_fact_fingerprints) = 1 AND
				         all(fingerprint IN r.observation_fact_fingerprints WHERE
				           fingerprint STARTS WITH $new_fingerprint_prefix) AS edge_fingerprint_exact,
				       server.retired_only AS server_retired_only,
				       host.retired_only AS host_retired_only,
				       r.retired_only AS edge_retired_only`, map[string]any{
				"server":                 serverID,
				"host":                   hostID,
				"new_token":              observationToken(newDomain, secondScan),
				"new_fingerprint_prefix": observationFingerprintDomainPrefix(newDomain),
			})
			if err != nil {
				t.Fatalf("query owner transfer: %v", err)
			}
			if len(rows) != 1 {
				t.Fatalf("owner transfer rows = %+v", rows)
			}
			row := rows[0]
			if row["server_complete"] != tt.wantComplete ||
				row["host_complete"] != tt.wantComplete ||
				row["edge_complete"] != tt.wantComplete {
				t.Fatalf("owner transfer completeness = %+v, want %t", row, tt.wantComplete)
			}
			for _, key := range []string{
				"server_token_exact", "host_token_exact", "edge_token_exact",
				"server_fingerprint_exact", "host_fingerprint_exact", "edge_fingerprint_exact",
			} {
				if row[key] != true {
					t.Fatalf("owner transfer %s = %v; row=%+v", key, row[key], row)
				}
			}
			if tt.retiredOnlyValue {
				if row["server_retired_only"] != "must-not-certify" ||
					row["host_retired_only"] != "must-not-certify" ||
					row["edge_retired_only"] != "must-not-certify" {
					t.Fatalf("lossy transfer unexpectedly removed stale evidence: %+v", row)
				}
			} else if row["server_retired_only"] != nil ||
				row["host_retired_only"] != nil || row["edge_retired_only"] != nil {
				t.Fatalf("owner transfer fabricated retired-only evidence: %+v", row)
			}
		})
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
				"endpoint":         "http://mcp.example/mcp",
				"transport":        "http",
				"configured_name":  "old-config-name",
				"description_hash": "hash-old",
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
			"configured_evidence": "old-edge-value",
		},
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
		"mcp_evidence": "live-edge-value",
	}
	combinedNodes := append(append([]ingest.Node(nil), configNodes...), mcpNodes...)
	combinedDomains := []string{configScope, mcpScope}
	nodesWritten, err := writer.WriteObservationNodes(
		ctx, combinedNodes, "combined-scan", combinedDomains,
	)
	if err != nil {
		t.Fatalf("write combined owner nodes: %v", err)
	}
	if nodesWritten != 2 {
		t.Fatalf("combined node write rows = %d, want two unique nodes", nodesWritten)
	}
	edgesWritten, err := writer.WriteObservationEdges(
		ctx, []ingest.Edge{configEdge, mcpEdge}, "combined-scan", combinedDomains,
	)
	if err != nil {
		t.Fatalf("write combined owner edge: %v", err)
	}
	if edgesWritten != 1 {
		t.Fatalf("combined edge write rows = %d, want one unique relationship", edgesWritten)
	}
	if _, err := ReconcileObservations(
		ctx, db, "combined-scan", combinedDomains,
	); err != nil {
		t.Fatalf("reconcile combined owners: %v", err)
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

	// Each owner must be able to rotate its scan-scoped token independently
	// when the semantic fact it reports is byte-for-byte unchanged. Lifecycle
	// fields may change between scans without changing that semantic identity.
	configEdgeRefresh := configEdge
	configEdgeRefresh.Properties = cloneProperties(configEdge.Properties)
	configEdgeRefresh.Properties["scan_id"] = "config-refresh"
	configEdgeRefresh.Properties["last_seen"] = "refreshed"
	if _, err := writer.WriteObservationNodes(
		ctx, configNodes, "config-refresh", []string{configScope},
	); err != nil {
		t.Fatalf("refresh config nodes: %v", err)
	}
	if _, err := writer.WriteObservationEdges(
		ctx, []ingest.Edge{configEdgeRefresh}, "config-refresh", []string{configScope},
	); err != nil {
		t.Fatalf("refresh config edge: %v", err)
	}
	if _, err := ReconcileObservations(
		ctx, db, "config-refresh", []string{configScope},
	); err != nil {
		t.Fatalf("reconcile config refresh: %v", err)
	}
	if _, err := writer.WriteObservationNodes(
		ctx, configNodes, "config-refresh-2", []string{configScope},
	); err != nil {
		t.Fatalf("repeat exact config nodes: %v", err)
	}
	if _, err := writer.WriteObservationEdges(
		ctx, []ingest.Edge{configEdgeRefresh}, "config-refresh-2", []string{configScope},
	); err != nil {
		t.Fatalf("repeat exact config edge: %v", err)
	}
	if _, err := ReconcileObservations(
		ctx, db, "config-refresh-2", []string{configScope},
	); err != nil {
		t.Fatalf("reconcile repeated config refresh: %v", err)
	}
	rows, err = db.Query(ctx, `
		MATCH (server:MCPServer {objectid: $server})-[r:RUNS_ON]->(host:Host {objectid: $host})
		RETURN server.observation_properties_complete AS server_complete,
		       host.observation_properties_complete AS host_complete,
		       r.observation_properties_complete AS edge_complete,
		       size(server.observation_fact_fingerprints) AS server_fingerprints,
		       size(host.observation_fact_fingerprints) AS host_fingerprints,
		       size(r.observation_fact_fingerprints) AS edge_fingerprints`,
		map[string]any{"server": nodeID, "host": targetID})
	if err != nil {
		t.Fatalf("query repeated config refresh: %v", err)
	}
	if len(rows) != 1 || rows[0]["server_complete"] != true ||
		rows[0]["host_complete"] != true || rows[0]["edge_complete"] != true ||
		rows[0]["server_fingerprints"] != int64(2) ||
		rows[0]["host_fingerprints"] != int64(2) ||
		rows[0]["edge_fingerprints"] != int64(2) {
		t.Fatalf("repeated exact config refresh lost certification: %+v", rows)
	}

	mcpEdgeRefresh := mcpEdge
	mcpEdgeRefresh.Properties = cloneProperties(mcpEdge.Properties)
	mcpEdgeRefresh.Properties["scan_id"] = "mcp-refresh"
	mcpEdgeRefresh.Properties["last_seen"] = "refreshed"
	if _, err := writer.WriteObservationNodes(
		ctx, mcpNodes, "mcp-refresh", []string{mcpScope},
	); err != nil {
		t.Fatalf("refresh MCP nodes: %v", err)
	}
	if _, err := writer.WriteObservationEdges(
		ctx, []ingest.Edge{mcpEdgeRefresh}, "mcp-refresh", []string{mcpScope},
	); err != nil {
		t.Fatalf("refresh MCP edge: %v", err)
	}
	if _, err := ReconcileObservations(
		ctx, db, "mcp-refresh", []string{mcpScope},
	); err != nil {
		t.Fatalf("reconcile MCP refresh: %v", err)
	}
	rows, err = db.Query(ctx, `
		MATCH (server:MCPServer {objectid: $server})-[r:RUNS_ON]->(host:Host {objectid: $host})
		RETURN server.observation_properties_complete AS server_complete,
		       host.observation_properties_complete AS host_complete,
		       r.observation_properties_complete AS edge_complete,
		       size(server.observation_fact_fingerprints) AS server_fingerprints,
		       size(host.observation_fact_fingerprints) AS host_fingerprints,
		       size(r.observation_fact_fingerprints) AS edge_fingerprints`,
		map[string]any{"server": nodeID, "host": targetID})
	if err != nil {
		t.Fatalf("query exact co-owner refresh: %v", err)
	}
	if len(rows) != 1 || rows[0]["server_complete"] != true ||
		rows[0]["host_complete"] != true || rows[0]["edge_complete"] != true ||
		rows[0]["server_fingerprints"] != int64(2) ||
		rows[0]["host_fingerprints"] != int64(2) ||
		rows[0]["edge_fingerprints"] != int64(2) {
		t.Fatalf("exact co-owner refresh became incomplete: %+v", rows)
	}

	changedConfigNodes := append([]ingest.Node(nil), configNodes...)
	changedConfigNodes[0].Properties = cloneProperties(configNodes[0].Properties)
	changedConfigNodes[0].Properties["configured_name"] = "new-config-name"
	changedConfigNodes[0].Properties["description_hash"] = "hash-new"
	changedConfigNodes[0].Properties["changed_only"] = true
	changedConfigEdge := configEdgeRefresh
	changedConfigEdge.Properties = cloneProperties(configEdgeRefresh.Properties)
	changedConfigEdge.Properties["scan_id"] = "config-changed"
	changedConfigEdge.Properties["configured_evidence"] = "new-edge-value"
	changedConfigEdge.Properties["changed_only"] = true
	if _, err := writer.WriteObservationNodes(
		ctx, changedConfigNodes, "config-changed", []string{configScope},
	); err != nil {
		t.Fatalf("write changed config nodes: %v", err)
	}
	if _, err := writer.WriteObservationEdges(
		ctx, []ingest.Edge{changedConfigEdge}, "config-changed", []string{configScope},
	); err != nil {
		t.Fatalf("write changed config edge: %v", err)
	}
	if _, err := ReconcileObservations(
		ctx, db, "config-changed", []string{configScope},
	); err != nil {
		t.Fatalf("reconcile changed config: %v", err)
	}
	rows, err = db.Query(ctx, `
		MATCH (server:MCPServer {objectid: $server})-[r:RUNS_ON]->(host:Host {objectid: $host})
		RETURN server.observation_properties_complete AS server_complete,
		       host.observation_properties_complete AS host_complete,
		       r.observation_properties_complete AS edge_complete,
		       server.configured_name AS configured_name,
		       server.description_hash AS description_hash,
		       server.changed_only AS server_changed_only,
		       r.configured_evidence AS configured_evidence,
		       r.changed_only AS edge_changed_only`,
		map[string]any{"server": nodeID, "host": targetID})
	if err != nil {
		t.Fatalf("query changed co-owner fact: %v", err)
	}
	if len(rows) != 1 || rows[0]["server_complete"] != false ||
		rows[0]["host_complete"] != true || rows[0]["edge_complete"] != false ||
		rows[0]["configured_name"] != "old-config-name" ||
		rows[0]["description_hash"] != "hash-old" ||
		rows[0]["server_changed_only"] != nil ||
		rows[0]["configured_evidence"] != "old-edge-value" ||
		rows[0]["edge_changed_only"] != nil {
		t.Fatalf("changed co-owner fact did not fail closed: %+v", rows)
	}

	// An old semantic retry must not re-certify a union after an incompatible
	// refresh. The incompatible attempt cannot mutate the last coherent public
	// properties, and its owner fingerprint stays invalidated until every
	// active owner jointly replaces the fact.
	if _, err := writer.WriteObservationNodes(
		ctx, configNodes, "config-old-retry", []string{configScope},
	); err != nil {
		t.Fatalf("retry old config nodes: %v", err)
	}
	if _, err := writer.WriteObservationEdges(
		ctx, []ingest.Edge{configEdgeRefresh}, "config-old-retry", []string{configScope},
	); err != nil {
		t.Fatalf("retry old config edge: %v", err)
	}
	if _, err := ReconcileObservations(
		ctx, db, "config-old-retry", []string{configScope},
	); err != nil {
		t.Fatalf("reconcile old config retry: %v", err)
	}
	rows, err = db.Query(ctx, `
		MATCH (server:MCPServer {objectid: $server})-[r:RUNS_ON]->(host:Host {objectid: $host})
		RETURN server.observation_properties_complete AS server_complete,
		       host.observation_properties_complete AS host_complete,
		       r.observation_properties_complete AS edge_complete,
		       server.configured_name AS configured_name,
		       server.description_hash AS description_hash,
		       server.changed_only AS server_changed_only,
		       r.configured_evidence AS configured_evidence,
		       r.changed_only AS edge_changed_only`,
		map[string]any{"server": nodeID, "host": targetID})
	if err != nil {
		t.Fatalf("query old semantic retry: %v", err)
	}
	if len(rows) != 1 || rows[0]["server_complete"] != false ||
		rows[0]["host_complete"] != true || rows[0]["edge_complete"] != false ||
		rows[0]["configured_name"] != "old-config-name" ||
		rows[0]["description_hash"] != "hash-old" ||
		rows[0]["server_changed_only"] != nil ||
		rows[0]["configured_evidence"] != "old-edge-value" ||
		rows[0]["edge_changed_only"] != nil {
		t.Fatalf("old semantic retry re-certified an invalid union: %+v", rows)
	}

	restoredNodes := append(append([]ingest.Node(nil), changedConfigNodes...), mcpNodes...)
	if _, err := writer.WriteObservationNodes(
		ctx, restoredNodes, "combined-restore", combinedDomains,
	); err != nil {
		t.Fatalf("restore combined owner nodes: %v", err)
	}
	if _, err := writer.WriteObservationEdges(
		ctx, []ingest.Edge{changedConfigEdge, mcpEdge}, "combined-restore", combinedDomains,
	); err != nil {
		t.Fatalf("restore combined owner edge: %v", err)
	}
	if _, err := ReconcileObservations(
		ctx, db, "combined-restore", combinedDomains,
	); err != nil {
		t.Fatalf("reconcile combined restore: %v", err)
	}
	rows, err = db.Query(ctx, `
		MATCH (server:MCPServer {objectid: $server})-[r:RUNS_ON]->(host:Host {objectid: $host})
		RETURN server.observation_properties_complete AS server_complete,
		       host.observation_properties_complete AS host_complete,
		       r.observation_properties_complete AS edge_complete,
		       server.configured_name AS configured_name,
		       server.description_hash AS description_hash,
		       server.previous_description_hash AS previous_description_hash,
		       server.changed_only AS server_changed_only,
		       r.configured_evidence AS configured_evidence,
		       r.changed_only AS edge_changed_only,
		       r.mcp_evidence AS mcp_evidence,
		       size(server.observation_fact_fingerprints) AS server_fingerprints,
		       size(r.observation_fact_fingerprints) AS edge_fingerprints`,
		map[string]any{"server": nodeID, "host": targetID})
	if err != nil {
		t.Fatalf("query combined restore: %v", err)
	}
	if len(rows) != 1 || rows[0]["server_complete"] != true ||
		rows[0]["host_complete"] != true || rows[0]["edge_complete"] != true ||
		rows[0]["configured_name"] != "new-config-name" ||
		rows[0]["description_hash"] != "hash-new" ||
		rows[0]["previous_description_hash"] != "hash-old" ||
		rows[0]["server_changed_only"] != true ||
		rows[0]["configured_evidence"] != "new-edge-value" ||
		rows[0]["edge_changed_only"] != true ||
		rows[0]["mcp_evidence"] != "live-edge-value" ||
		rows[0]["server_fingerprints"] != int64(2) ||
		rows[0]["edge_fingerprints"] != int64(2) {
		t.Fatalf("combined replacement did not restore clean union: %+v", rows)
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

	if _, err := writer.WriteObservationNodes(
		ctx, changedConfigNodes, "config-after-retirement", []string{configScope},
	); err != nil {
		t.Fatalf("refresh config after MCP retirement: %v", err)
	}
	if _, err := writer.WriteObservationEdges(
		ctx, []ingest.Edge{changedConfigEdge}, "config-after-retirement", []string{configScope},
	); err != nil {
		t.Fatalf("refresh config edge after MCP retirement: %v", err)
	}
	if _, err := ReconcileObservations(
		ctx, db, "config-after-retirement", []string{configScope},
	); err != nil {
		t.Fatalf("reconcile config after MCP retirement: %v", err)
	}
	rows, err = db.Query(ctx, `
		MATCH (server:MCPServer {objectid: $server})-[r:RUNS_ON]->(host:Host {objectid: $host})
		RETURN server.observation_properties_complete AS server_complete,
		       host.observation_properties_complete AS host_complete,
		       r.observation_properties_complete AS edge_complete,
		       server.protocol_version AS protocol_version,
		       host.scope AS host_scope,
		       r.mcp_evidence AS mcp_evidence,
		       server.configured_name AS configured_name,
		       r.configured_evidence AS configured_evidence,
		       size(server.observation_fact_fingerprints) AS server_fingerprints,
		       size(host.observation_fact_fingerprints) AS host_fingerprints,
		       size(r.observation_fact_fingerprints) AS edge_fingerprints`,
		map[string]any{"server": nodeID, "host": targetID})
	if err != nil {
		t.Fatalf("query config recovery after MCP retirement: %v", err)
	}
	if len(rows) != 1 || rows[0]["server_complete"] != true ||
		rows[0]["host_complete"] != true || rows[0]["edge_complete"] != true ||
		rows[0]["protocol_version"] != nil || rows[0]["host_scope"] != nil ||
		rows[0]["mcp_evidence"] != nil ||
		rows[0]["configured_name"] != "new-config-name" ||
		rows[0]["configured_evidence"] != "new-edge-value" ||
		rows[0]["server_fingerprints"] != int64(1) ||
		rows[0]["host_fingerprints"] != int64(1) ||
		rows[0]["edge_fingerprints"] != int64(1) {
		t.Fatalf("remaining config owner did not recover exact projection: %+v", rows)
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
