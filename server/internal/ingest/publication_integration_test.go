package ingest

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/adithyan-ak/agenthound/sdk/common"
	sdkingest "github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/server/internal/appdb"
	"github.com/adithyan-ak/agenthound/server/internal/graph"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func freshPublicationIntegrationHarness(
	t *testing.T,
) (context.Context, *Pipeline, *graph.DB, *graph.Writer, *pgxpool.Pool) {
	return publicationIntegrationHarness(t, true)
}

func publicationIntegrationHarness(
	t *testing.T,
	requireFreshOptIn bool,
) (context.Context, *Pipeline, *graph.DB, *graph.Writer, *pgxpool.Pool) {
	t.Helper()
	if requireFreshOptIn && os.Getenv("AGENTHOUND_FRESH_DB_INTEGRATION") != "1" {
		t.Skip("set AGENTHOUND_FRESH_DB_INTEGRATION=1 for destructive fresh-database integration")
	}
	neo4jURI := os.Getenv("AGENTHOUND_NEO4J_URI")
	pgURI := os.Getenv("AGENTHOUND_PG_URI")
	if neo4jURI == "" || pgURI == "" {
		t.Skip("AGENTHOUND_NEO4J_URI and AGENTHOUND_PG_URI are required")
	}

	ctx := context.Background()
	driver, err := graph.NewDriver(
		neo4jURI,
		os.Getenv("AGENTHOUND_NEO4J_USER"),
		os.Getenv("AGENTHOUND_NEO4J_PASSWORD"),
	)
	if err != nil {
		t.Fatalf("connect neo4j: %v", err)
	}
	t.Cleanup(func() { _ = driver.Close(ctx) })
	writer := graph.NewWriter(driver)
	db := graph.NewDB(graph.NewReader(driver), writer)
	if _, err := db.ExecuteWrite(ctx, "MATCH (n) DETACH DELETE n", nil); err != nil {
		t.Fatalf("reset neo4j: %v", err)
	}
	t.Cleanup(func() {
		if _, err := db.ExecuteWrite(ctx, "MATCH (n) DETACH DELETE n", nil); err != nil {
			t.Errorf("clean neo4j integration data: %v", err)
		}
	})
	if err := graph.InitSchema(ctx, driver); err != nil {
		t.Fatalf("initialize neo4j schema: %v", err)
	}

	admin, err := appdb.NewPool(pgURI)
	if err != nil {
		t.Fatalf("connect postgres: %v", err)
	}
	schema := fmt.Sprintf("agenthound_publication_test_%d", time.Now().UnixNano())
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+quotedSchema); err != nil {
		admin.Close()
		t.Fatalf("create isolated postgres schema: %v", err)
	}
	config, err := pgxpool.ParseConfig(pgURI)
	if err != nil {
		admin.Close()
		t.Fatalf("parse postgres config: %v", err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		admin.Close()
		t.Fatalf("connect isolated postgres schema: %v", err)
	}
	t.Cleanup(func() {
		pool.Close()
		if _, err := admin.Exec(ctx, "DROP SCHEMA "+quotedSchema+" CASCADE"); err != nil {
			t.Errorf("drop isolated postgres schema: %v", err)
		}
		admin.Close()
	})
	if err := appdb.RunMigrations(ctx, pool); err != nil {
		t.Fatalf("migrate postgres: %v", err)
	}

	return ctx, NewPipeline(
		writer,
		db,
		appdb.NewScanStore(pool),
		appdb.NewFindingStore(pool),
		allowStorageVerifier{},
	), db, writer, pool
}

func authoritativeMCPReport(
	root string,
	children ...string,
) *sdkingest.CollectionReport {
	report := &sdkingest.CollectionReport{
		State:        sdkingest.OutcomeComplete,
		CoverageKeys: append(append([]string(nil), children...), root),
		AuthoritativeRoots: []sdkingest.CoverageRoot{{
			CoverageKey:       root,
			ChildCoverageKeys: append([]string(nil), children...),
		}},
	}
	for _, child := range children {
		report.Outcomes = append(report.Outcomes, sdkingest.CollectionOutcome{
			Collector:   "mcp",
			CoverageKey: child,
			Target:      child,
			Method:      "enumerate",
			State:       sdkingest.OutcomeComplete,
			Items:       1,
		})
	}
	report.Outcomes = append(report.Outcomes, sdkingest.CollectionOutcome{
		Collector:   "mcp",
		CoverageKey: root,
		Target:      "mcp",
		Method:      "collect",
		State:       sdkingest.OutcomeComplete,
	})
	return report
}

func newPublicationIntegrationData(collector, scanID string) *sdkingest.IngestData {
	data := common.NewIngestData(collector, scanID)
	data.Meta.Identity = testCollectionIdentity()
	return data
}

func TestIntegrationFreshSchemaCompleteIngestPublishes(t *testing.T) {
	if os.Getenv("AGENTHOUND_FRESH_DB_INTEGRATION") != "1" {
		t.Skip("set AGENTHOUND_FRESH_DB_INTEGRATION=1 for destructive fresh-database integration")
	}
	neo4jURI := os.Getenv("AGENTHOUND_NEO4J_URI")
	pgURI := os.Getenv("AGENTHOUND_PG_URI")
	if neo4jURI == "" || pgURI == "" {
		t.Skip("AGENTHOUND_NEO4J_URI and AGENTHOUND_PG_URI are required")
	}

	ctx := context.Background()
	driver, err := graph.NewDriver(
		neo4jURI,
		os.Getenv("AGENTHOUND_NEO4J_USER"),
		os.Getenv("AGENTHOUND_NEO4J_PASSWORD"),
	)
	if err != nil {
		t.Fatalf("connect neo4j: %v", err)
	}
	defer func() { _ = driver.Close(ctx) }()
	db := graph.NewDB(graph.NewReader(driver), graph.NewWriter(driver))
	if _, err := db.ExecuteWrite(ctx, "MATCH (n) DETACH DELETE n", nil); err != nil {
		t.Fatalf("reset neo4j: %v", err)
	}
	if err := graph.InitSchema(ctx, driver); err != nil {
		t.Fatalf("initialize neo4j schema: %v", err)
	}

	pool, err := appdb.NewPool(pgURI)
	if err != nil {
		t.Fatalf("connect postgres: %v", err)
	}
	defer pool.Close()
	if err := appdb.RunMigrations(ctx, pool); err != nil {
		t.Fatalf("migrate postgres: %v", err)
	}
	if _, err := pool.Exec(ctx, `
TRUNCATE scans, posture_state RESTART IDENTITY CASCADE;
INSERT INTO posture_state (singleton) VALUES (TRUE);`); err != nil {
		t.Fatalf("reset postgres lifecycle: %v", err)
	}

	writer := graph.NewWriter(driver)
	pipeline := NewPipeline(
		writer,
		graph.NewDB(graph.NewReader(driver), writer),
		appdb.NewScanStore(pool),
		appdb.NewFindingStore(pool),
		allowStorageVerifier{},
	)
	scope := sdkingest.CanonicalCoverageKey(
		"mcp",
		"target",
		sdkingest.CanonicalURLScope("http://127.0.0.1:18080/mcp"),
	)
	data := newPublicationIntegrationData("mcp", "fresh-publication")
	data.Meta.Collection = &sdkingest.CollectionReport{
		State:        sdkingest.OutcomeComplete,
		CoverageKeys: []string{scope},
		Outcomes: []sdkingest.CollectionOutcome{{
			Collector:   "mcp",
			CoverageKey: scope,
			Target:      "http://127.0.0.1:18080/mcp",
			Method:      "initialize",
			State:       sdkingest.OutcomeComplete,
			Items:       1,
		}},
	}
	data.Graph.Nodes = []sdkingest.Node{{
		ID:                 "fresh-publication-server",
		Kinds:              []string{"MCPServer"},
		ObservationDomains: []string{scope},
		Properties: map[string]any{
			"name":           "fresh-publication-server",
			"transport":      "http",
			"endpoint":       "http://127.0.0.1:18080/mcp",
			"auth_method":    "none",
			"auth_assurance": "unauthenticated",
			"auth_evidence":  "anonymous_probe_succeeded",
		},
	}}

	result, err := pipeline.Ingest(ctx, data)
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if result.PublishedRevision == nil {
		t.Fatalf("complete fresh ingest did not publish: %+v", result)
	}
	if result.Outcome != sdkingest.OutcomeComplete {
		t.Fatalf("outcome = %q, want complete", result.Outcome)
	}
}

func TestIntegrationExhaustiveRootRemovesMissingChildAcrossGraphAndPublication(t *testing.T) {
	ctx, pipeline, db, _, pool := freshPublicationIntegrationHarness(t)
	root := sdkingest.CanonicalCoverageKey("mcp", "root", "collect")
	childA := sdkingest.CanonicalCoverageKey(
		"mcp",
		"target",
		sdkingest.CanonicalURLScope("http://127.0.0.1:18081/mcp"),
	)
	childB := sdkingest.CanonicalCoverageKey(
		"mcp",
		"target",
		sdkingest.CanonicalURLScope("http://127.0.0.1:18082/mcp"),
	)
	node := func(id, name, endpoint, scope string) sdkingest.Node {
		return sdkingest.Node{
			ID:                 id,
			Kinds:              []string{"MCPServer"},
			ObservationDomains: []string{scope},
			Properties: map[string]any{
				"name":           name,
				"transport":      "http",
				"endpoint":       endpoint,
				"auth_method":    "none",
				"auth_assurance": "unauthenticated",
				"auth_evidence":  "anonymous_probe_succeeded",
			},
		}
	}

	first := newPublicationIntegrationData("scan", "removed-child-first")
	first.Meta.Collection = authoritativeMCPReport(root, childA, childB)
	first.Graph.Nodes = []sdkingest.Node{
		node("removed-child-a", "server-a", "http://127.0.0.1:18081/mcp", childA),
		node("removed-child-b", "server-b", "http://127.0.0.1:18082/mcp", childB),
	}
	firstResult, err := pipeline.Ingest(ctx, first)
	if err != nil {
		t.Fatalf("first ingest: %v", err)
	}
	if firstResult.PublishedRevision == nil {
		t.Fatalf("first active set did not publish: %+v", firstResult)
	}

	second := newPublicationIntegrationData("scan", "removed-child-second")
	second.Meta.Collection = authoritativeMCPReport(root, childB)
	second.Graph.Nodes = []sdkingest.Node{
		node("removed-child-b", "server-b", "http://127.0.0.1:18082/mcp", childB),
	}
	secondResult, err := pipeline.Ingest(ctx, second)
	if err != nil {
		t.Fatalf("second ingest: %v", err)
	}
	if secondResult.Outcome != sdkingest.OutcomeComplete ||
		secondResult.PublishedRevision == nil {
		t.Fatalf("replacement active set did not publish: %+v", secondResult)
	}

	rows, err := db.Query(
		ctx,
		`MATCH (n) WHERE n.objectid IN $ids
		 RETURN collect(n.objectid) AS ids`,
		map[string]any{"ids": []string{"removed-child-a", "removed-child-b"}},
	)
	if err != nil {
		t.Fatalf("query graph active set: %v", err)
	}
	ids, _ := rows[0]["ids"].([]any)
	if len(ids) != 1 || ids[0] != "removed-child-b" {
		t.Fatalf("graph active children = %v, want removed-child-b only", ids)
	}
	var removedHeads int
	if err := pool.QueryRow(
		ctx,
		`SELECT count(*) FROM coverage_heads WHERE coverage_key = $1`,
		childA,
	).Scan(&removedHeads); err != nil {
		t.Fatalf("query removed coverage head: %v", err)
	}
	if removedHeads != 0 {
		t.Fatalf("removed child coverage heads = %d, want 0", removedHeads)
	}
	state, err := appdb.NewFindingStore(pool).GetProjectionState(ctx)
	if err != nil {
		t.Fatalf("get projection state: %v", err)
	}
	if state.Status != "complete" || len(state.DirtyCoverage) != 0 {
		t.Fatalf("projection state after child removal = %+v", state)
	}
}

func TestIntegrationCompleteEmptyRootRecoversFailedUnheadedChildAfterRestart(t *testing.T) {
	ctx, pipeline, db, writer, pool := freshPublicationIntegrationHarness(t)
	root := sdkingest.CollectorRootCoverageKey("mcp")
	failedChild := sdkingest.CanonicalCoverageKey(
		"mcp",
		"target",
		sdkingest.CanonicalURLScope("http://127.0.0.1:18084/mcp"),
	)

	failed := newPublicationIntegrationData("mcp", "failed-unheaded-child")
	failed.Meta.Collection = &sdkingest.CollectionReport{
		State:        sdkingest.OutcomeFailed,
		CoverageKeys: []string{failedChild},
		Outcomes: []sdkingest.CollectionOutcome{{
			Collector:   "mcp",
			CoverageKey: failedChild,
			Target:      "http://127.0.0.1:18084/mcp",
			Method:      "initialize",
			State:       sdkingest.OutcomeFailed,
			Error:       "connection failed",
		}},
	}
	failedResult, err := pipeline.Ingest(ctx, failed)
	if err != nil {
		t.Fatalf("failed child ingest: %v", err)
	}
	if failedResult.Outcome != sdkingest.OutcomePartial ||
		failedResult.PublishedRevision != nil {
		t.Fatalf("failed child result = %+v, want unpublished partial", failedResult)
	}
	var failedHeadCount int
	if err := pool.QueryRow(
		ctx,
		`SELECT count(*) FROM coverage_heads WHERE coverage_key = $1`,
		failedChild,
	).Scan(&failedHeadCount); err != nil {
		t.Fatalf("query failed child head: %v", err)
	}
	if failedHeadCount != 0 {
		t.Fatalf("failed child head count = %d, want 0", failedHeadCount)
	}
	state, err := appdb.NewFindingStore(pool).GetProjectionState(ctx)
	if err != nil {
		t.Fatalf("get failed projection state: %v", err)
	}
	if len(state.DirtyCoverage) != 1 || state.DirtyCoverage[0] != failedChild {
		t.Fatalf("failed projection dirty coverage = %v, want [%s]", state.DirtyCoverage, failedChild)
	}

	restarted := NewPipeline(
		writer,
		db,
		appdb.NewScanStore(pool),
		appdb.NewFindingStore(pool),
		allowStorageVerifier{},
	)
	completeEmpty := newPublicationIntegrationData("mcp", "complete-empty-after-restart")
	completeEmpty.Meta.Collection = authoritativeMCPReport(root)
	recovered, err := restarted.Ingest(ctx, completeEmpty)
	if err != nil {
		t.Fatalf("complete-empty ingest: %v", err)
	}
	if recovered.Outcome != sdkingest.OutcomeComplete ||
		recovered.PublishedRevision == nil {
		t.Fatalf("complete-empty recovery = %+v, want published complete", recovered)
	}
	state, err = appdb.NewFindingStore(pool).GetProjectionState(ctx)
	if err != nil {
		t.Fatalf("get recovered projection state: %v", err)
	}
	if state.Status != "complete" || len(state.DirtyCoverage) != 0 {
		t.Fatalf("recovered projection state = %+v", state)
	}
}

func TestIntegrationTokenlessAgentWithholdsPublication(t *testing.T) {
	ctx, pipeline, db, writer, pool := freshPublicationIntegrationHarness(t)
	configScope := sdkingest.CanonicalCoverageKey(
		"config",
		"path",
		"/tmp/tokenless-config.json",
	)
	instructionScope := sdkingest.CanonicalCoverageKey(
		"config",
		"path",
		"/tmp/CLAUDE.md",
	)
	if _, err := writer.WriteObservationNodes(
		ctx,
		[]sdkingest.Node{
			{
				ID:                 "tokenless-agent",
				Kinds:              []string{"AgentInstance"},
				ObservationDomains: []string{configScope},
				Properties:         map[string]any{"name": "tokenless-agent"},
			},
			{
				ID:                 "tokenless-instruction",
				Kinds:              []string{"InstructionFile"},
				ObservationDomains: []string{instructionScope},
				Properties:         map[string]any{"path": "/tmp/CLAUDE.md"},
			},
		},
		"tokenless-seed",
		[]string{configScope, instructionScope},
	); err != nil {
		t.Fatalf("seed observation nodes: %v", err)
	}
	if _, err := writer.WriteObservationEdges(
		ctx,
		[]sdkingest.Edge{{
			Source:             "tokenless-agent",
			Target:             "tokenless-instruction",
			Kind:               "LOADS_INSTRUCTIONS",
			SourceKind:         "AgentInstance",
			TargetKind:         "InstructionFile",
			Properties:         map[string]any{"risk_weight": 0.1},
			ObservationDomains: []string{instructionScope},
		}},
		"tokenless-seed",
		[]string{configScope, instructionScope},
	); err != nil {
		t.Fatalf("seed observation edge: %v", err)
	}
	if _, err := graph.ReconcileObservations(
		ctx,
		db,
		"tokenless-retire-config",
		[]string{configScope},
	); err != nil {
		t.Fatalf("retire config owner: %v", err)
	}

	scope := sdkingest.CanonicalCoverageKey(
		"mcp",
		"target",
		sdkingest.CanonicalURLScope("http://127.0.0.1:18083/mcp"),
	)
	data := newPublicationIntegrationData("mcp", "tokenless-publication")
	data.Meta.Collection = &sdkingest.CollectionReport{
		State:        sdkingest.OutcomeComplete,
		CoverageKeys: []string{scope},
		Outcomes: []sdkingest.CollectionOutcome{{
			Collector:   "mcp",
			CoverageKey: scope,
			Target:      "http://127.0.0.1:18083/mcp",
			Method:      "initialize",
			State:       sdkingest.OutcomeComplete,
			Items:       1,
		}},
	}
	data.Graph.Nodes = []sdkingest.Node{{
		ID:                 "tokenless-control-server",
		Kinds:              []string{"MCPServer"},
		ObservationDomains: []string{scope},
		Properties: map[string]any{
			"name":           "control-server",
			"transport":      "http",
			"endpoint":       "http://127.0.0.1:18083/mcp",
			"auth_method":    "none",
			"auth_assurance": "unauthenticated",
			"auth_evidence":  "anonymous_probe_succeeded",
		},
	}}

	result, err := pipeline.Ingest(ctx, data)
	if err != nil {
		t.Fatalf("ingest with tokenless residue: %v", err)
	}
	if result.Outcome != sdkingest.OutcomePartial ||
		result.PublishedRevision != nil {
		t.Fatalf("tokenless publication result = %+v, want withheld", result)
	}
	completeness, err := graph.GetObservationCompleteness(ctx, db)
	if err != nil {
		t.Fatalf("get tokenless completeness: %v", err)
	}
	if completeness.TokenlessNodes != 1 ||
		completeness.TokenlessIncidentRelationships != 1 {
		t.Fatalf("tokenless completeness = %+v", completeness)
	}
	state, err := appdb.NewFindingStore(pool).GetProjectionState(ctx)
	if err != nil {
		t.Fatalf("get withheld projection state: %v", err)
	}
	if state.PublishedRevision != nil ||
		state.Status != "incomplete" ||
		len(state.DirtyCoverage) != 1 ||
		state.DirtyCoverage[0] != scope {
		t.Fatalf("tokenless projection state = %+v", state)
	}
}
