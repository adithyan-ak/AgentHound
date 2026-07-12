package ingest

import (
	"context"
	"os"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/common"
	sdkingest "github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/server/internal/appdb"
	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

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
	)
	scope := sdkingest.CanonicalCoverageKey(
		"mcp",
		"target",
		sdkingest.CanonicalURLScope("http://127.0.0.1:18080/mcp"),
	)
	data := common.NewIngestData("mcp", "fresh-publication")
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
