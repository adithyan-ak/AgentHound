package cli

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/adithyan-ak/agenthound/server/internal/appdb"
	"github.com/adithyan-ak/agenthound/server/internal/graph"
	"github.com/adithyan-ak/agenthound/server/internal/ingest"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

type Infrastructure struct {
	Neo4jDriver neo4j.DriverWithContext
	PGPool      *pgxpool.Pool
	Writer      *graph.Writer
	Reader      *graph.Reader
	GraphDB     graph.GraphDB
	ScanStore   *appdb.ScanStore
	Pipeline    *ingest.Pipeline
}

func Bootstrap(ctx context.Context) (*Infrastructure, func(), error) {
	neo4jDriver, err := graph.NewDriver(cfg.Neo4jURI, cfg.Neo4jUser, cfg.Neo4jPassword)
	if err != nil {
		return nil, nil, fmt.Errorf("neo4j: %w", err)
	}
	slog.Info("connected to neo4j", "uri", cfg.Neo4jURI)

	pgPool, err := appdb.NewPool(cfg.PostgresURI)
	if err != nil {
		neo4jDriver.Close(ctx)
		return nil, nil, fmt.Errorf("postgres: %w", err)
	}
	slog.Info("connected to postgres")

	if err := graph.InitSchema(ctx, neo4jDriver); err != nil {
		pgPool.Close()
		neo4jDriver.Close(ctx)
		return nil, nil, fmt.Errorf("neo4j schema: %w", err)
	}
	if err := appdb.RunMigrations(ctx, pgPool); err != nil {
		pgPool.Close()
		neo4jDriver.Close(ctx)
		return nil, nil, fmt.Errorf("postgres migrations: %w", err)
	}

	writer := graph.NewWriter(neo4jDriver)
	reader := graph.NewReader(neo4jDriver)
	graphDB := graph.NewDB(reader, writer)
	scanStore := appdb.NewScanStore(pgPool)
	pipeline := ingest.NewPipeline(writer, graphDB, scanStore)

	cleanup := func() {
		pgPool.Close()
		neo4jDriver.Close(ctx)
	}

	return &Infrastructure{
		Neo4jDriver: neo4jDriver,
		PGPool:      pgPool,
		Writer:      writer,
		Reader:      reader,
		GraphDB:     graphDB,
		ScanStore:   scanStore,
		Pipeline:    pipeline,
	}, cleanup, nil
}
