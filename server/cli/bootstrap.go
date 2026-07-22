package cli

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/adithyan-ak/agenthound/server/internal/appdb"
	"github.com/adithyan-ak/agenthound/server/internal/binding"
	"github.com/adithyan-ak/agenthound/server/internal/graph"
	"github.com/adithyan-ak/agenthound/server/internal/ingest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

type Infrastructure struct {
	Neo4jDriver  neo4j.DriverWithContext
	PGPool       *pgxpool.Pool
	Writer       *graph.Writer
	Reader       *graph.Reader
	GraphDB      graph.GraphDB
	ScanStore    *appdb.ScanStore
	FindingStore *appdb.FindingStore
	Pipeline     *ingest.Pipeline
}

func Bootstrap(ctx context.Context) (*Infrastructure, func(), error) {
	// Cheap TCP probe BEFORE the real driver init so a stopped DB
	// stack produces a friendly, actionable error block instead of a
	// generic "dial tcp ...: connect: connection refused" trailer.
	if err := runtimePreflight(ctx, cfg); err != nil {
		return nil, nil, err
	}

	neo4jDriver, err := graph.NewDriver(cfg.Neo4jURI, cfg.Neo4jUser, cfg.Neo4jPassword)
	if err != nil {
		return nil, nil, classifyDriverError("Neo4j", cfg.Neo4jURI, err)
	}
	slog.Info("connected to neo4j", "uri", cfg.Neo4jURI)

	pgPool, err := appdb.NewPool(cfg.PostgresURI)
	if err != nil {
		neo4jDriver.Close(ctx)
		return nil, nil, classifyDriverError("PostgreSQL", cfg.PostgresURI, err)
	}
	slog.Info("connected to postgres")
	bootstrapReady := false
	defer func() {
		if bootstrapReady {
			return
		}
		pgPool.Close()
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = neo4jDriver.Close(closeCtx)
	}()

	releaseBindingLock, err := appdb.AcquireStorageBindingLock(ctx, pgPool)
	if err != nil {
		return nil, nil, err
	}
	lockHeld := true
	defer func() {
		if !lockHeld {
			return
		}
		releaseCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = releaseBindingLock(releaseCtx)
	}()

	postgresBindingStore := appdb.NewStorageBindingStore(pgPool)
	neo4jBindingStore := graph.NewStorageBindingStore(neo4jDriver)
	postgresInspection, err := postgresBindingStore.Inspect(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("inspect PostgreSQL storage binding: %w", err)
	}
	neo4jInspection, err := neo4jBindingStore.Inspect(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("inspect Neo4j storage binding: %w", err)
	}
	expectedBinding, err := resolveStorageBinding(
		postgresInspection,
		neo4jInspection,
	)
	if err != nil {
		return nil, nil, err
	}

	if err := appdb.RunMigrations(ctx, pgPool); err != nil {
		return nil, nil, fmt.Errorf("postgres migrations: %w", err)
	}
	if err := neo4jBindingStore.EnsureConstraint(ctx); err != nil {
		return nil, nil, err
	}
	if postgresInspection.Marker == nil {
		if err := postgresBindingStore.Install(ctx, expectedBinding); err != nil {
			return nil, nil, err
		}
	}
	if neo4jInspection.Marker == nil {
		if err := neo4jBindingStore.Install(ctx, expectedBinding); err != nil {
			return nil, nil, err
		}
	}
	postgresMarker, err := postgresBindingStore.ReadStorageBinding(ctx)
	if err != nil {
		return nil, nil, err
	}
	neo4jMarker, err := neo4jBindingStore.ReadStorageBinding(ctx)
	if err != nil {
		return nil, nil, err
	}
	if !postgresMarker.Equal(expectedBinding) || !neo4jMarker.Equal(expectedBinding) ||
		!postgresMarker.Equal(neo4jMarker) {
		return nil, nil, fmt.Errorf("storage binding verification failed after conditional installation")
	}
	if err := releaseBindingLock(ctx); err != nil {
		return nil, nil, err
	}
	lockHeld = false

	if err := graph.InitSchema(ctx, neo4jDriver); err != nil {
		return nil, nil, fmt.Errorf("neo4j schema: %w", err)
	}

	writer := graph.NewWriter(neo4jDriver)
	reader := graph.NewReader(neo4jDriver)
	graphDB := graph.NewDB(reader, writer)
	scanStore := appdb.NewScanStore(pgPool)
	findingStore := appdb.NewFindingStore(pgPool)
	storageGuard, err := binding.NewGuard(
		expectedBinding,
		postgresBindingStore,
		neo4jBindingStore,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("construct storage binding admission guard: %w", err)
	}
	pipeline := ingest.NewPipeline(writer, graphDB, scanStore, findingStore, storageGuard)

	cleanup := func() {
		pgPool.Close()
		neo4jDriver.Close(ctx)
	}
	bootstrapReady = true

	return &Infrastructure{
		Neo4jDriver:  neo4jDriver,
		PGPool:       pgPool,
		Writer:       writer,
		Reader:       reader,
		GraphDB:      graphDB,
		ScanStore:    scanStore,
		FindingStore: findingStore,
		Pipeline:     pipeline,
	}, cleanup, nil
}

func resolveStorageBinding(
	postgres appdb.StorageInspection,
	neo4j graph.StorageBindingInspection,
) (binding.Marker, error) {
	if postgres.Marker != nil && neo4j.Marker != nil &&
		!postgres.Marker.Equal(*neo4j.Marker) {
		return binding.Marker{}, fmt.Errorf(
			"PostgreSQL and Neo4j storage bindings belong to different volume pairs; refusing all mutation: restore the matching volumes",
		)
	}
	if postgres.Marker == nil || neo4j.Marker == nil {
		if !postgres.ProductEmpty || !neo4j.ProductEmpty {
			return binding.Marker{}, fmt.Errorf(
				"nonempty legacy or crossed storage is not an ingest v4 database pair; refusing all mutation: back up the existing deployment, recreate both PostgreSQL and Neo4j volumes, and recollect with ingest v4",
			)
		}
	}
	switch {
	case postgres.Marker != nil:
		return *postgres.Marker, nil
	case neo4j.Marker != nil:
		return *neo4j.Marker, nil
	default:
		marker, err := binding.NewMarker(uuid.NewString())
		if err != nil {
			return binding.Marker{}, fmt.Errorf("generate storage pair identity: %w", err)
		}
		return marker, nil
	}
}
