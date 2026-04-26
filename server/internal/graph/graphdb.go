package graph

import (
	"context"
	"fmt"
	"time"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

// PostProcessor computes composite edges from raw graph data.
type PostProcessor interface {
	Name() string
	Dependencies() []string
	Process(ctx context.Context, db GraphDB, scanID string) (ProcessingStats, error)
}

// ProcessingStats reports what a processor did.
type ProcessingStats struct {
	ProcessorName string        `json:"processor_name"`
	EdgesCreated  int           `json:"edges_created"`
	NodesUpdated  int           `json:"nodes_updated"`
	Duration      time.Duration `json:"duration"`
	Error         string        `json:"error,omitempty"`
}

// GraphDB abstracts graph read/write operations for post-processors.
type GraphDB interface {
	Query(ctx context.Context, cypher string, params map[string]any) ([]map[string]any, error)
	WriteEdges(ctx context.Context, edges []ingest.Edge, scanID string) (int, error)
	UpdateNodeProperties(ctx context.Context, objectID string, props map[string]any) error
	ExecuteWrite(ctx context.Context, cypher string, params map[string]any) (int, error)
	GetNode(ctx context.Context, objectID string) (*ingest.Node, []ingest.Edge, error)
	ListNodes(ctx context.Context, kind string, limit int) ([]ingest.Node, error)
	HasAPOC(ctx context.Context) bool
}

// DB is the concrete GraphDB implementation wrapping Reader and Writer.
type DB struct {
	reader *Reader
	writer *Writer
}

func NewDB(reader *Reader, writer *Writer) *DB {
	return &DB{reader: reader, writer: writer}
}

func (db *DB) Query(ctx context.Context, cypher string, params map[string]any) ([]map[string]any, error) {
	return db.reader.Query(ctx, cypher, params)
}

func (db *DB) WriteEdges(ctx context.Context, edges []ingest.Edge, scanID string) (int, error) {
	return db.writer.WriteEdges(ctx, edges, scanID)
}

func (db *DB) GetNode(ctx context.Context, objectID string) (*ingest.Node, []ingest.Edge, error) {
	return db.reader.GetNode(ctx, objectID)
}

func (db *DB) ListNodes(ctx context.Context, kind string, limit int) ([]ingest.Node, error) {
	return db.reader.ListNodes(ctx, kind, limit)
}

func (db *DB) HasAPOC(ctx context.Context) bool {
	db.writer.detectAPOC(ctx)
	return db.writer.hasAPOC
}

func (db *DB) ExecuteWrite(ctx context.Context, cypher string, params map[string]any) (int, error) {
	session := db.writer.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	result, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, cypher, params)
		if err != nil {
			return 0, err
		}
		if res.Next(ctx) {
			val, ok := res.Record().Values[0].(int64)
			if ok {
				return int(val), nil
			}
		}
		return 0, nil
	})
	if err != nil {
		return 0, err
	}
	written, _ := result.(int)
	return written, nil
}

func (db *DB) UpdateNodeProperties(ctx context.Context, objectID string, props map[string]any) error {
	session := db.writer.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		_, err := tx.Run(ctx, "MATCH (n {objectid: $id}) SET n += $props", map[string]any{
			"id":    objectID,
			"props": props,
		})
		if err != nil {
			return nil, fmt.Errorf("update node %s: %w", objectID, err)
		}
		return nil, nil
	})
	return err
}
