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
	// ListNodesPage lists nodes with an explicit offset so callers (e.g. risk
	// scoring) can page a node kind to exhaustion instead of silently capping.
	ListNodesPage(ctx context.Context, kind string, limit, offset int) ([]ingest.Node, error)
	HasAPOC(ctx context.Context) bool
	// DeleteGenerationTx removes ONE generation's contribution to the graph in
	// a SINGLE Neo4j transaction: it decrements the generation from every
	// fact's generations set and deletes the edges/nodes that become owned by
	// no generation. Running both statements in one transaction makes the
	// delete atomic (a failure rolls the whole decrement back) and idempotent
	// (re-running after a partial/interrupted delete is a no-op for facts
	// already decremented), which is what makes scan deletion recoverable.
	DeleteGenerationTx(ctx context.Context, generationID string) error
	// DeleteByScanIDTx removes facts tagged with a scalar scan_id in one
	// transaction. Legacy fallback for generationless (pre-generation) rows.
	DeleteByScanIDTx(ctx context.Context, scanID string) error
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

func (db *DB) WriteEdgesForScan(ctx context.Context, edges []ingest.Edge, scanID string) (int, error) {
	return db.writer.WriteEdgesForScan(ctx, edges, scanID)
}

func (db *DB) GetNode(ctx context.Context, objectID string) (*ingest.Node, []ingest.Edge, error) {
	// Unscoped: ingest-time processors operate on freshly-written, scan-tagged
	// facts across all generations (generation scoping is a default-read
	// concern handled by the API handlers, not the processing path).
	return db.reader.GetNode(ctx, objectID, nil)
}

func (db *DB) ListNodes(ctx context.Context, kind string, limit int) ([]ingest.Node, error) {
	return db.reader.ListNodes(ctx, kind, limit)
}

func (db *DB) ListNodesPage(ctx context.Context, kind string, limit, offset int) ([]ingest.Node, error) {
	return db.reader.ListNodesPage(ctx, kind, limit, offset, nil)
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

// deleteGenerationEdgesCypher and deleteGenerationNodesCypher are the two
// owned-only decrement+GC statements, run together in one transaction by
// DeleteGenerationTx. Edges run first so the node edgeless guard reflects the
// edges just removed.
const (
	deleteGenerationEdgesCypher = `MATCH ()-[r]->()
WHERE $gen IN coalesce(r.generations, [])
WITH r, [g IN coalesce(r.generations, []) WHERE g <> $gen] AS remaining
SET r.generations = remaining
WITH r, remaining WHERE size(remaining) = 0
DELETE r`
	deleteGenerationNodesCypher = `MATCH (n)
WHERE $gen IN coalesce(n.generations, [])
WITH n, [g IN coalesce(n.generations, []) WHERE g <> $gen] AS remaining
SET n.generations = remaining
WITH n, remaining WHERE size(remaining) = 0 AND NOT EXISTS { MATCH (n)-[]-() }
DELETE n`
	deleteByScanIDEdgesCypher = `MATCH ()-[r]->() WHERE r.scan_id = $value DELETE r`
	deleteByScanIDNodesCypher = `MATCH (n) WHERE n.scan_id = $value
AND NOT EXISTS { MATCH (n)-[]-() }
DELETE n`
)

// DeleteGenerationTx removes one generation's contribution to the graph in a
// single Neo4j transaction (see interface doc).
func (db *DB) DeleteGenerationTx(ctx context.Context, generationID string) error {
	return db.runWriteTx(ctx, []struct {
		cypher string
		params map[string]any
	}{
		{deleteGenerationEdgesCypher, map[string]any{"gen": generationID}},
		{deleteGenerationNodesCypher, map[string]any{"gen": generationID}},
	})
}

// DeleteByScanIDTx removes scalar-scan_id facts in one transaction (legacy).
func (db *DB) DeleteByScanIDTx(ctx context.Context, scanID string) error {
	return db.runWriteTx(ctx, []struct {
		cypher string
		params map[string]any
	}{
		{deleteByScanIDEdgesCypher, map[string]any{"value": scanID}},
		{deleteByScanIDNodesCypher, map[string]any{"value": scanID}},
	})
}

// runWriteTx executes several write statements inside ONE managed transaction:
// either all commit or none do.
func (db *DB) runWriteTx(ctx context.Context, stmts []struct {
	cypher string
	params map[string]any
}) error {
	session := db.writer.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)
	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		for _, s := range stmts {
			if _, err := tx.Run(ctx, s.cypher, s.params); err != nil {
				return nil, err
			}
		}
		return nil, nil
	})
	return err
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
