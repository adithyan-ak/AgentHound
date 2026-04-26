package graph

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

const defaultBatchSize = 1000

type Writer struct {
	driver    neo4j.DriverWithContext
	hasAPOC   bool
	apocOnce  sync.Once
	batchSize int
}

func NewWriter(driver neo4j.DriverWithContext) *Writer {
	return &Writer{
		driver:    driver,
		batchSize: defaultBatchSize,
	}
}

func (w *Writer) detectAPOC(ctx context.Context) {
	w.apocOnce.Do(func() {
		session := w.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
		defer session.Close(ctx)
		_, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
			res, err := tx.Run(ctx, "CALL dbms.procedures() YIELD name WHERE name = 'apoc.merge.relationship' RETURN name", nil)
			if err != nil {
				return nil, err
			}
			if res.Next(ctx) {
				return res.Record().Values[0], nil
			}
			return nil, fmt.Errorf("apoc.merge.relationship not found")
		})
		w.hasAPOC = err == nil
		if w.hasAPOC {
			slog.Info("APOC detected")
		} else {
			slog.Info("APOC not available, using fallback writer")
		}
	})
}

func (w *Writer) WriteNodes(ctx context.Context, nodes []ingest.Node, scanID string) (int, error) {
	if len(nodes) == 0 {
		return 0, nil
	}
	return w.writeNodesBatched(ctx, nodes, scanID)
}

func (w *Writer) writeNodesBatched(ctx context.Context, nodes []ingest.Node, scanID string) (int, error) {
	grouped := groupNodesByKind(nodes)
	total := 0

	for kind, kindNodes := range grouped {
		cypher := fmt.Sprintf(`UNWIND $nodes AS node
MERGE (n:%s {objectid: node.id})
ON CREATE SET n = node.properties, n.objectid = node.id, n.scan_id = $scan_id, n.first_seen = datetime(), n.last_seen = datetime()
ON MATCH SET n.previous_description_hash = n.description_hash, n += node.properties, n.scan_id = $scan_id, n.last_seen = datetime()
RETURN count(*) AS written`, kind)

		for i := 0; i < len(kindNodes); i += w.batchSize {
			end := min(i+w.batchSize, len(kindNodes))
			batch := kindNodes[i:end]

			params := make([]map[string]any, len(batch))
			for j, n := range batch {
				params[j] = map[string]any{
					"id":         n.ID,
					"properties": n.Properties,
				}
			}

			written, err := w.execBatch(ctx, cypher, map[string]any{
				"nodes":   params,
				"scan_id": scanID,
			})
			if err != nil {
				return total, fmt.Errorf("fallback node batch %s at offset %d: %w", kind, i, err)
			}
			total += written
		}
	}
	return total, nil
}

func (w *Writer) WriteEdges(ctx context.Context, edges []ingest.Edge, scanID string) (int, error) {
	if len(edges) == 0 {
		return 0, nil
	}

	w.detectAPOC(ctx)

	if w.hasAPOC {
		return w.writeEdgesAPOC(ctx, edges, scanID)
	}
	return w.writeEdgesFallback(ctx, edges, scanID)
}

func (w *Writer) writeEdgesAPOC(ctx context.Context, edges []ingest.Edge, scanID string) (int, error) {
	grouped := groupEdgesByEndpoints(edges)
	total := 0

	for key, kindEdges := range grouped {
		sourceMatch := matchClause("a", key.SourceKind, "source")
		targetMatch := matchClause("b", key.TargetKind, "target")

		cypher := fmt.Sprintf(`UNWIND $edges AS edge
%s
%s
CALL apoc.merge.relationship(a, $kind, {}, edge.properties, b) YIELD rel
SET rel.scan_id = $scan_id, rel.last_seen = datetime()
RETURN count(*) AS written`, sourceMatch, targetMatch)

		for i := 0; i < len(kindEdges); i += w.batchSize {
			end := min(i+w.batchSize, len(kindEdges))
			batch := kindEdges[i:end]

			params := make([]map[string]any, len(batch))
			for j, e := range batch {
				props := e.Properties
				if props == nil {
					props = map[string]any{}
				}
				params[j] = map[string]any{
					"source":     e.Source,
					"target":     e.Target,
					"properties": props,
				}
			}

			written, err := w.execBatch(ctx, cypher, map[string]any{
				"edges":   params,
				"kind":    key.Kind,
				"scan_id": scanID,
			})
			if err != nil {
				return total, fmt.Errorf("apoc edge batch %s at offset %d: %w", key.Kind, i, err)
			}
			total += written
		}
	}
	return total, nil
}

func (w *Writer) writeEdgesFallback(ctx context.Context, edges []ingest.Edge, scanID string) (int, error) {
	grouped := groupEdgesByEndpoints(edges)
	total := 0

	for key, kindEdges := range grouped {
		cypher := edgeCypherForKinds(key.Kind, key.SourceKind, key.TargetKind)

		for i := 0; i < len(kindEdges); i += w.batchSize {
			end := min(i+w.batchSize, len(kindEdges))
			batch := kindEdges[i:end]

			params := make([]map[string]any, len(batch))
			for j, e := range batch {
				props := e.Properties
				if props == nil {
					props = map[string]any{}
				}
				params[j] = map[string]any{
					"source":     e.Source,
					"target":     e.Target,
					"properties": props,
				}
			}

			written, err := w.execBatch(ctx, cypher, map[string]any{
				"edges":   params,
				"scan_id": scanID,
			})
			if err != nil {
				return total, fmt.Errorf("edge batch %s at offset %d: %w", key.Kind, i, err)
			}
			total += written
		}
	}
	return total, nil
}

func matchClause(variable, kind, edgeField string) string {
	if kind == "" {
		return fmt.Sprintf("MATCH (%s {objectid: edge.%s})", variable, edgeField)
	}
	return fmt.Sprintf("MATCH (%s:%s {objectid: edge.%s})", variable, kind, edgeField)
}

// edgeCypherForKinds generates a MERGE Cypher statement with optional label hints.
func edgeCypherForKinds(edgeKind, sourceKind, targetKind string) string {
	return fmt.Sprintf(`UNWIND $edges AS edge
%s
%s
MERGE (a)-[r:%s]->(b)
SET r += edge.properties, r.scan_id = $scan_id, r.last_seen = datetime()
RETURN count(*) AS written`, matchClause("a", sourceKind, "source"), matchClause("b", targetKind, "target"), edgeKind)
}

func (w *Writer) execBatch(ctx context.Context, cypher string, params map[string]any) (int, error) {
	session := w.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
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

func groupNodesByKind(nodes []ingest.Node) map[string][]ingest.Node {
	grouped := make(map[string][]ingest.Node)
	for _, n := range nodes {
		kind := "Node"
		if len(n.Kinds) > 0 {
			kind = n.Kinds[0]
		}
		grouped[kind] = append(grouped[kind], n)
	}
	return grouped
}

type edgeGroupKey struct {
	Kind       string
	SourceKind string
	TargetKind string
}

func groupEdgesByEndpoints(edges []ingest.Edge) map[edgeGroupKey][]ingest.Edge {
	grouped := make(map[edgeGroupKey][]ingest.Edge)
	for _, e := range edges {
		sk, tk := ingest.ResolveEdgeEndpoints(e.Kind, e.SourceKind, e.TargetKind)
		key := edgeGroupKey{Kind: e.Kind, SourceKind: sk, TargetKind: tk}
		grouped[key] = append(grouped[key], e)
	}
	return grouped
}
