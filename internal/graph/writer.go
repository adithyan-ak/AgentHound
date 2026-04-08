package graph

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/adithyan-ak/agenthound/internal/model"
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
			res, err := tx.Run(ctx, "RETURN apoc.version() AS version", nil)
			if err != nil {
				return nil, err
			}
			if res.Next(ctx) {
				return res.Record().Values[0], nil
			}
			return nil, fmt.Errorf("no result")
		})
		w.hasAPOC = err == nil
		if w.hasAPOC {
			slog.Info("APOC detected")
		} else {
			slog.Info("APOC not available, using fallback writer")
		}
	})
}

func (w *Writer) WriteNodes(ctx context.Context, nodes []model.Node, scanID string) (int, error) {
	if len(nodes) == 0 {
		return 0, nil
	}

	w.detectAPOC(ctx)

	if w.hasAPOC {
		return w.writeNodesAPOC(ctx, nodes, scanID)
	}
	return w.writeNodesFallback(ctx, nodes, scanID)
}

func (w *Writer) writeNodesAPOC(ctx context.Context, nodes []model.Node, scanID string) (int, error) {
	total := 0
	for i := 0; i < len(nodes); i += w.batchSize {
		end := min(i+w.batchSize, len(nodes))
		batch := nodes[i:end]

		params := make([]map[string]any, len(batch))
		for j, n := range batch {
			params[j] = map[string]any{
				"id":         n.ID,
				"kinds":      n.Kinds,
				"properties": n.Properties,
			}
		}

		cypher := `UNWIND $nodes AS node
CALL apoc.merge.node(node.kinds, {objectid: node.id}, node.properties) YIELD node AS n
SET n.scan_id = $scan_id, n.last_seen = datetime()
RETURN count(*) AS written`

		written, err := w.execBatch(ctx, cypher, map[string]any{
			"nodes":   params,
			"scan_id": scanID,
		})
		if err != nil {
			return total, fmt.Errorf("apoc node batch at offset %d: %w", i, err)
		}
		total += written
	}
	return total, nil
}

func (w *Writer) writeNodesFallback(ctx context.Context, nodes []model.Node, scanID string) (int, error) {
	grouped := groupNodesByKind(nodes)
	total := 0

	for kind, kindNodes := range grouped {
		cypher := fmt.Sprintf(`UNWIND $nodes AS node
MERGE (n:%s {objectid: node.id})
ON CREATE SET n = node.properties, n.objectid = node.id, n.scan_id = $scan_id, n.last_seen = datetime()
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

func (w *Writer) WriteEdges(ctx context.Context, edges []model.Edge, scanID string) (int, error) {
	if len(edges) == 0 {
		return 0, nil
	}

	w.detectAPOC(ctx)

	if w.hasAPOC {
		return w.writeEdgesAPOC(ctx, edges, scanID)
	}
	return w.writeEdgesFallback(ctx, edges, scanID)
}

func (w *Writer) writeEdgesAPOC(ctx context.Context, edges []model.Edge, scanID string) (int, error) {
	total := 0
	for i := 0; i < len(edges); i += w.batchSize {
		end := min(i+w.batchSize, len(edges))
		batch := edges[i:end]

		params := make([]map[string]any, len(batch))
		for j, e := range batch {
			params[j] = map[string]any{
				"source":     e.Source,
				"target":     e.Target,
				"kind":       e.Kind,
				"properties": e.Properties,
			}
		}

		cypher := `UNWIND $edges AS edge
MATCH (a {objectid: edge.source})
MATCH (b {objectid: edge.target})
CALL apoc.merge.relationship(a, edge.kind, {}, edge.properties, b) YIELD rel
SET rel.scan_id = $scan_id, rel.last_seen = datetime()
RETURN count(*) AS written`

		written, err := w.execBatch(ctx, cypher, map[string]any{
			"edges":   params,
			"scan_id": scanID,
		})
		if err != nil {
			return total, fmt.Errorf("apoc edge batch at offset %d: %w", i, err)
		}
		total += written
	}
	return total, nil
}

var edgeKindCypher = buildEdgeKindCypher()

func buildEdgeKindCypher() map[string]string {
	m := make(map[string]string, len(model.AllowedEdgeKinds))
	for kind := range model.AllowedEdgeKinds {
		m[kind] = fmt.Sprintf(`UNWIND $edges AS edge
MATCH (a {objectid: edge.source})
MATCH (b {objectid: edge.target})
MERGE (a)-[r:%s]->(b)
SET r += edge.properties, r.scan_id = $scan_id, r.last_seen = datetime()
RETURN count(*) AS written`, kind)
	}
	return m
}

func (w *Writer) writeEdgesFallback(ctx context.Context, edges []model.Edge, scanID string) (int, error) {
	grouped := groupEdgesByKind(edges)
	total := 0

	for kind, kindEdges := range grouped {
		cypher, ok := edgeKindCypher[kind]
		if !ok {
			return total, fmt.Errorf("unknown edge kind: %s", kind)
		}

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
				return total, fmt.Errorf("fallback edge batch %s at offset %d: %w", kind, i, err)
			}
			total += written
		}
	}
	return total, nil
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

func groupNodesByKind(nodes []model.Node) map[string][]model.Node {
	grouped := make(map[string][]model.Node)
	for _, n := range nodes {
		kind := "Node"
		if len(n.Kinds) > 0 {
			kind = n.Kinds[0]
		}
		grouped[kind] = append(grouped[kind], n)
	}
	return grouped
}

func groupEdgesByKind(edges []model.Edge) map[string][]model.Edge {
	grouped := make(map[string][]model.Edge)
	for _, e := range edges {
		grouped[e.Kind] = append(grouped[e.Kind], e)
	}
	return grouped
}

// EdgeKindCypherKeys returns all edge kinds that have Cypher templates.
// Used by tests to verify completeness against AllowedEdgeKinds.
func EdgeKindCypherKeys() map[string]bool {
	keys := make(map[string]bool, len(edgeKindCypher))
	for k := range edgeKindCypher {
		keys[k] = true
	}
	return keys
}
