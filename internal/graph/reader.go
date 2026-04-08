package graph

import (
	"context"
	"fmt"
	"strings"

	"github.com/adithyan-ak/agenthound/internal/model"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

type GraphStats struct {
	NodeCounts map[string]int64 `json:"node_counts"`
	EdgeCounts map[string]int64 `json:"edge_counts"`
	TotalNodes int64            `json:"total_nodes"`
	TotalEdges int64            `json:"total_edges"`
}

type Reader struct {
	driver neo4j.DriverWithContext
}

func NewReader(driver neo4j.DriverWithContext) *Reader {
	return &Reader{driver: driver}
}

func (r *Reader) Ping(ctx context.Context) error {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	_, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, "RETURN 1", nil)
		if err != nil {
			return nil, err
		}
		res.Next(ctx)
		return nil, res.Err()
	})
	return err
}

func (r *Reader) GetStats(ctx context.Context) (*GraphStats, error) {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	stats := &GraphStats{
		NodeCounts: make(map[string]int64),
		EdgeCounts: make(map[string]int64),
	}

	// Node counts
	_, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, "MATCH (n) RETURN labels(n)[0] AS kind, count(*) AS count", nil)
		if err != nil {
			return nil, err
		}
		for res.Next(ctx) {
			record := res.Record()
			kind, _ := record.Get("kind")
			count, _ := record.Get("count")
			if k, ok := kind.(string); ok {
				if c, ok := count.(int64); ok {
					stats.NodeCounts[k] = c
					stats.TotalNodes += c
				}
			}
		}
		return nil, res.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("node stats: %w", err)
	}

	// Edge counts
	_, err = session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, "MATCH ()-[r]->() RETURN type(r) AS kind, count(r) AS count", nil)
		if err != nil {
			return nil, err
		}
		for res.Next(ctx) {
			record := res.Record()
			kind, _ := record.Get("kind")
			count, _ := record.Get("count")
			if k, ok := kind.(string); ok {
				if c, ok := count.(int64); ok {
					stats.EdgeCounts[k] = c
					stats.TotalEdges += c
				}
			}
		}
		return nil, res.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("edge stats: %w", err)
	}

	return stats, nil
}

func (r *Reader) GetNode(ctx context.Context, objectID string) (*model.Node, []model.Edge, error) {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	type nodeResult struct {
		node  *model.Node
		edges []model.Edge
	}

	result, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		// Get node
		res, err := tx.Run(ctx, "MATCH (n {objectid: $id}) RETURN n, labels(n) AS kinds", map[string]any{"id": objectID})
		if err != nil {
			return nil, err
		}
		if !res.Next(ctx) {
			return nil, nil
		}

		record := res.Record()
		neoNode, ok := record.Values[0].(neo4j.Node)
		if !ok {
			return nil, fmt.Errorf("unexpected node type")
		}
		kinds, _ := record.Values[1].([]any)
		kindStrs := make([]string, 0, len(kinds))
		for _, k := range kinds {
			if s, ok := k.(string); ok {
				kindStrs = append(kindStrs, s)
			}
		}

		node := &model.Node{
			ID:         objectID,
			Kinds:      kindStrs,
			Properties: neoNode.Props,
		}

		// Get connected edges
		edgeRes, err := tx.Run(ctx, `MATCH (n {objectid: $id})-[r]-(m)
RETURN type(r) AS kind, properties(r) AS props,
       startNode(r) = n AS outgoing,
       m.objectid AS other_id`, map[string]any{"id": objectID})
		if err != nil {
			return &nodeResult{node: node}, nil
		}

		var edges []model.Edge
		for edgeRes.Next(ctx) {
			rec := edgeRes.Record()
			kind, _ := rec.Get("kind")
			props, _ := rec.Get("props")
			outgoing, _ := rec.Get("outgoing")
			otherID, _ := rec.Get("other_id")

			kindStr, _ := kind.(string)
			e := model.Edge{
				Kind: kindStr,
			}
			if p, ok := props.(map[string]any); ok {
				e.Properties = p
			}
			if out, ok := outgoing.(bool); ok && out {
				e.Source = objectID
				if oid, ok := otherID.(string); ok {
					e.Target = oid
				}
			} else {
				e.Target = objectID
				if oid, ok := otherID.(string); ok {
					e.Source = oid
				}
			}
			edges = append(edges, e)
		}

		return &nodeResult{node: node, edges: edges}, nil
	})
	if err != nil {
		return nil, nil, fmt.Errorf("get node: %w", err)
	}
	if result == nil {
		return nil, nil, nil
	}
	nr, ok := result.(*nodeResult)
	if !ok {
		return nil, nil, nil
	}
	return nr.node, nr.edges, nil
}

func (r *Reader) ListNodes(ctx context.Context, kind string, limit int) ([]model.Node, error) {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	if limit <= 0 {
		limit = 100
	}

	// Validate kind to prevent Cypher injection
	var cypher string
	if kind != "" {
		if !model.AllowedNodeKinds[kind] && kind != "ResourceGroup" && kind != "TrustZone" {
			return nil, fmt.Errorf("invalid node kind: %s", kind)
		}
		cypher = fmt.Sprintf("MATCH (n:%s) RETURN n, labels(n) AS kinds ORDER BY n.name LIMIT $limit", kind)
	} else {
		cypher = "MATCH (n) RETURN n, labels(n) AS kinds LIMIT $limit"
	}

	result, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, cypher, map[string]any{"limit": limit})
		if err != nil {
			return nil, err
		}

		var nodes []model.Node
		for res.Next(ctx) {
			record := res.Record()
			neoNode, ok := record.Values[0].(neo4j.Node)
			if !ok {
				continue
			}
			kinds, _ := record.Values[1].([]any)
			kindStrs := make([]string, 0, len(kinds))
			for _, k := range kinds {
				if s, ok := k.(string); ok {
					kindStrs = append(kindStrs, s)
				}
			}

			objectID, _ := neoNode.Props["objectid"].(string)
			nodes = append(nodes, model.Node{
				ID:         objectID,
				Kinds:      kindStrs,
				Properties: neoNode.Props,
			})
		}
		return nodes, res.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("list nodes: %w", err)
	}
	nodes, _ := result.([]model.Node)
	return nodes, nil
}

func (r *Reader) ListEdges(ctx context.Context, kind, sourceID, targetID string, limit int) ([]model.Edge, error) {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	if limit <= 0 {
		limit = 100
	}

	var cypher string
	params := map[string]any{"limit": limit}
	var conditions []string

	if kind != "" {
		if !model.AllowedEdgeKinds[kind] {
			return nil, fmt.Errorf("invalid edge kind: %s", kind)
		}
		cypher = fmt.Sprintf("MATCH (a)-[r:%s]->(b)", kind)
	} else {
		cypher = "MATCH (a)-[r]->(b)"
	}

	if sourceID != "" {
		conditions = append(conditions, "a.objectid = $source")
		params["source"] = sourceID
	}
	if targetID != "" {
		conditions = append(conditions, "b.objectid = $target")
		params["target"] = targetID
	}

	if len(conditions) > 0 {
		cypher += " WHERE " + strings.Join(conditions, " AND ")
	}
	cypher += " RETURN a.objectid AS source, b.objectid AS target, type(r) AS kind, properties(r) AS props LIMIT $limit"

	result, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, cypher, params)
		if err != nil {
			return nil, err
		}

		var edges []model.Edge
		for res.Next(ctx) {
			record := res.Record()
			src, _ := record.Get("source")
			tgt, _ := record.Get("target")
			k, _ := record.Get("kind")
			props, _ := record.Get("props")

			kindStr, _ := k.(string)
			e := model.Edge{
				Kind: kindStr,
			}
			if s, ok := src.(string); ok {
				e.Source = s
			}
			if t, ok := tgt.(string); ok {
				e.Target = t
			}
			if p, ok := props.(map[string]any); ok {
				e.Properties = p
			}
			edges = append(edges, e)
		}
		return edges, res.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("list edges: %w", err)
	}
	edges, _ := result.([]model.Edge)
	return edges, nil
}

func (r *Reader) Query(ctx context.Context, cypher string, params map[string]any) ([]map[string]any, error) {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	result, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, cypher, params)
		if err != nil {
			return nil, err
		}

		var rows []map[string]any
		keys, _ := res.Keys()
		for res.Next(ctx) {
			row := make(map[string]any, len(keys))
			for i, key := range keys {
				row[key] = res.Record().Values[i]
			}
			rows = append(rows, row)
		}
		return rows, res.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}
	rows, _ := result.([]map[string]any)
	return rows, nil
}
