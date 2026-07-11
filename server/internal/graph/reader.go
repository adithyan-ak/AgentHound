package graph

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

type GraphStats struct {
	NodeCounts map[string]int64 `json:"node_counts"`
	EdgeCounts map[string]int64 `json:"edge_counts"`
	TotalNodes int64            `json:"total_nodes"`
	TotalEdges int64            `json:"total_edges"`
}

// PageInfo describes one stable page while preserving the API's historical
// array response bodies.
type PageInfo struct {
	Offset   int
	Limit    int
	Total    int64
	HasMore  bool
	Complete bool
	Revision string
}

// RevisionMismatchError means a caller attempted to continue pagination after
// the graph changed. Returning partial pages as one complete graph would make
// counts and relationships internally inconsistent.
type RevisionMismatchError struct {
	Expected string
	Actual   string
}

func (e *RevisionMismatchError) Error() string {
	return fmt.Sprintf("graph revision changed: expected %q, got %q", e.Expected, e.Actual)
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

const graphRevisionCypher = `
CALL {
  MATCH (n)
  RETURN count(n) AS node_count,
         coalesce(max(toString(n.last_seen)), '') AS node_last_seen,
         coalesce(max(toString(n.graph_updated_at)), '') AS node_graph_updated,
         coalesce(max(toString(n.scan_id)), '') AS node_scan_id
}
CALL {
  MATCH ()-[r]->()
  RETURN count(r) AS edge_count,
         coalesce(max(toString(r.last_seen)), '') AS edge_last_seen,
         coalesce(max(toString(r.scan_id)), '') AS edge_scan_id
}
RETURN node_count, node_last_seen, node_graph_updated, node_scan_id,
       edge_count, edge_last_seen, edge_scan_id`

func readGraphRevision(ctx context.Context, tx neo4j.ManagedTransaction) (string, error) {
	res, err := tx.Run(ctx, graphRevisionCypher, nil)
	if err != nil {
		return "", err
	}
	if !res.Next(ctx) {
		return "", res.Err()
	}
	record := res.Record()
	values := make([]any, 0, len(record.Values))
	values = append(values, record.Values...)
	sum := sha256.Sum256([]byte(fmt.Sprintf("%#v", values)))
	return fmt.Sprintf("%x", sum[:]), res.Err()
}

func verifyExpectedRevision(expected, actual string) error {
	if expected != "" && expected != actual {
		return &RevisionMismatchError{Expected: expected, Actual: actual}
	}
	return nil
}

func normalizePageArgs(limit, offset, fallback int) (int, int) {
	if limit <= 0 {
		limit = fallback
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

func (r *Reader) GetStats(ctx context.Context) (*GraphStats, error) {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	params := map[string]any{"public_kinds": ingest.PublicNodeLabels}
	result, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		stats := &GraphStats{
			NodeCounts: make(map[string]int64),
			EdgeCounts: make(map[string]int64),
		}

		// Public node and edge totals are read in the same transaction so the
		// persisted publication cannot combine two different graph revisions.
		res, err := tx.Run(ctx, `MATCH (n)
WHERE any(label IN labels(n) WHERE label IN $public_kinds)
RETURN labels(n) AS kinds, count(*) AS count`, params)
		if err != nil {
			return nil, fmt.Errorf("node stats: %w", err)
		}
		for res.Next(ctx) {
			record := res.Record()
			kinds, _ := record.Get("kinds")
			count, _ := record.Get("count")
			kind := publicNodeKind(kinds)
			if kind == "" {
				continue
			}
			if c, ok := count.(int64); ok {
				stats.NodeCounts[kind] += c
				stats.TotalNodes += c
			}
		}
		if err := res.Err(); err != nil {
			return nil, fmt.Errorf("node stats: %w", err)
		}

		res, err = tx.Run(ctx, `MATCH (a)-[r]->(b)
WHERE any(label IN labels(a) WHERE label IN $public_kinds)
  AND any(label IN labels(b) WHERE label IN $public_kinds)
RETURN type(r) AS kind, count(r) AS count`, params)
		if err != nil {
			return nil, fmt.Errorf("edge stats: %w", err)
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
		if err := res.Err(); err != nil {
			return nil, fmt.Errorf("edge stats: %w", err)
		}
		return stats, nil
	})
	if err != nil {
		return nil, err
	}
	stats, _ := result.(*GraphStats)
	if stats == nil {
		stats = &GraphStats{
			NodeCounts: map[string]int64{},
			EdgeCounts: map[string]int64{},
		}
	}
	return stats, nil
}

func publicNodeKind(value any) string {
	kinds := make(map[string]bool)
	switch rawKinds := value.(type) {
	case []any:
		for _, raw := range rawKinds {
			if kind, ok := raw.(string); ok {
				kinds[kind] = true
			}
		}
	case []string:
		for _, kind := range rawKinds {
			kinds[kind] = true
		}
	}
	for _, kind := range ingest.PublicNodeLabels {
		if kinds[kind] {
			return kind
		}
	}
	return ""
}

func (r *Reader) GetNode(ctx context.Context, objectID string) (*ingest.Node, []ingest.Edge, error) {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	type nodeResult struct {
		node  *ingest.Node
		edges []ingest.Edge
	}

	result, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		// Get node
		res, err := tx.Run(ctx, `MATCH (n {objectid: $id})
WHERE any(label IN labels(n) WHERE label IN $public_kinds)
RETURN n, labels(n) AS kinds`, map[string]any{
			"id":           objectID,
			"public_kinds": ingest.PublicNodeLabels,
		})
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

		node := &ingest.Node{
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
			return nil, err
		}

		edges := make([]ingest.Edge, 0)
		for edgeRes.Next(ctx) {
			rec := edgeRes.Record()
			kind, _ := rec.Get("kind")
			props, _ := rec.Get("props")
			outgoing, _ := rec.Get("outgoing")
			otherID, _ := rec.Get("other_id")

			kindStr, _ := kind.(string)
			e := ingest.Edge{
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
		if err := edgeRes.Err(); err != nil {
			return nil, err
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

func (r *Reader) ListNodes(ctx context.Context, kind string, limit int) ([]ingest.Node, error) {
	nodes, _, err := r.ListNodesPage(ctx, kind, limit, 0, "")
	return nodes, err
}

// ListNodesPage returns a stable, revision-checked page ordered by display
// identity and objectid. expectedRevision may be empty for the first page.
func (r *Reader) ListNodesPage(
	ctx context.Context,
	kind string,
	limit, offset int,
	expectedRevision string,
) ([]ingest.Node, PageInfo, error) {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	limit, offset = normalizePageArgs(limit, offset, 100)

	var matchClause, whereClause string
	if kind != "" {
		if !ingest.AllowedNodeKinds[kind] {
			return nil, PageInfo{}, fmt.Errorf("invalid node kind: %s", kind)
		}
		matchClause = fmt.Sprintf("MATCH (n:%s)", kind)
	} else {
		matchClause = "MATCH (n)"
		whereClause = " WHERE any(label IN labels(n) WHERE label IN $public_kinds)"
	}

	countCypher := matchClause + whereClause + " RETURN count(n) AS total"
	pageCypher := matchClause + whereClause + `
 RETURN n, labels(n) AS kinds
 ORDER BY toLower(coalesce(n.name, n.uri, n.path, n.hostname, n.objectid, '')),
          n.objectid, id(n)
 SKIP $offset LIMIT $fetch_limit`

	type nodePageResult struct {
		nodes    []ingest.Node
		total    int64
		revision string
	}

	result, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		revision, err := readGraphRevision(ctx, tx)
		if err != nil {
			return nil, err
		}
		if err := verifyExpectedRevision(expectedRevision, revision); err != nil {
			return nil, err
		}

		params := map[string]any{
			"offset":       offset,
			"fetch_limit":  limit + 1,
			"public_kinds": ingest.PublicNodeLabels,
		}
		countRes, err := tx.Run(ctx, countCypher, params)
		if err != nil {
			return nil, err
		}
		var total int64
		if countRes.Next(ctx) {
			total, _ = countRes.Record().Values[0].(int64)
		}
		if err := countRes.Err(); err != nil {
			return nil, err
		}

		res, err := tx.Run(ctx, pageCypher, params)
		if err != nil {
			return nil, err
		}

		nodes := make([]ingest.Node, 0, limit+1)
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
			nodes = append(nodes, ingest.Node{
				ID:         objectID,
				Kinds:      kindStrs,
				Properties: neoNode.Props,
			})
		}
		if err := res.Err(); err != nil {
			return nil, err
		}

		finalRevision, err := readGraphRevision(ctx, tx)
		if err != nil {
			return nil, err
		}
		if finalRevision != revision {
			return nil, &RevisionMismatchError{Expected: revision, Actual: finalRevision}
		}
		return &nodePageResult{nodes: nodes, total: total, revision: revision}, nil
	})
	if err != nil {
		return nil, PageInfo{}, fmt.Errorf("list nodes: %w", err)
	}
	page, _ := result.(*nodePageResult)
	if page == nil {
		return []ingest.Node{}, PageInfo{
			Offset: offset, Limit: limit, Complete: true,
		}, nil
	}
	hasMore := len(page.nodes) > limit
	if hasMore {
		page.nodes = page.nodes[:limit]
	}
	return page.nodes, PageInfo{
		Offset:   offset,
		Limit:    limit,
		Total:    page.total,
		HasMore:  hasMore,
		Complete: !hasMore,
		Revision: page.revision,
	}, nil
}

func (r *Reader) ListEdges(ctx context.Context, kind, sourceID, targetID string, limit int) ([]ingest.Edge, error) {
	edges, _, err := r.ListEdgesPage(ctx, kind, sourceID, targetID, limit, 0, "")
	return edges, err
}

// ListEdgesPage returns a stable, revision-checked relationship page.
func (r *Reader) ListEdgesPage(
	ctx context.Context,
	kind, sourceID, targetID string,
	limit, offset int,
	expectedRevision string,
) ([]ingest.Edge, PageInfo, error) {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	limit, offset = normalizePageArgs(limit, offset, 100)

	var matchClause string
	params := map[string]any{
		"offset":       offset,
		"fetch_limit":  limit + 1,
		"public_kinds": ingest.PublicNodeLabels,
	}
	conditions := []string{
		"any(label IN labels(a) WHERE label IN $public_kinds)",
		"any(label IN labels(b) WHERE label IN $public_kinds)",
	}

	if kind != "" {
		if !ingest.AllowedEdgeKinds[kind] {
			return nil, PageInfo{}, fmt.Errorf("invalid edge kind: %s", kind)
		}
		matchClause = fmt.Sprintf("MATCH (a)-[r:%s]->(b)", kind)
	} else {
		matchClause = "MATCH (a)-[r]->(b)"
	}

	if sourceID != "" {
		conditions = append(conditions, "a.objectid = $source")
		params["source"] = sourceID
	}
	if targetID != "" {
		conditions = append(conditions, "b.objectid = $target")
		params["target"] = targetID
	}

	whereClause := " WHERE " + strings.Join(conditions, " AND ")
	countCypher := matchClause + whereClause + " RETURN count(r) AS total"
	pageCypher := matchClause + whereClause + `
 RETURN a.objectid AS source, b.objectid AS target, type(r) AS kind,
        properties(r) AS props, labels(a) AS source_kinds,
        labels(b) AS target_kinds
 ORDER BY kind, source, target, id(r)
 SKIP $offset LIMIT $fetch_limit`

	type edgePageResult struct {
		edges    []ingest.Edge
		total    int64
		revision string
	}
	result, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		revision, err := readGraphRevision(ctx, tx)
		if err != nil {
			return nil, err
		}
		if err := verifyExpectedRevision(expectedRevision, revision); err != nil {
			return nil, err
		}

		countRes, err := tx.Run(ctx, countCypher, params)
		if err != nil {
			return nil, err
		}
		var total int64
		if countRes.Next(ctx) {
			total, _ = countRes.Record().Values[0].(int64)
		}
		if err := countRes.Err(); err != nil {
			return nil, err
		}

		res, err := tx.Run(ctx, pageCypher, params)
		if err != nil {
			return nil, err
		}

		edges := make([]ingest.Edge, 0, limit+1)
		for res.Next(ctx) {
			record := res.Record()
			src, _ := record.Get("source")
			tgt, _ := record.Get("target")
			k, _ := record.Get("kind")
			props, _ := record.Get("props")
			srcKinds, _ := record.Get("source_kinds")
			tgtKinds, _ := record.Get("target_kinds")

			kindStr, _ := k.(string)
			e := ingest.Edge{
				Kind: kindStr,
			}
			if s, ok := src.(string); ok {
				e.Source = s
			}
			if t, ok := tgt.(string); ok {
				e.Target = t
			}
			e.SourceKind = publicNodeKind(srcKinds)
			e.TargetKind = publicNodeKind(tgtKinds)
			if p, ok := props.(map[string]any); ok {
				e.Properties = p
			}
			edges = append(edges, e)
		}
		if err := res.Err(); err != nil {
			return nil, err
		}

		finalRevision, err := readGraphRevision(ctx, tx)
		if err != nil {
			return nil, err
		}
		if finalRevision != revision {
			return nil, &RevisionMismatchError{Expected: revision, Actual: finalRevision}
		}
		return &edgePageResult{edges: edges, total: total, revision: revision}, nil
	})
	if err != nil {
		return nil, PageInfo{}, fmt.Errorf("list edges: %w", err)
	}
	page, _ := result.(*edgePageResult)
	if page == nil {
		return []ingest.Edge{}, PageInfo{
			Offset: offset, Limit: limit, Complete: true,
		}, nil
	}
	hasMore := len(page.edges) > limit
	if hasMore {
		page.edges = page.edges[:limit]
	}
	return page.edges, PageInfo{
		Offset:   offset,
		Limit:    limit,
		Total:    page.total,
		HasMore:  hasMore,
		Complete: !hasMore,
		Revision: page.revision,
	}, nil
}

// SearchResult is a lightweight node result for search autocomplete.
type SearchResult struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Kind string `json:"kind"`
}

// SearchNodes returns nodes whose name, uri, path, or hostname contains q (case-insensitive).
func (r *Reader) SearchNodes(ctx context.Context, q string, limit int) ([]SearchResult, error) {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	if limit <= 0 {
		limit = 20
	}

	cypher := `MATCH (n)
WHERE any(label IN labels(n) WHERE label IN $public_kinds)
  AND toLower(coalesce(n.name, n.uri, n.path, n.hostname, n.objectid, '')) CONTAINS toLower($q)
RETURN n.objectid AS id,
       coalesce(n.name, n.uri, n.path, n.hostname, n.objectid) AS name,
       labels(n) AS kinds
ORDER BY toLower(name), id
LIMIT $limit`

	result, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, cypher, map[string]any{
			"q":            q,
			"limit":        limit,
			"public_kinds": ingest.PublicNodeLabels,
		})
		if err != nil {
			return nil, err
		}
		var out []SearchResult
		for res.Next(ctx) {
			rec := res.Record()
			idVal, _ := rec.Get("id")
			nameVal, _ := rec.Get("name")
			kindsVal, _ := rec.Get("kinds")
			sr := SearchResult{}
			if s, ok := idVal.(string); ok {
				sr.ID = s
			}
			if s, ok := nameVal.(string); ok {
				sr.Name = s
			}
			sr.Kind = publicNodeKind(kindsVal)
			if sr.ID == "" {
				continue
			}
			out = append(out, sr)
		}
		return out, res.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("search nodes: %w", err)
	}
	results, _ := result.([]SearchResult)
	if results == nil {
		results = []SearchResult{}
	}
	return results, nil
}

// GetNeighborhood returns all nodes and edges within depth hops of the given node.
// depth is clamped to [1, 3].
func (r *Reader) GetNeighborhood(ctx context.Context, objectID string, depth int) ([]ingest.Node, []ingest.Edge, error) {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	if depth < 1 {
		depth = 1
	}
	if depth > 3 {
		depth = 3
	}

	type neighborhoodResult struct {
		nodes []ingest.Node
		edges []ingest.Edge
	}

	// First: check the center node exists and collect all nodes within depth hops.
	nodesCypher := fmt.Sprintf(`MATCH (center {objectid: $id})
WHERE any(label IN labels(center) WHERE label IN $public_kinds)
OPTIONAL MATCH (center)-[*1..%d]-(m)
WITH collect(DISTINCT center) + collect(DISTINCT m) AS all_nodes
UNWIND all_nodes AS n
WITH n WHERE n IS NOT NULL
RETURN DISTINCT n, labels(n) AS kinds`, depth)

	// Second: collect edges where both endpoints are within the neighborhood.
	edgesCypher := fmt.Sprintf(`MATCH (center {objectid: $id})
OPTIONAL MATCH (center)-[*1..%d]-(reach)
WITH collect(DISTINCT center) + collect(DISTINCT reach) AS scope
UNWIND scope AS n
WITH collect(DISTINCT n) AS scope_nodes
UNWIND scope_nodes AS a
UNWIND scope_nodes AS b
WITH a, b WHERE id(a) < id(b) OR id(a) <> id(b)
MATCH (a)-[r]->(b)
RETURN a.objectid AS source, b.objectid AS target, type(r) AS kind, properties(r) AS props, labels(a)[0] AS source_kind, labels(b)[0] AS target_kind`, depth)

	result, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		// Node query
		queryParams := map[string]any{
			"id":           objectID,
			"public_kinds": ingest.PublicNodeLabels,
		}
		res, err := tx.Run(ctx, nodesCypher, queryParams)
		if err != nil {
			return nil, err
		}

		seenNodes := make(map[string]bool)
		var nodes []ingest.Node

		for res.Next(ctx) {
			record := res.Record()
			neoNode, ok := record.Values[0].(neo4j.Node)
			if !ok {
				continue
			}
			oid, _ := neoNode.Props["objectid"].(string)
			if oid == "" || seenNodes[oid] {
				continue
			}
			seenNodes[oid] = true
			kindsVal, _ := record.Values[1].([]any)
			kindStrs := make([]string, 0, len(kindsVal))
			for _, k := range kindsVal {
				if s, ok := k.(string); ok {
					kindStrs = append(kindStrs, s)
				}
			}
			nodes = append(nodes, ingest.Node{
				ID:         oid,
				Kinds:      kindStrs,
				Properties: neoNode.Props,
			})
		}
		if err := res.Err(); err != nil {
			return nil, err
		}
		if len(nodes) == 0 {
			return nil, nil
		}

		// Edge query
		edgeRes, err := tx.Run(ctx, edgesCypher, queryParams)
		if err != nil {
			return nil, err
		}

		seenEdges := make(map[string]bool)
		edges := make([]ingest.Edge, 0)
		for edgeRes.Next(ctx) {
			rec := edgeRes.Record()
			srcVal, _ := rec.Get("source")
			tgtVal, _ := rec.Get("target")
			kindVal, _ := rec.Get("kind")
			propsVal, _ := rec.Get("props")
			srcKindVal, _ := rec.Get("source_kind")
			tgtKindVal, _ := rec.Get("target_kind")

			src, _ := srcVal.(string)
			tgt, _ := tgtVal.(string)
			kindStr, _ := kindVal.(string)
			if src == "" || tgt == "" || kindStr == "" {
				continue
			}
			key := fmt.Sprintf("%s->%s:%s", src, tgt, kindStr)
			if seenEdges[key] {
				continue
			}
			seenEdges[key] = true

			e := ingest.Edge{
				Source: src,
				Target: tgt,
				Kind:   kindStr,
			}
			if sk, ok := srcKindVal.(string); ok {
				e.SourceKind = sk
			}
			if tk, ok := tgtKindVal.(string); ok {
				e.TargetKind = tk
			}
			if p, ok := propsVal.(map[string]any); ok {
				e.Properties = p
			}
			edges = append(edges, e)
		}

		return &neighborhoodResult{nodes: nodes, edges: edges}, edgeRes.Err()
	})
	if err != nil {
		return nil, nil, fmt.Errorf("get neighborhood: %w", err)
	}
	if result == nil {
		return nil, nil, nil
	}
	nr, ok := result.(*neighborhoodResult)
	if !ok {
		return nil, nil, nil
	}
	if nr.nodes == nil {
		nr.nodes = []ingest.Node{}
	}
	if nr.edges == nil {
		nr.edges = []ingest.Edge{}
	}
	return nr.nodes, nr.edges, nil
}

// BlastRadiusResult holds the reachable subgraph from a source node, with nodes
// grouped by their BFS hop distance for concentric ring rendering.
type BlastRadiusResult struct {
	Nodes []ingest.Node    `json:"nodes"`
	Edges []ingest.Edge    `json:"edges"`
	Rings map[int][]string `json:"rings"` // hop distance -> []objectid
}

func blastRadiusTraversalPattern(direction string) string {
	switch direction {
	case "in":
		return "<--"
	case "both":
		return "--"
	default:
		return "-->"
	}
}

// GetBlastRadius returns all nodes reachable from the given source node within
// maxHops, along with the edges that form the reachable subgraph and a ring map
// grouping nodes by hop distance.
//
// direction:
//
//	"out"  — follow outgoing edges only (default; blast radius semantics)
//	"in"   — follow incoming edges only (inbound reach)
//	"both" — undirected (equivalent to full neighborhood)
//
// maxHops is clamped to [1, 10].
func (r *Reader) GetBlastRadius(ctx context.Context, objectID, direction string, maxHops int) (*BlastRadiusResult, error) {
	if maxHops < 1 {
		maxHops = 1
	}
	if maxHops > 10 {
		maxHops = 10
	}

	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	// Verify the source node exists first. Empty result => nil (not found).
	centerCypher := "MATCH (center {objectid: $id}) RETURN count(center) AS c"
	centerExists, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, centerCypher, map[string]any{"id": objectID})
		if err != nil {
			return false, err
		}
		if !res.Next(ctx) {
			return false, res.Err()
		}
		c, _ := res.Record().Values[0].(int64)
		return c > 0, res.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("blast radius center check: %w", err)
	}
	if exists, _ := centerExists.(bool); !exists {
		return nil, nil
	}

	// BFS expansion per hop. We issue one query per hop level using the
	// current frontier as the starting set. This is bounded (maxHops <= 10)
	// and avoids Neo4j's pathological variable-length pattern materialization
	// on dense graphs while giving us exact ring-level grouping.
	arrow := blastRadiusTraversalPattern(direction)

	visited := map[string]ingest.Node{}
	rings := map[int][]string{0: {objectID}}
	frontier := []string{objectID}

	expandCypher := fmt.Sprintf(
		`UNWIND $ids AS id
MATCH (a {objectid: id})%s(b)
WHERE NOT b.objectid IN $visited
RETURN DISTINCT b`, arrow)

	for hop := 1; hop <= maxHops && len(frontier) > 0; hop++ {
		visitedIDs := make([]string, 0, len(visited)+1)
		visitedIDs = append(visitedIDs, objectID)
		for id := range visited {
			visitedIDs = append(visitedIDs, id)
		}

		params := map[string]any{"ids": frontier, "visited": visitedIDs}
		hopResult, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
			res, err := tx.Run(ctx, expandCypher, params)
			if err != nil {
				return nil, err
			}
			var nodes []ingest.Node
			for res.Next(ctx) {
				record := res.Record()
				neoNode, ok := record.Values[0].(neo4j.Node)
				if !ok {
					continue
				}
				oid, _ := neoNode.Props["objectid"].(string)
				if oid == "" {
					continue
				}
				kinds := make([]string, 0, len(neoNode.Labels))
				kinds = append(kinds, neoNode.Labels...)
				nodes = append(nodes, ingest.Node{
					ID:         oid,
					Kinds:      kinds,
					Properties: neoNode.Props,
				})
			}
			return nodes, res.Err()
		})
		if err != nil {
			return nil, fmt.Errorf("blast radius hop %d: %w", hop, err)
		}
		newNodes, _ := hopResult.([]ingest.Node)

		nextFrontier := make([]string, 0, len(newNodes))
		ringIDs := make([]string, 0, len(newNodes))
		for _, n := range newNodes {
			if _, seen := visited[n.ID]; seen {
				continue
			}
			visited[n.ID] = n
			nextFrontier = append(nextFrontier, n.ID)
			ringIDs = append(ringIDs, n.ID)
		}
		if len(ringIDs) > 0 {
			rings[hop] = ringIDs
		}
		frontier = nextFrontier
	}

	// Collect the center node and all visited nodes in a single slice.
	centerNodeCypher := "MATCH (center {objectid: $id}) RETURN center, labels(center) AS kinds"
	centerResult, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, centerNodeCypher, map[string]any{"id": objectID})
		if err != nil {
			return nil, err
		}
		if !res.Next(ctx) {
			return nil, res.Err()
		}
		record := res.Record()
		neoNode, ok := record.Values[0].(neo4j.Node)
		if !ok {
			return nil, res.Err()
		}
		kindsVal, _ := record.Values[1].([]any)
		kindStrs := make([]string, 0, len(kindsVal))
		for _, k := range kindsVal {
			if s, ok := k.(string); ok {
				kindStrs = append(kindStrs, s)
			}
		}
		return ingest.Node{
			ID:         objectID,
			Kinds:      kindStrs,
			Properties: neoNode.Props,
		}, res.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("blast radius center fetch: %w", err)
	}

	nodes := make([]ingest.Node, 0, len(visited)+1)
	if center, ok := centerResult.(ingest.Node); ok {
		nodes = append(nodes, center)
	}
	for _, n := range visited {
		nodes = append(nodes, n)
	}

	// Edge collection matches stored edges where both endpoints are visited.
	// Traversal direction affects the node scope, not returned edge orientation.
	scope := make([]string, 0, len(nodes))
	for _, n := range nodes {
		scope = append(scope, n.ID)
	}
	const edgeCypher = `MATCH (a)-[r]->(b)
WHERE a.objectid IN $scope AND b.objectid IN $scope
RETURN a.objectid AS source, b.objectid AS target, type(r) AS kind, properties(r) AS props, labels(a)[0] AS source_kind, labels(b)[0] AS target_kind`

	edgeResult, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, edgeCypher, map[string]any{"scope": scope})
		if err != nil {
			return nil, err
		}
		seen := make(map[string]bool)
		var edges []ingest.Edge
		for res.Next(ctx) {
			rec := res.Record()
			srcVal, _ := rec.Get("source")
			tgtVal, _ := rec.Get("target")
			kindVal, _ := rec.Get("kind")
			propsVal, _ := rec.Get("props")
			srcKindVal, _ := rec.Get("source_kind")
			tgtKindVal, _ := rec.Get("target_kind")

			src, _ := srcVal.(string)
			tgt, _ := tgtVal.(string)
			kindStr, _ := kindVal.(string)
			if src == "" || tgt == "" || kindStr == "" {
				continue
			}
			key := fmt.Sprintf("%s->%s:%s", src, tgt, kindStr)
			if seen[key] {
				continue
			}
			seen[key] = true

			e := ingest.Edge{
				Source: src,
				Target: tgt,
				Kind:   kindStr,
			}
			if sk, ok := srcKindVal.(string); ok {
				e.SourceKind = sk
			}
			if tk, ok := tgtKindVal.(string); ok {
				e.TargetKind = tk
			}
			if p, ok := propsVal.(map[string]any); ok {
				e.Properties = p
			}
			edges = append(edges, e)
		}
		return edges, res.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("blast radius edges: %w", err)
	}
	edges, _ := edgeResult.([]ingest.Edge)
	// Normalize nil to an empty slice so the JSON response carries `[]`, never
	// `null`. An isolated node has zero in-scope edges; the client's blast
	// radius transform calls `.map` on edges, which throws on null (AH-UI-11).
	if edges == nil {
		edges = []ingest.Edge{}
	}
	if nodes == nil {
		nodes = []ingest.Node{}
	}

	return &BlastRadiusResult{
		Nodes: nodes,
		Edges: edges,
		Rings: rings,
	}, nil
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
	// Normalize nil to an empty slice so a zero-row query serializes as `[]`
	// rather than `null`. The Query Library reads `rows.length` client-side,
	// which throws on null and trips the root error boundary (AH-UI-11).
	if rows == nil {
		rows = []map[string]any{}
	}
	return rows, nil
}
