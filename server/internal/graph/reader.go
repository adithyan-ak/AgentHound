package graph

import (
	"context"
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
	return r.GetStatsScoped(ctx, nil)
}

// GetStatsScoped returns node/edge counts scoped to the given generations.
// When gens is non-empty only facts whose generations set intersects those ids
// are counted; an empty gens counts all generations (unscoped). Membership
// (not a scalar generation_id) is used so a fact observed by several
// generations is counted for each promoted generation that saw it — retention
// is non-destructive, so a demoted generation's facts survive but drop out of
// the current view. Internal :SchemaVersion markers are never counted.
func (r *Reader) GetStatsScoped(ctx context.Context, gens []string) (*GraphStats, error) {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	stats := &GraphStats{
		NodeCounts: make(map[string]int64),
		EdgeCounts: make(map[string]int64),
	}

	nodeWhere := "WHERE NOT n:SchemaVersion"
	edgeWhere := ""
	params := map[string]any{}
	if len(gens) > 0 {
		nodeWhere += " AND ANY(g IN coalesce(n.generations, []) WHERE g IN $gens)"
		edgeWhere = "WHERE ANY(g IN coalesce(r.generations, []) WHERE g IN $gens)"
		params["gens"] = gens
	}

	// Node counts. Internal :SchemaVersion migration markers are excluded so
	// they never surface as a node kind or inflate the user-facing inventory.
	// Counting DISTINCT objectid (not physical rows) is the logical-current
	// projection for stats: when several current generations each observe the
	// same objectid (e.g. config + mcp both describe one MCPServer), the
	// logical node is counted once rather than once per physical observation.
	_, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, "MATCH (n) "+nodeWhere+" RETURN labels(n)[0] AS kind, count(DISTINCT n.objectid) AS count", params)
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

	// Edge counts. Counted as DISTINCT logical (source objectid, kind, target
	// objectid) triples rather than physical relationships, so a relationship
	// observed by several current generations (or duplicated across the
	// physical observations of a merged logical node) is counted once. This is
	// the edge-inventory analogue of the distinct-objectid node count above.
	_, err = session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, "MATCH (a)-[r]->(b) "+edgeWhere+" RETURN type(r) AS kind, count(DISTINCT [a.objectid, type(r), b.objectid]) AS count", params)
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

// genPredicate returns a Cypher boolean fragment (with a leading " AND " when
// non-empty) that restricts variable `v` to facts observed by one of the
// scoped generations, and registers the $gens param. An empty gens yields an
// empty fragment (unscoped) — the historical behaviour used by ingest-time
// processors that operate on freshly-written, scan-tagged facts. Scoping keys
// on generations-set MEMBERSHIP (not a scalar) so a retained/demoted
// generation's facts drop out of the current view without being destroyed.
func genPredicate(v string, gens []string, params map[string]any) string {
	if len(gens) == 0 {
		return ""
	}
	params["gens"] = gens
	return fmt.Sprintf(" AND ANY(g IN coalesce(%s.generations, []) WHERE g IN $gens)", v)
}

// GetNode returns a node and its edges, scoped to the given generations. When
// gens is non-empty a node outside the current generations is reported as not
// found, and only edges whose set intersects the scope (and whose neighbour is
// itself in-scope) are returned — a retained historical fact never leaks into
// a detail read.
func (r *Reader) GetNode(ctx context.Context, objectID string, gens []string) (*ingest.Node, []ingest.Edge, error) {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	type nodeResult struct {
		node  *ingest.Node
		edges []ingest.Edge
	}

	result, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		// Get node (scoped to current generations when gens is non-empty).
		nodeParams := map[string]any{"id": objectID}
		nodePred := genPredicate("n", gens, nodeParams)
		nodeCypher := "MATCH (n {objectid: $id})"
		if nodePred != "" {
			nodeCypher += " WHERE true" + nodePred
		}
		nodeCypher += " RETURN n, labels(n) AS kinds"
		res, err := tx.Run(ctx, nodeCypher, nodeParams)
		if err != nil {
			return nil, err
		}
		// Collect every in-scope physical observation of this objectid and
		// merge them into one deterministic logical node. When several current
		// generations observe the same objectid, this returns the merged node
		// (union of properties, deterministic conflict winner) instead of an
		// arbitrary single physical observation.
		var obs []physObservation
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
			obs = append(obs, physObservation{props: neoNode.Props, labels: kindStrs})
		}
		if err := res.Err(); err != nil {
			return nil, err
		}
		if len(obs) == 0 {
			return nil, nil
		}
		merged := mergeObservations(objectID, obs)
		node := &merged

		// Get connected edges. When scoped, keep only edges AND neighbours that
		// are themselves in the current generations, so a retained historical
		// edge/neighbour never leaks into the node detail view.
		edgeParams := map[string]any{"id": objectID}
		edgePred := genPredicate("r", gens, edgeParams) + genPredicate("m", gens, edgeParams)
		edgeCypher := "MATCH (n {objectid: $id})-[r]-(m)"
		if edgePred != "" {
			edgeCypher += " WHERE true" + edgePred
		}
		edgeCypher += `
RETURN type(r) AS kind, properties(r) AS props,
       startNode(r) = n AS outgoing,
       m.objectid AS other_id`
		edgeRes, err := tx.Run(ctx, edgeCypher, edgeParams)
		if err != nil {
			return &nodeResult{node: node}, nil
		}

		var edges []ingest.Edge
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

		// A merged logical node's edges are matched by objectid, so the same
		// logical edge can arrive once per physical observation; collapse to
		// distinct (source, kind, target) triples.
		return &nodeResult{node: node, edges: dedupEdgesLogical(edges)}, nil
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
	return r.ListNodesPage(ctx, kind, limit, 0, nil)
}

// ListNodesPage lists nodes with an explicit offset for exhaustive paging and
// an optional generation filter. When gens is non-empty the read is scoped to
// those generations (n.generation_id IN gens); an empty gens reads all
// generations — the historical, unscoped behaviour used by ingest-time
// processors that operate on freshly-written, scan-tagged facts.
func (r *Reader) ListNodesPage(ctx context.Context, kind string, limit, offset int, gens []string) ([]ingest.Node, error) {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	if limit <= 0 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	// Validate kind to prevent Cypher injection
	var match string
	conds := []string{}
	if kind != "" {
		if !ingest.AllowedNodeKinds[kind] {
			return nil, fmt.Errorf("invalid node kind: %s", kind)
		}
		match = fmt.Sprintf("MATCH (n:%s)", kind)
	} else {
		// Exclude internal :SchemaVersion migration markers from the
		// unfiltered listing — they are not user inventory.
		match = "MATCH (n)"
		conds = append(conds, "NOT n:SchemaVersion")
	}
	params := map[string]any{"limit": limit, "offset": offset}
	if len(gens) > 0 {
		conds = append(conds, "ANY(g IN coalesce(n.generations, []) WHERE g IN $gens)")
		params["gens"] = gens
	}
	where := ""
	if len(conds) > 0 {
		where = " WHERE " + strings.Join(conds, " AND ")
	}

	// Scoped reads project to the logical-current node: group physical
	// observations by objectid so pagination pages over distinct logical
	// nodes (not physical rows) and duplicate observations of the same
	// objectid across current generations never leak as separate rows. The
	// per-objectid observation set is merged deterministically in Go.
	if len(gens) > 0 {
		return r.listLogicalNodes(ctx, session, match, where, params)
	}

	// Unscoped (ingest-time processors): physical rows, historical behaviour.
	order := ""
	if kind != "" {
		order = " ORDER BY n.name"
	}
	cypher := match + where + " RETURN n, labels(n) AS kinds" + order + " SKIP $offset LIMIT $limit"

	result, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, cypher, params)
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
		return nodes, res.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("list nodes: %w", err)
	}
	nodes, _ := result.([]ingest.Node)
	return nodes, nil
}

// listLogicalNodes runs the grouped, logical-current projection for a scoped
// node listing: it groups by objectid, orders deterministically by display name
// (then objectid), paginates over the distinct logical nodes, and merges each
// objectid's physical observations into one node.
func (r *Reader) listLogicalNodes(ctx context.Context, session neo4j.SessionWithContext, match, where string, params map[string]any) ([]ingest.Node, error) {
	cypher := match + where + `
WITH n.objectid AS oid, collect({props: properties(n), labels: labels(n)}) AS obs, coalesce(max(n.name), n.objectid) AS nm
RETURN oid, obs ORDER BY nm, oid SKIP $offset LIMIT $limit`

	result, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, cypher, params)
		if err != nil {
			return nil, err
		}
		var nodes []ingest.Node
		for res.Next(ctx) {
			rec := res.Record()
			oid, _ := rec.Values[0].(string)
			obsRaw, _ := rec.Values[1].([]any)
			nodes = append(nodes, mergeObservations(oid, decodeObservations(obsRaw)))
		}
		return nodes, res.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("list nodes: %w", err)
	}
	nodes, _ := result.([]ingest.Node)
	return nodes, nil
}

// anySliceToMaps converts a Neo4j `collect(properties(r))` value (a []any of
// map[string]any) into a typed slice for deterministic representative picking.
func anySliceToMaps(v any) []map[string]any {
	raw, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]map[string]any, 0, len(raw))
	for _, item := range raw {
		if m, ok := item.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// decodeObservations converts the Neo4j `collect({props, labels})` rows into
// physObservation values for deterministic merging.
func decodeObservations(raw []any) []physObservation {
	out := make([]physObservation, 0, len(raw))
	for _, item := range raw {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		obs := physObservation{}
		if p, ok := m["props"].(map[string]any); ok {
			obs.props = p
		}
		if labels, ok := m["labels"].([]any); ok {
			for _, l := range labels {
				if s, ok := l.(string); ok {
					obs.labels = append(obs.labels, s)
				}
			}
		}
		out = append(out, obs)
	}
	return out
}

func (r *Reader) ListEdges(ctx context.Context, kind, sourceID, targetID string, limit int) ([]ingest.Edge, error) {
	return r.ListEdgesPage(ctx, kind, sourceID, targetID, limit, 0, nil)
}

// ListEdgesPage lists edges with an explicit offset for exhaustive paging and
// an optional generation filter (r.generation_id IN gens when non-empty).
func (r *Reader) ListEdgesPage(ctx context.Context, kind, sourceID, targetID string, limit, offset int, gens []string) ([]ingest.Edge, error) {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	if limit <= 0 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	var cypher string
	params := map[string]any{"limit": limit, "offset": offset}
	var conditions []string

	if kind != "" {
		if !ingest.AllowedEdgeKinds[kind] {
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
	if len(gens) > 0 {
		conditions = append(conditions, "ANY(g IN coalesce(r.generations, []) WHERE g IN $gens)")
		params["gens"] = gens
	}

	if len(conditions) > 0 {
		cypher += " WHERE " + strings.Join(conditions, " AND ")
	}
	if len(gens) > 0 {
		// Scoped reads project to distinct logical (source, kind, target)
		// triples so a relationship observed by several current generations —
		// or duplicated across the physical observations of a merged logical
		// node — pages and renders once. ALL physical observations' properties
		// are collected so the representative is chosen DETERMINISTICALLY in Go
		// (by collector authority, then capture/completion time) rather than by
		// the driver's arbitrary collect() order.
		cypher += ` WITH a.objectid AS source, b.objectid AS target, type(r) AS kind,
       labels(a)[0] AS source_kind, labels(b)[0] AS target_kind, collect(properties(r)) AS props_list
RETURN source, target, kind, props_list, source_kind, target_kind
ORDER BY kind, source, target SKIP $offset LIMIT $limit`
	} else {
		cypher += " RETURN a.objectid AS source, b.objectid AS target, type(r) AS kind, properties(r) AS props, labels(a)[0] AS source_kind, labels(b)[0] AS target_kind ORDER BY kind, source, target SKIP $offset LIMIT $limit"
	}

	result, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, cypher, params)
		if err != nil {
			return nil, err
		}

		var edges []ingest.Edge
		for res.Next(ctx) {
			record := res.Record()
			src, _ := record.Get("source")
			tgt, _ := record.Get("target")
			k, _ := record.Get("kind")
			srcKind, _ := record.Get("source_kind")
			tgtKind, _ := record.Get("target_kind")

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
			if sk, ok := srcKind.(string); ok {
				e.SourceKind = sk
			}
			if tk, ok := tgtKind.(string); ok {
				e.TargetKind = tk
			}
			// Scoped reads return props_list (all physical observations of the
			// triple) so the representative is chosen deterministically here;
			// unscoped reads return a single props map.
			if propsList, ok := record.Get("props_list"); ok {
				e.Properties = pickEdgePropsRepresentative(anySliceToMaps(propsList))
			} else if props, ok := record.Get("props"); ok {
				if p, ok := props.(map[string]any); ok {
					e.Properties = p
				}
			}
			edges = append(edges, e)
		}
		return edges, res.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("list edges: %w", err)
	}
	edges, _ := result.([]ingest.Edge)
	return edges, nil
}

// SearchResult is a lightweight node result for search autocomplete.
type SearchResult struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Kind string `json:"kind"`
}

// SearchNodes returns nodes whose name, uri, path, or hostname contains q
// (case-insensitive), scoped to the given generations. When gens is non-empty
// only nodes in the current generations match, so search never surfaces a
// retained historical node. Internal :SchemaVersion markers are excluded.
func (r *Reader) SearchNodes(ctx context.Context, q string, limit int, gens []string) ([]SearchResult, error) {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	if limit <= 0 {
		limit = 20
	}

	params := map[string]any{"q": q, "limit": limit}
	cypher := `MATCH (n)
WHERE NOT n:SchemaVersion
  AND toLower(coalesce(n.name, n.uri, n.path, n.hostname, n.objectid, '')) CONTAINS toLower($q)` +
		genPredicate("n", gens, params) + `
RETURN n.objectid AS id,
       coalesce(n.name, n.uri, n.path, n.hostname, n.objectid) AS name,
       labels(n)[0] AS kind
LIMIT $limit`

	result, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, cypher, params)
		if err != nil {
			return nil, err
		}
		var out []SearchResult
		for res.Next(ctx) {
			rec := res.Record()
			idVal, _ := rec.Get("id")
			nameVal, _ := rec.Get("name")
			kindVal, _ := rec.Get("kind")
			sr := SearchResult{}
			if s, ok := idVal.(string); ok {
				sr.ID = s
			}
			if s, ok := nameVal.(string); ok {
				sr.Name = s
			}
			if s, ok := kindVal.(string); ok {
				sr.Kind = s
			}
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
	// Collapse duplicate objectids: a logical node observed by several current
	// generations returns one physical row per observation, so search must not
	// list the same objectid multiple times.
	if len(results) > 1 {
		seen := make(map[string]bool, len(results))
		deduped := results[:0]
		for _, sr := range results {
			if seen[sr.ID] {
				continue
			}
			seen[sr.ID] = true
			deduped = append(deduped, sr)
		}
		results = deduped
	}
	return results, nil
}

// GetNeighborhood returns all nodes and edges within depth hops of the given
// node, scoped to the given generations. depth is clamped to [1, 3]. When gens
// is non-empty, only nodes and edges in the current generations are returned,
// so a retained historical fact never leaks into a neighbourhood read (an
// in-scope node reachable only via a historical path is still shown — it IS in
// the current view — but the historical intermediary and its edges are not).
func (r *Reader) GetNeighborhood(ctx context.Context, objectID string, depth int, gens []string) ([]ingest.Node, []ingest.Edge, error) {
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

	params := map[string]any{"id": objectID}
	nodeScopePred := genPredicate("n", gens, params)
	edgeScopePred := genPredicate("a", gens, params) + genPredicate("b", gens, params) + genPredicate("r", gens, params)

	// First: check the center node exists and collect all in-scope nodes within
	// depth hops.
	nodesCypher := fmt.Sprintf(`MATCH (center {objectid: $id})
OPTIONAL MATCH (center)-[*1..%d]-(m)
WITH collect(DISTINCT center) + collect(DISTINCT m) AS all_nodes
UNWIND all_nodes AS n
WITH n WHERE n IS NOT NULL%s
RETURN DISTINCT n, labels(n) AS kinds`, depth, nodeScopePred)

	// Second: collect in-scope edges where both endpoints are within the
	// neighborhood.
	edgesCypher := fmt.Sprintf(`MATCH (center {objectid: $id})
OPTIONAL MATCH (center)-[*1..%d]-(reach)
WITH collect(DISTINCT center) + collect(DISTINCT reach) AS scope
UNWIND scope AS n
WITH collect(DISTINCT n) AS scope_nodes
UNWIND scope_nodes AS a
UNWIND scope_nodes AS b
WITH a, b WHERE id(a) < id(b) OR id(a) <> id(b)
MATCH (a)-[r]->(b)
WITH a, b, r WHERE true%s
RETURN a.objectid AS source, b.objectid AS target, type(r) AS kind, properties(r) AS props, labels(a)[0] AS source_kind, labels(b)[0] AS target_kind`, depth, edgeScopePred)

	result, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		// Node query
		res, err := tx.Run(ctx, nodesCypher, params)
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
		edgeRes, err := tx.Run(ctx, edgesCypher, params)
		if err != nil {
			return &neighborhoodResult{nodes: nodes, edges: nil}, nil
		}

		seenEdges := make(map[string]bool)
		var edges []ingest.Edge
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
	return nr.nodes, nr.edges, nil
}

// BlastRadiusResult holds the reachable subgraph from a source node, with nodes
// grouped by their BFS hop distance for concentric ring rendering.
type BlastRadiusResult struct {
	Nodes []ingest.Node    `json:"nodes"`
	Edges []ingest.Edge    `json:"edges"`
	Rings map[int][]string `json:"rings"` // hop distance -> []objectid
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
//
// gens scopes the reachable subgraph to the current generations: when it is
// non-empty, expansion only follows into in-scope nodes and only in-scope
// edges are returned, so blast radius over a retained historical generation's
// facts cannot leak. An out-of-scope source node reports not found.
func (r *Reader) GetBlastRadius(ctx context.Context, objectID, direction string, maxHops int, gens []string) (*BlastRadiusResult, error) {
	if maxHops < 1 {
		maxHops = 1
	}
	if maxHops > 10 {
		maxHops = 10
	}
	switch direction {
	case "out", "in", "both":
	default:
		direction = "out"
	}

	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	// Verify the source node exists AND is in scope first. Empty => not found.
	centerParams := map[string]any{"id": objectID}
	centerCypher := "MATCH (center {objectid: $id}) WHERE true" + genPredicate("center", gens, centerParams) + " RETURN count(center) AS c"
	centerExists, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, centerCypher, centerParams)
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
	var arrow string
	switch direction {
	case "in":
		arrow = "<--"
	case "both":
		arrow = "--"
	default:
		arrow = "-->"
	}

	visited := map[string]ingest.Node{}
	rings := map[int][]string{0: {objectID}}
	frontier := []string{objectID}

	expandCypher := fmt.Sprintf(
		`UNWIND $ids AS id
MATCH (a {objectid: id})%s(b)
WHERE NOT b.objectid IN $visited%s
RETURN DISTINCT b`, arrow, genPredicate("b", gens, map[string]any{}))

	for hop := 1; hop <= maxHops && len(frontier) > 0; hop++ {
		visitedIDs := make([]string, 0, len(visited)+1)
		visitedIDs = append(visitedIDs, objectID)
		for id := range visited {
			visitedIDs = append(visitedIDs, id)
		}

		params := map[string]any{"ids": frontier, "visited": visitedIDs}
		if len(gens) > 0 {
			params["gens"] = gens
		}
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

	// Edge collection: match edges where BOTH endpoints are in the visited set,
	// respecting directionality consistent with the BFS.
	scope := make([]string, 0, len(nodes))
	for _, n := range nodes {
		scope = append(scope, n.ID)
	}
	// Edge collection: both endpoints already within the visited (in-scope)
	// set. When scoped, additionally require the edge itself to be in the
	// current generations, so a retained historical edge between two in-scope
	// nodes cannot leak. The three directions currently collect the same
	// endpoint-bounded edge set (directionality is enforced during BFS
	// expansion above).
	edgeParams := map[string]any{"scope": scope}
	edgeGenPred := genPredicate("a", gens, edgeParams) + genPredicate("b", gens, edgeParams) + genPredicate("r", gens, edgeParams)
	edgeCypher := `MATCH (a)-[r]->(b)
WHERE a.objectid IN $scope AND b.objectid IN $scope` + edgeGenPred + `
RETURN a.objectid AS source, b.objectid AS target, type(r) AS kind, properties(r) AS props, labels(a)[0] AS source_kind, labels(b)[0] AS target_kind`

	edgeResult, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, edgeCypher, edgeParams)
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
	return rows, nil
}
