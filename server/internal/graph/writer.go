package graph

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

const defaultBatchSize = 1000

// execFunc executes a single cypher batch. Real driver-backed instances use
// driverExecBatch; tests inject an in-memory recorder to assert batching,
// APOC routing, and error propagation without a live Neo4j.
type execFunc func(ctx context.Context, cypher string, params map[string]any) (int, error)

type Writer struct {
	driver    neo4j.DriverWithContext
	hasAPOC   bool
	apocOnce  sync.Once
	batchSize int
	execFn    execFunc
}

func NewWriter(driver neo4j.DriverWithContext) *Writer {
	w := &Writer{
		driver:    driver,
		batchSize: defaultBatchSize,
	}
	w.execFn = w.driverExecBatch
	return w
}

func (w *Writer) detectAPOC(ctx context.Context) {
	w.apocOnce.Do(func() {
		session := w.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
		defer session.Close(ctx)
		_, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
			if name, err := detectAPOCWithQuery(ctx, tx, "SHOW PROCEDURES YIELD name WHERE name = 'apoc.merge.relationship' RETURN name"); err == nil {
				return name, nil
			}
			return detectAPOCWithQuery(ctx, tx, "CALL dbms.procedures() YIELD name WHERE name = 'apoc.merge.relationship' RETURN name")
		})
		w.hasAPOC = err == nil
		if w.hasAPOC {
			slog.Info("APOC detected")
		} else {
			slog.Info("APOC not available, using fallback writer")
		}
	})
}

func detectAPOCWithQuery(ctx context.Context, tx neo4j.ManagedTransaction, cypher string) (any, error) {
	res, err := tx.Run(ctx, cypher, nil)
	if err != nil {
		return nil, err
	}
	if res.Next(ctx) {
		return res.Record().Values[0], nil
	}
	return nil, fmt.Errorf("apoc.merge.relationship not found")
}

func (w *Writer) WriteNodes(ctx context.Context, nodes []ingest.Node, scanID string) (int, error) {
	if len(nodes) == 0 {
		return 0, nil
	}
	return w.writeNodesBatched(ctx, nodes, scanID)
}

// WriteNodesForGeneration writes immutable node observations for one
// generation. objectid remains the stable logical identity exposed to callers;
// observation_id is the physical merge key, so a later generation can observe
// the same logical node with different properties without mutating an earlier
// generation's observation.
func (w *Writer) WriteNodesForGeneration(ctx context.Context, nodes []ingest.Node, scanID, generationID string) (int, error) {
	if len(nodes) == 0 {
		return 0, nil
	}
	grouped := groupNodesByKindTuple(nodes)
	total := 0
	for tupleKey, group := range grouped {
		cypher := generationNodeCypherForKindTuple(group.PrimaryKind, group.ExtraLabels)
		for i := 0; i < len(group.Nodes); i += w.batchSize {
			end := min(i+w.batchSize, len(group.Nodes))
			batch := group.Nodes[i:end]
			params := make([]map[string]any, len(batch))
			for j, n := range batch {
				params[j] = map[string]any{
					"id":             n.ID,
					"observation_id": generationID + "\x1f" + n.ID,
					"properties":     n.Properties,
				}
			}
			written, err := w.execFn(ctx, cypher, map[string]any{
				"nodes":         params,
				"scan_id":       scanID,
				"generation_id": generationID,
			})
			if err != nil {
				return total, fmt.Errorf("generation node batch %s at offset %d: %w", tupleKey, i, err)
			}
			total += written
		}
	}
	return total, nil
}

func (w *Writer) writeNodesBatched(ctx context.Context, nodes []ingest.Node, scanID string) (int, error) {
	grouped := groupNodesByKindTuple(nodes)
	total := 0

	for tupleKey, group := range grouped {
		cypher := nodeCypherForKindTuple(group.PrimaryKind, group.ExtraLabels)

		for i := 0; i < len(group.Nodes); i += w.batchSize {
			end := min(i+w.batchSize, len(group.Nodes))
			batch := group.Nodes[i:end]

			params := make([]map[string]any, len(batch))
			for j, n := range batch {
				params[j] = map[string]any{
					"id":         n.ID,
					"properties": n.Properties,
				}
			}

			written, err := w.execFn(ctx, cypher, map[string]any{
				"nodes":   params,
				"scan_id": scanID,
			})
			if err != nil {
				return total, fmt.Errorf("fallback node batch %s at offset %d: %w", tupleKey, i, err)
			}
			total += written
		}
	}
	return total, nil
}

// nodeCypherForKindTuple builds a MERGE-on-primary-label, then-SET-umbrella-labels
// statement. Kinds[1:] cannot be parameterized in Cypher (labels are a syntactic
// element, not a value), so the labels are inlined into the template; we
// rely on `ingest.AllowedNodeKinds` having already validated each label
// upstream so this is safe from injection.
func nodeCypherForKindTuple(primaryKind string, extraLabels []string) string {
	var sb strings.Builder
	sb.WriteString("UNWIND $nodes AS node\n")
	fmt.Fprintf(&sb, "MERGE (n:%s {objectid: node.id})\n", primaryKind)
	// ON CREATE: seed the previous-hash trio from the incoming hashes so the
	// rug-pull predicates (which gate on previous_*_hash IS NOT NULL) do not
	// fire spuriously on a tool's/server's first scan. Reading from
	// node.properties.* is unambiguous regardless of SET-item ordering.
	sb.WriteString("ON CREATE SET n = node.properties, n.objectid = node.id, n.scan_id = $scan_id, n.first_seen = datetime(), n.last_seen = datetime(), n.previous_description_hash = node.properties.description_hash, n.previous_input_schema_hash = node.properties.input_schema_hash, n.previous_instructions_hash = node.properties.instructions_hash\n")
	// ON MATCH: pivot previous_*_hash = current hash BEFORE n += node.properties
	// overwrites the current values. SET items apply left-to-right, so the
	// three pivots capture the prior scan's hashes (rug-pull change detection).
	sb.WriteString("ON MATCH SET n.previous_description_hash = n.description_hash, n.previous_input_schema_hash = n.input_schema_hash, n.previous_instructions_hash = n.instructions_hash, n += node.properties, n.scan_id = $scan_id, n.last_seen = datetime()")
	for _, lbl := range extraLabels {
		fmt.Fprintf(&sb, "\nSET n:%s", lbl)
	}
	sb.WriteString("\nRETURN count(*) AS written")
	return sb.String()
}

func generationNodeCypherForKindTuple(primaryKind string, extraLabels []string) string {
	var sb strings.Builder
	sb.WriteString("UNWIND $nodes AS node\n")
	fmt.Fprintf(&sb, "MERGE (n:%s {observation_id: node.observation_id})\n", primaryKind)
	sb.WriteString("ON CREATE SET n = node.properties, n.objectid = node.id, n.scan_id = $scan_id, n.generation_id = $generation_id, n.generations = [$generation_id], n.first_seen = datetime(), n.last_seen = datetime(), n.previous_description_hash = node.properties.description_hash, n.previous_input_schema_hash = node.properties.input_schema_hash, n.previous_instructions_hash = node.properties.instructions_hash\n")
	// Replays of the same scan/generation are idempotent. No other generation
	// can match this observation_id, so this update never mutates history.
	sb.WriteString("ON MATCH SET n += node.properties, n.objectid = node.id, n.scan_id = $scan_id, n.generation_id = $generation_id, n.generations = [$generation_id], n.last_seen = datetime()")
	for _, lbl := range extraLabels {
		fmt.Fprintf(&sb, "\nSET n:%s", lbl)
	}
	sb.WriteString("\nRETURN count(*) AS written")
	return sb.String()
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

// WriteEdgesForGeneration writes immutable relationship observations between
// node observations in the same generation.
func (w *Writer) WriteEdgesForGeneration(ctx context.Context, edges []ingest.Edge, scanID, generationID string) (int, error) {
	if len(edges) == 0 {
		return 0, nil
	}
	grouped := groupEdgesByEndpoints(edges)
	total := 0
	for key, kindEdges := range grouped {
		cypher := generationEdgeCypherForKinds(key.Kind, key.SourceKind, key.TargetKind)
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
			written, err := w.execFn(ctx, cypher, map[string]any{
				"edges":         params,
				"scan_id":       scanID,
				"generation_id": generationID,
			})
			if err != nil {
				return total, fmt.Errorf("generation edge batch %s at offset %d: %w", key.Kind, i, err)
			}
			total += written
		}
	}
	return total, nil
}

// WriteEdgesForScan writes processor-produced edges only between node
// observations owned by scanID. Generation tagging runs after processors and
// stamps these edges with the generation.
func (w *Writer) WriteEdgesForScan(ctx context.Context, edges []ingest.Edge, scanID string) (int, error) {
	if len(edges) == 0 {
		return 0, nil
	}
	grouped := groupEdgesByEndpoints(edges)
	total := 0
	for key, kindEdges := range grouped {
		sourceMatch := matchClause("a", key.SourceKind, "source")
		targetMatch := matchClause("b", key.TargetKind, "target")
		cypher := fmt.Sprintf(`UNWIND $edges AS edge
%s
%s
WHERE a.scan_id = $scan_id AND b.scan_id = $scan_id
MERGE (a)-[r:%s]->(b)
SET r += edge.properties, r.scan_id = $scan_id, r.last_seen = datetime()
RETURN count(*) AS written`, sourceMatch, targetMatch, key.Kind)
		for i := 0; i < len(kindEdges); i += w.batchSize {
			end := min(i+w.batchSize, len(kindEdges))
			batch := kindEdges[i:end]
			params := make([]map[string]any, len(batch))
			for j, e := range batch {
				props := e.Properties
				if props == nil {
					props = map[string]any{}
				}
				params[j] = map[string]any{"source": e.Source, "target": e.Target, "properties": props}
			}
			written, err := w.execFn(ctx, cypher, map[string]any{"edges": params, "scan_id": scanID})
			if err != nil {
				return total, fmt.Errorf("scan edge batch %s at offset %d: %w", key.Kind, i, err)
			}
			total += written
		}
	}
	return total, nil
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

			written, err := w.execFn(ctx, cypher, map[string]any{
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

			written, err := w.execFn(ctx, cypher, map[string]any{
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

func generationEdgeCypherForKinds(edgeKind, sourceKind, targetKind string) string {
	sourceMatch := matchClause("a", sourceKind, "source")
	targetMatch := matchClause("b", targetKind, "target")
	return fmt.Sprintf(`UNWIND $edges AS edge
%s
%s
WHERE a.generation_id = $generation_id AND b.generation_id = $generation_id
MERGE (a)-[r:%s]->(b)
SET r += edge.properties, r.scan_id = $scan_id, r.generation_id = $generation_id,
    r.generations = [$generation_id], r.last_seen = datetime()
RETURN count(*) AS written`, sourceMatch, targetMatch, edgeKind)
}

// driverExecBatch executes a cypher batch against the live Neo4j driver. It is
// the production implementation of execFn. Kept as a method (not a free func)
// so it can be swapped per-Writer for tests.
func (w *Writer) driverExecBatch(ctx context.Context, cypher string, params map[string]any) (int, error) {
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

// nodeKindTuple captures a node's MERGE shape: the primary label that owns the
// uniqueness constraint plus the extra umbrella labels that get applied via
// SET. Nodes that share a tuple share a Cypher template and a write batch.
type nodeKindTuple struct {
	PrimaryKind string
	ExtraLabels []string
	Nodes       []ingest.Node
}

// groupNodesByKindTuple partitions nodes by their full Kinds shape so that
// multi-label nodes (e.g. ["LiteLLMGateway", "AIService"]) get a Cypher
// template that MERGEs on the per-kind label and SETs the umbrella, while
// single-label nodes ([\"MCPServer\"]) take the original code path
// transparently. Extra labels are sorted so [A,B] and [B,A] hash to the
// same group.
func groupNodesByKindTuple(nodes []ingest.Node) map[string]*nodeKindTuple {
	grouped := make(map[string]*nodeKindTuple)
	for _, n := range nodes {
		primary := "Node"
		var extras []string
		if len(n.Kinds) > 0 {
			primary = n.Kinds[0]
			if len(n.Kinds) > 1 {
				extras = make([]string, len(n.Kinds)-1)
				copy(extras, n.Kinds[1:])
				sort.Strings(extras)
			}
		}
		key := primary
		if len(extras) > 0 {
			key = primary + "+" + strings.Join(extras, ",")
		}
		group, ok := grouped[key]
		if !ok {
			group = &nodeKindTuple{
				PrimaryKind: primary,
				ExtraLabels: extras,
			}
			grouped[key] = group
		}
		group.Nodes = append(group.Nodes, n)
	}
	return grouped
}

// groupNodesByKind is kept for backwards compatibility with existing tests
// that assert grouping by primary kind only. New code should use
// groupNodesByKindTuple.
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
