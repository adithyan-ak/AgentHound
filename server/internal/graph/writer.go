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

const observationTokenSeparator = "\x1f"

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
	return w.WriteObservationNodes(ctx, nodes, scanID, nil)
}

func (w *Writer) WriteObservationNodes(
	ctx context.Context,
	nodes []ingest.Node,
	scanID string,
	completeDomains []string,
) (int, error) {
	if len(nodes) == 0 {
		return 0, nil
	}
	return w.writeNodesBatched(ctx, nodes, scanID, completeDomains)
}

func (w *Writer) writeNodesBatched(
	ctx context.Context,
	nodes []ingest.Node,
	scanID string,
	completeDomains []string,
) (int, error) {
	grouped := groupNodesByKindTuple(nodes)
	total := 0
	completePrefixes := observationDomainPrefixes(completeDomains)

	for tupleKey, group := range grouped {
		cypher := nodeCypherForKindTuple(group.PrimaryKind, group.ExtraLabels)

		for i := 0; i < len(group.Nodes); i += w.batchSize {
			end := min(i+w.batchSize, len(group.Nodes))
			batch := group.Nodes[i:end]

			params := make([]map[string]any, len(batch))
			for j, n := range batch {
				params[j] = map[string]any{
					"id":                          n.ID,
					"properties":                  factProperties(n.Properties),
					"observation_tokens":          observationTokens(n.ObservationDomains, scanID),
					"observation_domain_prefixes": observationDomainPrefixes(n.ObservationDomains),
					"complete_domain_prefixes":    completePrefixes,
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
	sb.WriteString(`ON CREATE SET n.__agenthound_observation_created = true
WITH n, node,
     coalesce(n.__agenthound_observation_created, false) AS observation_created,
     n.description_hash AS old_description_hash,
     n.input_schema_hash AS old_input_schema_hash,
     n.instructions_hash AS old_instructions_hash,
     n.first_seen AS old_first_seen,
     coalesce(n.observation_tokens, []) AS old_tokens,
     coalesce(n.observation_managed, false) AS old_managed,
     coalesce(n.legacy_observation, NOT coalesce(n.observation_managed, false)) AS old_legacy
WITH n, node, observation_created,
     old_description_hash, old_input_schema_hash, old_instructions_hash,
     old_first_seen, old_tokens, old_managed, old_legacy,
     (size(node.observation_tokens) > 0
      AND all(token IN node.observation_tokens WHERE
          any(prefix IN node.complete_domain_prefixes WHERE token STARTS WITH prefix))) AS incoming_complete
WITH n, node, observation_created,
     old_description_hash, old_input_schema_hash, old_instructions_hash,
     old_first_seen, old_tokens, old_managed, old_legacy, incoming_complete,
     (NOT observation_created
      AND incoming_complete
      AND (NOT old_managed OR
          all(token IN old_tokens WHERE
              any(prefix IN node.observation_domain_prefixes WHERE token STARTS WITH prefix)))) AS replace_properties
FOREACH (_ IN CASE WHEN observation_created OR replace_properties THEN [1] ELSE [] END |
  SET n = node.properties)
FOREACH (_ IN CASE WHEN NOT observation_created AND NOT replace_properties THEN [1] ELSE [] END |
  SET n += node.properties)
SET n.objectid = node.id,
    n.scan_id = $scan_id,
    n.first_seen = CASE WHEN observation_created THEN datetime() ELSE coalesce(old_first_seen, datetime()) END,
    n.last_seen = datetime(),
    n.previous_description_hash = CASE WHEN observation_created THEN node.properties.description_hash ELSE old_description_hash END,
    n.previous_input_schema_hash = CASE WHEN observation_created THEN node.properties.input_schema_hash ELSE old_input_schema_hash END,
    n.previous_instructions_hash = CASE WHEN observation_created THEN node.properties.instructions_hash ELSE old_instructions_hash END,
    n.observation_tokens = reduce(tokens = old_tokens, token IN node.observation_tokens |
      CASE WHEN token IN tokens THEN tokens ELSE tokens + token END),
    n.observation_managed = old_managed OR size(node.observation_tokens) > 0,
    n.observation_properties_complete = CASE
      WHEN observation_created THEN incoming_complete
      WHEN replace_properties THEN true
      ELSE false
    END,
    n.legacy_observation = CASE
      WHEN observation_created THEN size(node.observation_tokens) = 0
      WHEN replace_properties THEN false
      WHEN size(node.observation_tokens) > 0 AND NOT old_managed THEN true
      ELSE old_legacy
    END
REMOVE n.__agenthound_observation_created`)
	for _, lbl := range extraLabels {
		fmt.Fprintf(&sb, "\nSET n:%s", lbl)
	}
	sb.WriteString("\nRETURN count(*) AS written")
	return sb.String()
}

func (w *Writer) WriteEdges(ctx context.Context, edges []ingest.Edge, scanID string) (int, error) {
	return w.WriteObservationEdges(ctx, edges, scanID, nil)
}

func (w *Writer) WriteObservationEdges(
	ctx context.Context,
	edges []ingest.Edge,
	scanID string,
	completeDomains []string,
) (int, error) {
	if len(edges) == 0 {
		return 0, nil
	}

	w.detectAPOC(ctx)

	if w.hasAPOC {
		return w.writeEdgesAPOC(ctx, edges, scanID, completeDomains)
	}
	return w.writeEdgesFallback(ctx, edges, scanID, completeDomains)
}

func (w *Writer) writeEdgesAPOC(
	ctx context.Context,
	edges []ingest.Edge,
	scanID string,
	completeDomains []string,
) (int, error) {
	grouped := groupEdgesByEndpoints(edges)
	total := 0
	completePrefixes := observationDomainPrefixes(completeDomains)

	for key, kindEdges := range grouped {
		sourceMatch := matchClause("a", key.SourceKind, "source")
		targetMatch := matchClause("b", key.TargetKind, "target")

		cypher := fmt.Sprintf(`UNWIND $edges AS edge
%s
%s
CALL apoc.merge.relationship(a, $kind, {}, edge.create_properties, b, edge.properties) YIELD rel
WITH rel, edge, coalesce(rel.__agenthound_observation_created, false) AS observation_created
WITH rel, edge, observation_created,
     coalesce(rel.observation_tokens, []) AS old_tokens,
     coalesce(rel.observation_managed, false) AS old_managed,
     coalesce(rel.legacy_observation, NOT coalesce(rel.observation_managed, false)) AS old_legacy
WITH rel, edge, observation_created, old_tokens, old_managed, old_legacy,
     (size(edge.observation_tokens) > 0
      AND all(token IN edge.observation_tokens WHERE
          any(prefix IN edge.complete_domain_prefixes WHERE token STARTS WITH prefix))) AS incoming_complete
WITH rel, edge, observation_created, old_tokens, old_managed, old_legacy, incoming_complete,
     (NOT observation_created
      AND incoming_complete
      AND (NOT old_managed OR
          all(token IN old_tokens WHERE
              any(prefix IN edge.observation_domain_prefixes WHERE token STARTS WITH prefix)))) AS replace_properties
FOREACH (_ IN CASE WHEN NOT observation_created AND replace_properties THEN [1] ELSE [] END |
  SET rel = edge.properties)
FOREACH (_ IN CASE WHEN NOT observation_created AND NOT replace_properties THEN [1] ELSE [] END |
  SET rel += edge.properties)
SET rel.legacy_observation = CASE
      WHEN observation_created THEN size(edge.observation_tokens) = 0
      WHEN replace_properties THEN false
      WHEN size(edge.observation_tokens) > 0 AND NOT old_managed THEN true
      ELSE old_legacy
    END,
    rel.observation_managed = old_managed OR size(edge.observation_tokens) > 0,
    rel.observation_properties_complete = CASE
      WHEN observation_created THEN incoming_complete
      WHEN replace_properties THEN true
      ELSE false
    END,
    rel.observation_tokens = reduce(tokens = old_tokens, token IN edge.observation_tokens |
      CASE WHEN token IN tokens THEN tokens ELSE tokens + token END),
    rel.scan_id = $scan_id,
    rel.last_seen = datetime()
REMOVE rel.__agenthound_observation_created
RETURN count(*) AS written`, sourceMatch, targetMatch)

		for i := 0; i < len(kindEdges); i += w.batchSize {
			end := min(i+w.batchSize, len(kindEdges))
			batch := kindEdges[i:end]

			params := make([]map[string]any, len(batch))
			for j, e := range batch {
				props := factProperties(e.Properties)
				createProps := cloneProperties(props)
				createProps["__agenthound_observation_created"] = true
				tokens := observationTokens(e.ObservationDomains, scanID)
				createProps["observation_tokens"] = tokens
				createProps["observation_managed"] = len(tokens) > 0
				createProps["legacy_observation"] = len(tokens) == 0
				params[j] = map[string]any{
					"source":                      e.Source,
					"target":                      e.Target,
					"properties":                  props,
					"create_properties":           createProps,
					"observation_tokens":          tokens,
					"observation_domain_prefixes": observationDomainPrefixes(e.ObservationDomains),
					"complete_domain_prefixes":    completePrefixes,
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

func (w *Writer) writeEdgesFallback(
	ctx context.Context,
	edges []ingest.Edge,
	scanID string,
	completeDomains []string,
) (int, error) {
	grouped := groupEdgesByEndpoints(edges)
	total := 0
	completePrefixes := observationDomainPrefixes(completeDomains)

	for key, kindEdges := range grouped {
		cypher := edgeCypherForKinds(key.Kind, key.SourceKind, key.TargetKind)

		for i := 0; i < len(kindEdges); i += w.batchSize {
			end := min(i+w.batchSize, len(kindEdges))
			batch := kindEdges[i:end]

			params := make([]map[string]any, len(batch))
			for j, e := range batch {
				props := factProperties(e.Properties)
				params[j] = map[string]any{
					"source":                      e.Source,
					"target":                      e.Target,
					"properties":                  props,
					"observation_tokens":          observationTokens(e.ObservationDomains, scanID),
					"observation_domain_prefixes": observationDomainPrefixes(e.ObservationDomains),
					"complete_domain_prefixes":    completePrefixes,
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
ON CREATE SET r.__agenthound_observation_created = true
WITH r, edge,
     coalesce(r.__agenthound_observation_created, false) AS observation_created,
     coalesce(r.observation_tokens, []) AS old_tokens,
     coalesce(r.observation_managed, false) AS old_managed,
     coalesce(r.legacy_observation, NOT coalesce(r.observation_managed, false)) AS old_legacy
WITH r, edge, observation_created, old_tokens, old_managed, old_legacy,
     (size(edge.observation_tokens) > 0
      AND all(token IN edge.observation_tokens WHERE
          any(prefix IN edge.complete_domain_prefixes WHERE token STARTS WITH prefix))) AS incoming_complete
WITH r, edge, observation_created, old_tokens, old_managed, old_legacy, incoming_complete,
     (NOT observation_created
      AND incoming_complete
      AND (NOT old_managed OR
          all(token IN old_tokens WHERE
              any(prefix IN edge.observation_domain_prefixes WHERE token STARTS WITH prefix)))) AS replace_properties
FOREACH (_ IN CASE WHEN observation_created OR replace_properties THEN [1] ELSE [] END |
  SET r = edge.properties)
FOREACH (_ IN CASE WHEN NOT observation_created AND NOT replace_properties THEN [1] ELSE [] END |
  SET r += edge.properties)
SET r.scan_id = $scan_id,
    r.last_seen = datetime(),
    r.observation_tokens = reduce(tokens = old_tokens, token IN edge.observation_tokens |
      CASE WHEN token IN tokens THEN tokens ELSE tokens + token END),
    r.observation_managed = old_managed OR size(edge.observation_tokens) > 0,
    r.observation_properties_complete = CASE
      WHEN observation_created THEN incoming_complete
      WHEN replace_properties THEN true
      ELSE false
    END,
    r.legacy_observation = CASE
      WHEN observation_created THEN size(edge.observation_tokens) = 0
      WHEN replace_properties THEN false
      WHEN size(edge.observation_tokens) > 0 AND NOT old_managed THEN true
      ELSE old_legacy
    END
REMOVE r.__agenthound_observation_created
RETURN count(*) AS written`, matchClause("a", sourceKind, "source"), matchClause("b", targetKind, "target"), edgeKind)
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

func observationDomainPrefix(domain string) string {
	return domain + observationTokenSeparator
}

func observationToken(domain, scanID string) string {
	return observationDomainPrefix(domain) + scanID
}

func observationTokens(domains []string, scanID string) []string {
	if len(domains) == 0 {
		return []string{}
	}
	seen := make(map[string]bool, len(domains))
	tokens := make([]string, 0, len(domains))
	for _, domain := range domains {
		domain = strings.TrimSpace(domain)
		if domain == "" || seen[domain] {
			continue
		}
		seen[domain] = true
		tokens = append(tokens, observationToken(domain, scanID))
	}
	sort.Strings(tokens)
	return tokens
}

func observationDomainPrefixes(domains []string) []string {
	domains = normalizedDomains(domains)
	prefixes := make([]string, len(domains))
	for i, domain := range domains {
		prefixes[i] = observationDomainPrefix(domain)
	}
	return prefixes
}

func cloneProperties(props map[string]any) map[string]any {
	out := make(map[string]any, len(props))
	for key, value := range props {
		out[key] = value
	}
	return out
}

func factProperties(props map[string]any) map[string]any {
	out := cloneProperties(props)
	delete(out, "observation_tokens")
	delete(out, "observation_managed")
	delete(out, "observation_properties_complete")
	delete(out, "legacy_observation")
	delete(out, "__agenthound_observation_created")
	return out
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
