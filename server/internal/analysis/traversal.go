package analysis

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

type TraversalScope string

const (
	TraversalScopeTopology TraversalScope = "topology"
	TraversalScopeSecurity TraversalScope = "security"
)

// SecurityTraversalEdgeKinds is the explicit directed policy used by security
// path assertions. CAN_REACH and similarity-only composites are excluded:
// summary/heuristic shortcuts are not interchangeable with their evidence
// chains in minimum-weight calculations.
var SecurityTraversalEdgeKinds = []string{
	"TRUSTS_SERVER",
	"PROVIDES_TOOL",
	"PROVIDES_RESOURCE",
	"PROVIDES_PROMPT",
	"ADVERTISES_SKILL",
	"DELEGATES_TO",
	"AUTHENTICATES_WITH",
	"USES_CREDENTIAL",
	"RUNS_ON",
	"CONFIGURED_IN",
	"HAS_ENV_VAR",
	"LOADS_INSTRUCTIONS",
	"EXPOSES",
	"EXPOSES_CREDENTIAL",
	"PROVIDES_MODEL",
	"EXTRACTED_FROM",
	"INGESTS_UNTRUSTED",
	"HAS_ACCESS_TO",
	"CAN_EXECUTE",
	"CAN_EXFILTRATE_VIA",
	"CONFUSED_DEPUTY",
	"TAINTS",
	"IFC_VIOLATION",
	"POISONS_CONTEXT",
}

func ParseTraversalScope(value string) (TraversalScope, error) {
	switch TraversalScope(value) {
	case "", TraversalScopeSecurity:
		return TraversalScopeSecurity, nil
	case TraversalScopeTopology:
		return TraversalScopeTopology, nil
	default:
		return "", fmt.Errorf("scope must be one of: topology, security")
	}
}

type TraversalCost string

const (
	TraversalCostHops TraversalCost = "hops"
	TraversalCostRisk TraversalCost = "risk_weight"
)

type TraversalNode struct {
	ID         string         `json:"id"`
	Name       string         `json:"name"`
	Kinds      []string       `json:"kinds"`
	Properties map[string]any `json:"properties,omitempty"`
}

type TraversalEdge struct {
	Source     string   `json:"source"`
	Target     string   `json:"target"`
	Kind       string   `json:"kind"`
	RiskWeight *float64 `json:"risk_weight,omitempty"`
}

type TraversalPath struct {
	Nodes  []TraversalNode `json:"nodes"`
	Edges  []TraversalEdge `json:"edges"`
	Weight float64         `json:"weight"`
	Hops   int             `json:"hops"`
}

type TraversalMetadata struct {
	Scope              TraversalScope `json:"scope"`
	Direction          string         `json:"direction"`
	RelationshipKinds  []string       `json:"relationship_kinds"`
	MaxHops            int            `json:"max_hops"`
	Algorithm          string         `json:"algorithm"`
	Complete           bool           `json:"complete"`
	Truncated          bool           `json:"truncated"`
	ExpansionLimit     int            `json:"expansion_limit"`
	Expansions         int            `json:"expansions"`
	DefaultRiskWeight  float64        `json:"default_risk_weight,omitempty"`
	UsedDefaultWeights bool           `json:"used_default_weights"`
	IncompleteReason   string         `json:"incomplete_reason,omitempty"`
}

type TraversalResult struct {
	Paths    []TraversalPath   `json:"paths"`
	Metadata TraversalMetadata `json:"metadata"`
}

type TraversalSelector struct {
	Kind       string
	Property   string
	Value      *string
	InProperty string
	InValues   []string
}

var traversalProperties = map[string]bool{
	"objectid":   true,
	"name":       true,
	"uri_scheme": true,
}

// ResolveTraversalNodes resolves an internal, validated selector to concrete
// node IDs before path expansion. Dynamic labels/properties never come from an
// unchecked request.
func ResolveTraversalNodes(
	ctx context.Context,
	db graph.GraphDB,
	selector TraversalSelector,
) ([]TraversalNode, error) {
	if selector.Kind != "" && !ingest.AllowedNodeKinds[selector.Kind] {
		return nil, fmt.Errorf("invalid traversal node kind %q", selector.Kind)
	}
	if selector.Property != "" && !traversalProperties[selector.Property] {
		return nil, fmt.Errorf("invalid traversal property %q", selector.Property)
	}
	if selector.Value != nil && selector.Property == "" {
		return nil, fmt.Errorf("traversal value requires a match property")
	}
	if selector.InProperty != "" && !traversalProperties[selector.InProperty] {
		return nil, fmt.Errorf("invalid traversal property %q", selector.InProperty)
	}
	if len(selector.InValues) > 0 && selector.InProperty == "" {
		return nil, fmt.Errorf("traversal values require an IN property")
	}

	match := "MATCH (n)"
	if selector.Kind != "" {
		match = fmt.Sprintf("MATCH (n:%s)", selector.Kind)
	}
	conditions := make([]string, 0, 2)
	params := map[string]any{}
	if selector.Value != nil {
		conditions = append(conditions, fmt.Sprintf("n.%s = $value", selector.Property))
		params["value"] = *selector.Value
	}
	if len(selector.InValues) > 0 {
		conditions = append(conditions, fmt.Sprintf("n.%s IN $in_values", selector.InProperty))
		params["in_values"] = selector.InValues
	}
	where := ""
	if len(conditions) > 0 {
		where = " WHERE " + strings.Join(conditions, " AND ")
	}
	cypher := `/* traversal:resolve */ ` + match + where + `
 RETURN n.objectid AS id,
        coalesce(n.name, n.uri, n.path, n.hostname, n.objectid) AS name,
        labels(n) AS kinds,
        properties(n) AS properties
 ORDER BY id`

	rows, err := db.Query(ctx, cypher, params)
	if err != nil {
		return nil, fmt.Errorf("resolve traversal nodes: %w", err)
	}
	nodes := make([]TraversalNode, 0, len(rows))
	for _, row := range rows {
		node := traversalNodeFromRow(row)
		if node.ID != "" {
			nodes = append(nodes, node)
		}
	}
	return nodes, nil
}

// FindShortestDatabasePaths powers every execution surface for the critical
// pre-built query so the HTTP API and direct-DB CLI cannot drift.
func FindShortestDatabasePaths(ctx context.Context, db graph.GraphDB) (TraversalResult, error) {
	sources, err := ResolveTraversalNodes(
		ctx,
		db,
		TraversalSelector{Kind: "AgentInstance"},
	)
	if err != nil {
		return TraversalResult{}, fmt.Errorf("resolve database path sources: %w", err)
	}
	targets, err := ResolveTraversalNodes(
		ctx,
		db,
		TraversalSelector{
			Kind:       "MCPResource",
			InProperty: "uri_scheme",
			InValues:   []string{"postgres", "mysql", "mongodb", "redis"},
		},
	)
	if err != nil {
		return TraversalResult{}, fmt.Errorf("resolve database path targets: %w", err)
	}
	return FindBoundedTraversalPaths(
		ctx,
		db,
		sources,
		targets,
		TraversalOptions{
			Scope:   TraversalScopeSecurity,
			Cost:    TraversalCostHops,
			MaxHops: 10, Limit: 50, MaxExpansions: 100000,
		},
	)
}

func DatabasePathRows(result TraversalResult) []map[string]any {
	rows := make([]map[string]any, 0, len(result.Paths))
	for _, path := range result.Paths {
		if len(path.Nodes) < 2 {
			continue
		}
		source := path.Nodes[0]
		target := path.Nodes[len(path.Nodes)-1]
		nodeNames := make([]string, 0, len(path.Nodes))
		for _, node := range path.Nodes {
			nodeNames = append(nodeNames, node.Name)
		}
		edgeKinds := make([]string, 0, len(path.Edges))
		for _, edge := range path.Edges {
			edgeKinds = append(edgeKinds, edge.Kind)
		}
		rows = append(rows, map[string]any{
			"agent_name":   source.Name,
			"resource_uri": target.Properties["uri"],
			"sensitivity":  target.Properties["sensitivity"],
			"path_length":  path.Hops,
			"path_nodes":   nodeNames,
			"path_edges":   edgeKinds,
		})
	}
	return rows
}

type TraversalOptions struct {
	Scope         TraversalScope
	Cost          TraversalCost
	MaxHops       int
	Limit         int
	MaxExpansions int
	AllPaths      bool
}

type traversalState struct {
	source TraversalNode
	node   TraversalNode
	nodes  []TraversalNode
	edges  []TraversalEdge
	cost   float64
	key    string
}

type adjacency struct {
	traversalSource string
	traversalTarget string
	next            TraversalNode
	edge            TraversalEdge
}

const defaultTraversalRiskWeight = 0.5

// FindBoundedTraversalPaths performs one deployment-independent bounded path
// search. Minimum mode keeps the cheapest state per (source,node,hop), which
// yields the exact minimum non-negative cost under a hop bound. AllPaths mode
// enumerates simple paths with the same direction/policy and an expansion cap.
func FindBoundedTraversalPaths(
	ctx context.Context,
	db graph.GraphDB,
	sources, targets []TraversalNode,
	opts TraversalOptions,
) (TraversalResult, error) {
	opts = normalizeTraversalOptions(opts)
	metadata := TraversalMetadata{
		Scope:             opts.Scope,
		Direction:         "both",
		RelationshipKinds: []string{},
		MaxHops:           opts.MaxHops,
		Algorithm:         "bounded-min-weight",
		Complete:          true,
		ExpansionLimit:    opts.MaxExpansions,
	}
	if opts.Scope == TraversalScopeSecurity {
		metadata.Direction = "out"
		metadata.RelationshipKinds = append([]string(nil), SecurityTraversalEdgeKinds...)
	}
	if opts.Cost == TraversalCostRisk {
		metadata.DefaultRiskWeight = defaultTraversalRiskWeight
	}
	if opts.AllPaths {
		metadata.Algorithm = "bounded-enumeration"
	}

	if len(sources) == 0 || len(targets) == 0 {
		return TraversalResult{Paths: []TraversalPath{}, Metadata: metadata}, nil
	}

	targetIDs := make(map[string]bool, len(targets))
	for _, target := range targets {
		targetIDs[target.ID] = true
	}

	if opts.AllPaths {
		return enumerateBoundedPaths(ctx, db, sources, targetIDs, opts, metadata)
	}
	return minimumBoundedPaths(ctx, db, sources, targetIDs, opts, metadata)
}

func normalizeTraversalOptions(opts TraversalOptions) TraversalOptions {
	if opts.Scope != TraversalScopeSecurity {
		opts.Scope = TraversalScopeTopology
	}
	if opts.Cost != TraversalCostRisk {
		opts.Cost = TraversalCostHops
	}
	if opts.MaxHops < 1 {
		opts.MaxHops = 10
	}
	if opts.MaxHops > 20 {
		opts.MaxHops = 20
	}
	if opts.Limit < 1 {
		opts.Limit = 10
	}
	if opts.MaxExpansions < 1 {
		opts.MaxExpansions = 100000
	}
	return opts
}

func minimumBoundedPaths(
	ctx context.Context,
	db graph.GraphDB,
	sources []TraversalNode,
	targetIDs map[string]bool,
	opts TraversalOptions,
	metadata TraversalMetadata,
) (TraversalResult, error) {
	states := make(map[string]traversalState, len(sources))
	for _, source := range sources {
		state := traversalState{
			source: source,
			node:   source,
			nodes:  []TraversalNode{source},
			edges:  []TraversalEdge{},
			key:    source.ID,
		}
		states[stateMapKey(source.ID, source.ID)] = state
	}
	bestTargets := make(map[string]traversalState)

	for hop := 1; hop <= opts.MaxHops && len(states) > 0; hop++ {
		adj, err := loadAdjacency(ctx, db, stateNodeIDs(states), opts.Scope)
		if err != nil {
			return TraversalResult{}, err
		}
		nextStates := make(map[string]traversalState)
		for _, stateKey := range sortedStateKeys(states) {
			state := states[stateKey]
			for _, edge := range adj[state.node.ID] {
				metadata.Expansions++
				if metadata.Expansions > opts.MaxExpansions {
					metadata.Complete = false
					metadata.IncompleteReason = "expansion limit reached before minimum cost was proven"
					return TraversalResult{Paths: []TraversalPath{}, Metadata: metadata}, nil
				}
				stepCost, defaulted, err := traversalEdgeCost(edge.edge, opts.Cost)
				if err != nil {
					return TraversalResult{}, err
				}
				metadata.UsedDefaultWeights = metadata.UsedDefaultWeights || defaulted
				next := extendTraversalState(state, edge, stepCost)
				key := stateMapKey(next.source.ID, next.node.ID)
				if existing, ok := nextStates[key]; !ok || betterTraversalState(next, existing) {
					nextStates[key] = next
				}
				if targetIDs[next.node.ID] && next.node.ID != next.source.ID {
					targetKey := stateMapKey(next.source.ID, next.node.ID)
					if existing, ok := bestTargets[targetKey]; !ok || betterTraversalState(next, existing) {
						bestTargets[targetKey] = next
					}
				}
			}
		}
		states = nextStates
	}

	paths := statesToSortedPaths(bestTargets)
	if len(paths) > opts.Limit {
		paths = paths[:opts.Limit]
		metadata.Complete = false
		metadata.Truncated = true
		metadata.IncompleteReason = "result limit reached"
	}
	return TraversalResult{Paths: paths, Metadata: metadata}, nil
}

func enumerateBoundedPaths(
	ctx context.Context,
	db graph.GraphDB,
	sources []TraversalNode,
	targetIDs map[string]bool,
	opts TraversalOptions,
	metadata TraversalMetadata,
) (TraversalResult, error) {
	frontier := make([]traversalState, 0, len(sources))
	for _, source := range sources {
		frontier = append(frontier, traversalState{
			source: source,
			node:   source,
			nodes:  []TraversalNode{source},
			edges:  []TraversalEdge{},
			key:    source.ID,
		})
	}
	candidates := make([]traversalState, 0)

	for hop := 1; hop <= opts.MaxHops && len(frontier) > 0; hop++ {
		adj, err := loadAdjacency(ctx, db, frontierNodeIDs(frontier), opts.Scope)
		if err != nil {
			return TraversalResult{}, err
		}
		sort.Slice(frontier, func(i, j int) bool { return frontier[i].key < frontier[j].key })
		nextFrontier := make([]traversalState, 0)
		for _, state := range frontier {
			for _, edge := range adj[state.node.ID] {
				metadata.Expansions++
				if metadata.Expansions > opts.MaxExpansions {
					metadata.Complete = false
					metadata.Truncated = true
					metadata.IncompleteReason = "expansion limit reached"
					return TraversalResult{
						Paths:    sortedTraversalPaths(candidates, opts.Limit),
						Metadata: metadata,
					}, nil
				}
				if traversalPathContains(state.nodes, edge.next.ID) {
					continue
				}
				next := extendTraversalState(state, edge, 1)
				nextFrontier = append(nextFrontier, next)
				if targetIDs[next.node.ID] && next.node.ID != next.source.ID {
					candidates = append(candidates, next)
				}
			}
		}
		frontier = nextFrontier
	}

	paths := sortedTraversalPaths(candidates, opts.Limit)
	if len(candidates) > opts.Limit {
		metadata.Complete = false
		metadata.Truncated = true
		metadata.IncompleteReason = "result limit reached"
	}
	return TraversalResult{Paths: paths, Metadata: metadata}, nil
}

func loadAdjacency(
	ctx context.Context,
	db graph.GraphDB,
	nodeIDs []string,
	scope TraversalScope,
) (map[string][]adjacency, error) {
	out := make(map[string][]adjacency, len(nodeIDs))
	if len(nodeIDs) == 0 {
		return out, nil
	}

	const chunkSize = 1000
	for start := 0; start < len(nodeIDs); start += chunkSize {
		end := min(start+chunkSize, len(nodeIDs))
		match := "MATCH (current {objectid: current_id})-[r]-(next)"
		params := map[string]any{"ids": nodeIDs[start:end]}
		where := ""
		if scope == TraversalScopeSecurity {
			match = "MATCH (current {objectid: current_id})-[r]->(next)"
			where = " WHERE type(r) IN $relationship_kinds"
			params["relationship_kinds"] = SecurityTraversalEdgeKinds
		}
		cypher := `/* traversal:adjacency */
UNWIND $ids AS current_id
` + match + where + `
 RETURN current.objectid AS traversal_source,
        next.objectid AS traversal_target,
        next.objectid AS next_id,
        coalesce(next.name, next.uri, next.path, next.hostname, next.objectid) AS next_name,
        labels(next) AS next_kinds,
        properties(next) AS next_properties,
        startNode(r).objectid AS source,
        endNode(r).objectid AS target,
        type(r) AS kind,
        r.risk_weight AS risk_weight
 ORDER BY traversal_source, kind, source, target, traversal_target`
		rows, err := db.Query(ctx, cypher, params)
		if err != nil {
			return nil, fmt.Errorf("load traversal adjacency: %w", err)
		}
		for _, row := range rows {
			entry, ok := adjacencyFromRow(row)
			if !ok {
				continue
			}
			out[entry.traversalSource] = append(out[entry.traversalSource], entry)
		}
	}
	return out, nil
}

func adjacencyFromRow(row map[string]any) (adjacency, bool) {
	traversalSource, _ := row["traversal_source"].(string)
	traversalTarget, _ := row["traversal_target"].(string)
	source, _ := row["source"].(string)
	target, _ := row["target"].(string)
	kind, _ := row["kind"].(string)
	if traversalSource == "" || traversalTarget == "" || source == "" || target == "" || kind == "" {
		return adjacency{}, false
	}
	var riskWeight *float64
	if raw := row["risk_weight"]; raw != nil {
		weight, ok := numericFloat(raw)
		if !ok {
			invalid := math.NaN()
			riskWeight = &invalid
		} else {
			riskWeight = &weight
		}
	}
	next := traversalNodeFromRow(map[string]any{
		"id":         row["next_id"],
		"name":       row["next_name"],
		"kinds":      row["next_kinds"],
		"properties": row["next_properties"],
	})
	return adjacency{
		traversalSource: traversalSource,
		traversalTarget: traversalTarget,
		next:            next,
		edge: TraversalEdge{
			Source: source, Target: target, Kind: kind, RiskWeight: riskWeight,
		},
	}, next.ID != ""
}

func traversalNodeFromRow(row map[string]any) TraversalNode {
	id, _ := row["id"].(string)
	name, _ := row["name"].(string)
	if name == "" {
		name = id
	}
	properties, _ := row["properties"].(map[string]any)
	if properties == nil {
		properties = map[string]any{}
	}
	return TraversalNode{
		ID:         id,
		Name:       name,
		Kinds:      stringSlice(row["kinds"]),
		Properties: properties,
	}
}

func stringSlice(value any) []string {
	switch values := value.(type) {
	case []string:
		return append([]string(nil), values...)
	case []any:
		out := make([]string, 0, len(values))
		for _, value := range values {
			if text, ok := value.(string); ok {
				out = append(out, text)
			}
		}
		return out
	default:
		return []string{}
	}
}

func numericFloat(value any) (float64, bool) {
	switch number := value.(type) {
	case float64:
		return number, true
	case float32:
		return float64(number), true
	case int:
		return float64(number), true
	case int64:
		return float64(number), true
	case int32:
		return float64(number), true
	default:
		return 0, false
	}
}

func traversalEdgeCost(edge TraversalEdge, cost TraversalCost) (float64, bool, error) {
	if cost == TraversalCostHops {
		return 1, false, nil
	}
	if edge.RiskWeight == nil {
		return defaultTraversalRiskWeight, true, nil
	}
	weight := *edge.RiskWeight
	if math.IsNaN(weight) || math.IsInf(weight, 0) || weight < 0 {
		return 0, false, fmt.Errorf(
			"edge %s %s->%s has invalid risk_weight %v",
			edge.Kind, edge.Source, edge.Target, weight,
		)
	}
	return weight, false, nil
}

func extendTraversalState(state traversalState, edge adjacency, stepCost float64) traversalState {
	nodes := append(append([]TraversalNode(nil), state.nodes...), edge.next)
	edges := append(append([]TraversalEdge(nil), state.edges...), edge.edge)
	return traversalState{
		source: state.source,
		node:   edge.next,
		nodes:  nodes,
		edges:  edges,
		cost:   state.cost + stepCost,
		key:    state.key + "|" + state.node.ID + ">" + edge.next.ID + ":" + edge.edge.Kind,
	}
}

func betterTraversalState(left, right traversalState) bool {
	if left.cost != right.cost {
		return left.cost < right.cost
	}
	if len(left.edges) != len(right.edges) {
		return len(left.edges) < len(right.edges)
	}
	return left.key < right.key
}

func stateMapKey(sourceID, nodeID string) string {
	return sourceID + "\x00" + nodeID
}

func stateNodeIDs(states map[string]traversalState) []string {
	ids := make(map[string]bool, len(states))
	for _, state := range states {
		ids[state.node.ID] = true
	}
	return sortedIDs(ids)
}

func frontierNodeIDs(states []traversalState) []string {
	ids := make(map[string]bool, len(states))
	for _, state := range states {
		ids[state.node.ID] = true
	}
	return sortedIDs(ids)
}

func sortedIDs(ids map[string]bool) []string {
	out := make([]string, 0, len(ids))
	for id := range ids {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func sortedStateKeys(states map[string]traversalState) []string {
	keys := make([]string, 0, len(states))
	for key := range states {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func traversalPathContains(nodes []TraversalNode, id string) bool {
	for _, node := range nodes {
		if node.ID == id {
			return true
		}
	}
	return false
}

func statesToSortedPaths(states map[string]traversalState) []TraversalPath {
	values := make([]traversalState, 0, len(states))
	for _, state := range states {
		values = append(values, state)
	}
	return sortedTraversalPaths(values, len(values))
}

func sortedTraversalPaths(states []traversalState, limit int) []TraversalPath {
	sort.Slice(states, func(i, j int) bool {
		if states[i].cost != states[j].cost {
			return states[i].cost < states[j].cost
		}
		if len(states[i].edges) != len(states[j].edges) {
			return len(states[i].edges) < len(states[j].edges)
		}
		return states[i].key < states[j].key
	})
	if len(states) > limit {
		states = states[:limit]
	}
	paths := make([]TraversalPath, 0, len(states))
	for _, state := range states {
		paths = append(paths, TraversalPath{
			Nodes: state.nodes, Edges: state.edges,
			Weight: state.cost, Hops: len(state.edges),
		})
	}
	return paths
}
