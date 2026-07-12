package analysis

import (
	"context"
	"strings"
	"testing"

	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

func TestBuildBoundedPathQuery_DirectedAndBounded(t *testing.T) {
	q := buildBoundedPathQuery(DefaultTraversalPolicy())
	if !strings.Contains(q, "-[rels*1..8]->") {
		t.Errorf("default query must be forward-directed and hop-bounded at 8; got:\n%s", q)
	}
	if strings.Contains(q, "shortestPath") {
		t.Errorf("bounded traversal must not use shortestPath; got:\n%s", q)
	}
	if strings.Contains(q, "apoc") {
		t.Errorf("bounded traversal must not depend on APOC; got:\n%s", q)
	}
	if !strings.Contains(q, "NOT coalesce(r.is_composite, false)") {
		t.Errorf("default query must exclude composite edges; got:\n%s", q)
	}
}

func TestBuildBoundedPathQuery_HopBoundHonored(t *testing.T) {
	q := buildBoundedPathQuery(TraversalPolicy{MaxHops: 3, Direction: DirectionForward})
	if !strings.Contains(q, "-[rels*1..3]->") {
		t.Errorf("hop bound 3 not reflected; got:\n%s", q)
	}
}

func TestBuildBoundedPathQuery_AnyDirection(t *testing.T) {
	q := buildBoundedPathQuery(TraversalPolicy{MaxHops: 2, Direction: DirectionAny})
	if !strings.Contains(q, "-[rels*1..2]-(tgt") {
		t.Errorf("DirectionAny must produce an undirected pattern; got:\n%s", q)
	}
	if strings.Contains(q, "]->(tgt") {
		t.Errorf("DirectionAny must not be directed; got:\n%s", q)
	}
}

func candidateRow(edges ...map[string]any) map[string]any {
	rawEdges := make([]any, len(edges))
	for i, e := range edges {
		rawEdges[i] = e
	}
	return map[string]any{
		"nodes": []any{
			map[string]any{"id": "a", "kinds": []any{"AgentInstance"}, "properties": map[string]any{}},
			map[string]any{"id": "b", "kinds": []any{"MCPResource"}, "properties": map[string]any{}},
		},
		"edges": rawEdges,
	}
}

func TestBoundedMinWeightPath_PicksMinimumWeight(t *testing.T) {
	mock := &graph.MockGraphDB{
		QueryResult: []map[string]any{
			candidateRow(map[string]any{"source": "a", "target": "b", "kind": "X", "properties": map[string]any{"risk_weight": 0.9}}),
			candidateRow(map[string]any{"source": "a", "target": "b", "kind": "Y", "properties": map[string]any{"risk_weight": 0.2}}),
		},
	}
	path, err := BoundedMinWeightPath(context.Background(), mock, "a", "b", DefaultTraversalPolicy())
	if err != nil {
		t.Fatalf("BoundedMinWeightPath() error = %v", err)
	}
	if path == nil || path.TotalRiskWeight == nil {
		t.Fatal("expected a fully-weighted path")
	}
	if *path.TotalRiskWeight > 0.2001 {
		t.Errorf("expected minimum weight 0.2, got %f", *path.TotalRiskWeight)
	}
}

func TestBoundedMinWeightPath_PrefersFullyWeightedOverCheaperUnknown(t *testing.T) {
	mock := &graph.MockGraphDB{
		QueryResult: []map[string]any{
			// Cheaper on present-sum, but has a missing weight (unknown cost).
			candidateRow(map[string]any{"source": "a", "target": "b", "kind": "Y", "properties": map[string]any{}}),
			// Fully weighted, higher total.
			candidateRow(map[string]any{"source": "a", "target": "b", "kind": "X", "properties": map[string]any{"risk_weight": 0.5}}),
		},
	}
	path, err := BoundedMinWeightPath(context.Background(), mock, "a", "b", DefaultTraversalPolicy())
	if err != nil {
		t.Fatalf("BoundedMinWeightPath() error = %v", err)
	}
	if path == nil || path.TotalRiskWeight == nil {
		t.Fatal("expected the fully-weighted path to win, not the unknown-cost one")
	}
	if *path.TotalRiskWeight < 0.4999 || *path.TotalRiskWeight > 0.5001 {
		t.Errorf("expected total 0.5 from fully-weighted path, got %f", *path.TotalRiskWeight)
	}
}

func TestBoundedMinWeightPath_NoRows(t *testing.T) {
	mock := &graph.MockGraphDB{QueryResult: []map[string]any{}}
	path, err := BoundedMinWeightPath(context.Background(), mock, "a", "b", DefaultTraversalPolicy())
	if err != nil {
		t.Fatalf("BoundedMinWeightPath() error = %v", err)
	}
	if path != nil {
		t.Errorf("expected nil path for no rows, got %+v", path)
	}
}
