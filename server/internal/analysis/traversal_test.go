package analysis

import (
	"context"
	"strings"
	"testing"

	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

func TestParseTraversalScopeRequiresExplicitLegacyTopology(t *testing.T) {
	scope, err := ParseTraversalScope("")
	if err != nil {
		t.Fatal(err)
	}
	if scope != TraversalScopeSecurity {
		t.Fatalf("blank scope = %q, want security", scope)
	}
	scope, err = ParseTraversalScope("topology")
	if err != nil {
		t.Fatal(err)
	}
	if scope != TraversalScopeTopology {
		t.Fatalf("explicit topology scope = %q", scope)
	}
}

type traversalFixtureEdge struct {
	source string
	target string
	kind   string
	weight *float64
}

func fixtureWeight(value float64) *float64 {
	return &value
}

func traversalFixtureDB(t *testing.T, edges []traversalFixtureEdge) *graph.MockGraphDB {
	t.Helper()
	return &graph.MockGraphDB{
		QueryFunc: func(_ context.Context, cypher string, params map[string]any) ([]map[string]any, error) {
			if !strings.Contains(cypher, "traversal:adjacency") {
				t.Fatalf("unexpected query: %s", cypher)
			}
			ids, _ := params["ids"].([]string)
			directed := params["relationship_kinds"] != nil
			rows := make([]map[string]any, 0)
			for _, current := range ids {
				for _, edge := range edges {
					next := ""
					switch {
					case edge.source == current:
						next = edge.target
					case !directed && edge.target == current:
						next = edge.source
					default:
						continue
					}
					var weight any
					if edge.weight != nil {
						weight = *edge.weight
					}
					rows = append(rows, map[string]any{
						"traversal_source": current,
						"traversal_target": next,
						"next_id":          next,
						"next_name":        next,
						"next_kinds":       []any{"MCPResource"},
						"next_properties":  map[string]any{"objectid": next, "name": next},
						"source":           edge.source,
						"target":           edge.target,
						"kind":             edge.kind,
						"risk_weight":      weight,
					})
				}
			}
			return rows, nil
		},
	}
}

func traversalNode(id string) TraversalNode {
	return TraversalNode{
		ID: id, Name: id, Kinds: []string{"AgentInstance"},
		Properties: map[string]any{"objectid": id, "name": id},
	}
}

func TestSecurityTraversalPolicyExcludesSummaryAndSimilarityEdges(t *testing.T) {
	kinds := make(map[string]bool, len(SecurityTraversalEdgeKinds))
	for _, kind := range SecurityTraversalEdgeKinds {
		kinds[kind] = true
	}
	for _, excluded := range []string{
		"CAN_REACH",
		"SAME_AUTH_DOMAIN",
		"SHADOWS",
		"CAN_IMPERSONATE",
	} {
		if kinds[excluded] {
			t.Errorf("security traversal policy must not compose %s", excluded)
		}
	}
}

func TestDirectedSecurityRejectsBackwardTopologyPath(t *testing.T) {
	db := traversalFixtureDB(t, []traversalFixtureEdge{
		{source: "A", target: "S", kind: "TRUSTS_SERVER", weight: fixtureWeight(0.1)},
		{source: "B", target: "S", kind: "TRUSTS_SERVER", weight: fixtureWeight(0.1)},
		{source: "B", target: "DB", kind: "HAS_ACCESS_TO", weight: fixtureWeight(0.1)},
	})
	sources := []TraversalNode{traversalNode("A")}
	targets := []TraversalNode{traversalNode("DB")}

	security, err := FindBoundedTraversalPaths(context.Background(), db, sources, targets, TraversalOptions{
		Scope: TraversalScopeSecurity, Cost: TraversalCostHops, MaxHops: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(security.Paths) != 0 {
		t.Fatalf("security traversal found backward path: %+v", security.Paths)
	}
	if security.Metadata.Direction != "out" {
		t.Fatalf("security direction = %q, want out", security.Metadata.Direction)
	}

	topology, err := FindBoundedTraversalPaths(context.Background(), db, sources, targets, TraversalOptions{
		Scope: TraversalScopeTopology, Cost: TraversalCostHops, MaxHops: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(topology.Paths) != 1 || topology.Paths[0].Hops != 3 {
		t.Fatalf("legacy topology path = %+v, want one three-hop path", topology.Paths)
	}
	if topology.Metadata.Direction != "both" {
		t.Fatalf("topology direction = %q, want both", topology.Metadata.Direction)
	}
}

func TestBoundedMinimumWeightChoosesLongerCheaperPath(t *testing.T) {
	db := traversalFixtureDB(t, []traversalFixtureEdge{
		{source: "A", target: "T", kind: "HAS_ACCESS_TO", weight: fixtureWeight(0.9)},
		{source: "A", target: "B", kind: "PROVIDES_TOOL", weight: fixtureWeight(0.1)},
		{source: "B", target: "T", kind: "HAS_ACCESS_TO", weight: fixtureWeight(0.1)},
	})

	result, err := FindBoundedTraversalPaths(
		context.Background(),
		db,
		[]TraversalNode{traversalNode("A")},
		[]TraversalNode{traversalNode("T")},
		TraversalOptions{
			Scope: TraversalScopeSecurity, Cost: TraversalCostRisk,
			MaxHops: 2, Limit: 1,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Paths) != 1 {
		t.Fatalf("paths = %d, want 1", len(result.Paths))
	}
	if result.Paths[0].Weight != 0.2 || result.Paths[0].Hops != 2 {
		t.Fatalf("path = %+v, want two-hop weight 0.2", result.Paths[0])
	}
}

func TestBoundedMinimumWeightHonorsHopLimit(t *testing.T) {
	db := traversalFixtureDB(t, []traversalFixtureEdge{
		{source: "A", target: "T", kind: "HAS_ACCESS_TO", weight: fixtureWeight(0.9)},
		{source: "A", target: "B", kind: "PROVIDES_TOOL", weight: fixtureWeight(0.1)},
		{source: "B", target: "T", kind: "HAS_ACCESS_TO", weight: fixtureWeight(0.1)},
	})

	result, err := FindBoundedTraversalPaths(
		context.Background(),
		db,
		[]TraversalNode{traversalNode("A")},
		[]TraversalNode{traversalNode("T")},
		TraversalOptions{
			Scope: TraversalScopeSecurity, Cost: TraversalCostRisk,
			MaxHops: 1, Limit: 1,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Paths) != 1 || result.Paths[0].Weight != 0.9 {
		t.Fatalf("bounded path = %+v, want direct weight 0.9", result.Paths)
	}
}

func TestBoundedMinimumWeightDisclosesCompatibilityDefault(t *testing.T) {
	db := traversalFixtureDB(t, []traversalFixtureEdge{{
		source: "A", target: "T", kind: "HAS_ACCESS_TO",
	}})
	result, err := FindBoundedTraversalPaths(
		context.Background(),
		db,
		[]TraversalNode{traversalNode("A")},
		[]TraversalNode{traversalNode("T")},
		TraversalOptions{
			Scope: TraversalScopeSecurity, Cost: TraversalCostRisk, MaxHops: 1,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Paths) != 1 || result.Paths[0].Weight != defaultTraversalRiskWeight {
		t.Fatalf("defaulted path = %+v", result.Paths)
	}
	if !result.Metadata.UsedDefaultWeights ||
		result.Metadata.DefaultRiskWeight != defaultTraversalRiskWeight {
		t.Fatalf("default metadata = %+v", result.Metadata)
	}
}
