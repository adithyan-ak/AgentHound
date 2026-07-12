package analysis

import (
	"context"
	"strings"
	"testing"

	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

// TestQueryFindingsScoped_ExcludesForeignCompositeEdges is the counterexample
// for the snapshot-scoping finding: a stale/foreign composite edge left in the
// graph by another scope's generation MUST NOT be re-stamped into this
// generation's snapshot.
//
// The mock returns the finding belonging to gen-1 only when the query is the
// generation-scoped one carrying gen=gen-1; the unscoped query (what the old
// snapshot used) returns a foreign composite edge as well. The scoped query
// must return only the current generation's finding.
func TestQueryFindingsScoped_ExcludesForeignCompositeEdges(t *testing.T) {
	thisGen := map[string]any{
		"source_id": "srcA", "source_name": "agent-a", "source_kind": "AgentInstance",
		"target_id": "tgtA", "target_name": "res-a", "target_kind": "MCPResource",
		"edge_kind": "CAN_REACH", "confidence": 0.9, "cross_protocol": false,
		"target_sensitivity": "high",
	}
	foreign := map[string]any{
		"source_id": "srcZ", "source_name": "agent-z", "source_kind": "AgentInstance",
		"target_id": "tgtZ", "target_name": "res-z", "target_kind": "MCPResource",
		"edge_kind": "CAN_REACH", "confidence": 0.5, "cross_protocol": false,
		"target_sensitivity": "high",
	}

	db := &graph.MockGraphDB{
		QueryFunc: func(_ context.Context, cypher string, params map[string]any) ([]map[string]any, error) {
			// The scoped query filters on the generations set with the bound
			// gen param; only then does the graph return this generation's row.
			if strings.Contains(cypher, "$gen IN coalesce(r.generations") && params["gen"] == "gen-1" {
				return []map[string]any{thisGen}, nil
			}
			// The unscoped query (old snapshot behaviour) would leak the
			// foreign composite edge too.
			return []map[string]any{thisGen, foreign}, nil
		},
	}

	scoped, err := QueryFindingsScoped(context.Background(), db, "", "gen-1")
	if err != nil {
		t.Fatalf("QueryFindingsScoped: %v", err)
	}
	if len(scoped) != 1 {
		t.Fatalf("scoped snapshot must contain only this generation's finding; got %d: %+v", len(scoped), scoped)
	}
	if scoped[0].SourceID != "srcA" || scoped[0].TargetID != "tgtA" {
		t.Errorf("scoped snapshot returned the wrong finding: %+v", scoped[0])
	}

	// Sanity: the unscoped read leaks the foreign edge, proving the scoping is
	// what excludes it (not the fixture).
	unscoped, err := QueryFindings(context.Background(), db, "")
	if err != nil {
		t.Fatalf("QueryFindings: %v", err)
	}
	if len(unscoped) != 2 {
		t.Fatalf("expected the unscoped read to leak the foreign edge; got %d", len(unscoped))
	}
}

// TestQueryFindingsScoped_EmptyGenerationFallsBack verifies that an empty
// generation id degrades to the unscoped query rather than returning nothing.
func TestQueryFindingsScoped_EmptyGenerationFallsBack(t *testing.T) {
	row := map[string]any{
		"source_id": "s", "target_id": "t", "edge_kind": "CAN_REACH",
		"source_kind": "AgentInstance", "target_kind": "MCPResource", "confidence": 0.7,
	}
	db := &graph.MockGraphDB{QueryResult: []map[string]any{row}}
	got, err := QueryFindingsScoped(context.Background(), db, "", "")
	if err != nil {
		t.Fatalf("QueryFindingsScoped: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("empty generation should fall back to unscoped; got %d", len(got))
	}
}
