package graph

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

func TestReconcileObservationsSkipsUnknownCoverage(t *testing.T) {
	db := &MockGraphDB{}
	stats, err := ReconcileObservations(context.Background(), db, "scan-1", nil)
	if err != nil {
		t.Fatalf("ReconcileObservations: %v", err)
	}
	if stats != (ReconciliationStats{}) {
		t.Fatalf("stats = %+v, want zero", stats)
	}
	if len(db.CallsTo("ExecuteWrite")) != 0 {
		t.Fatal("unknown coverage must not retire graph observations")
	}
}

func TestReconcileObservationsRetiresOnlySelectedDomains(t *testing.T) {
	results := []int{7, 3, 5, 2}
	db := &MockGraphDB{
		ExecuteWriteFunc: func(_ context.Context, _ string, _ map[string]any) (int, error) {
			result := results[0]
			results = results[1:]
			return result, nil
		},
	}

	stats, err := ReconcileObservations(
		context.Background(),
		db,
		"scan-current",
		[]string{"mcp", "config", "mcp"},
	)
	if err != nil {
		t.Fatalf("ReconcileObservations: %v", err)
	}
	if stats.RelationshipOwnersRetired != 7 ||
		stats.RelationshipsDeleted != 3 ||
		stats.NodeOwnersRetired != 5 ||
		stats.NodesDeleted != 2 {
		t.Fatalf("unexpected stats: %+v", stats)
	}

	calls := db.CallsTo("ExecuteWrite")
	if len(calls) != 4 {
		t.Fatalf("ExecuteWrite calls = %d, want 4", len(calls))
	}
	params, ok := calls[0].Args[1].(map[string]any)
	if !ok {
		t.Fatalf("params type = %T", calls[0].Args[1])
	}
	prefixes, _ := params["domain_prefixes"].([]string)
	wantPrefixes := []string{"config\x1f", "mcp\x1f"}
	if !reflect.DeepEqual(prefixes, wantPrefixes) {
		t.Fatalf("prefixes = %q, want %q", prefixes, wantPrefixes)
	}
	tokens, _ := params["current_tokens"].([]string)
	wantTokens := []string{"config\x1fscan-current", "mcp\x1fscan-current"}
	if !reflect.DeepEqual(tokens, wantTokens) {
		t.Fatalf("tokens = %q, want %q", tokens, wantTokens)
	}
	retireQuery, ok := calls[0].Args[0].(string)
	if !ok {
		t.Fatalf("retire query type = %T", calls[0].Args[0])
	}
	if !strings.Contains(retireQuery, "token IN $current_tokens") {
		t.Fatal("current observation tokens must survive owner retirement")
	}
	deleteQuery, ok := calls[1].Args[0].(string)
	if !ok {
		t.Fatalf("delete query type = %T", calls[1].Args[0])
	}
	if !strings.Contains(deleteQuery, "legacy_observation") {
		t.Fatal("legacy observations must be protected from deletion")
	}
}

func TestReconcileObservationsDoesNotRetireSiblingTarget(t *testing.T) {
	targetA := "mcp:target:sha256:a"
	targetB := "mcp:target:sha256:b"
	db := &MockGraphDB{}

	if _, err := ReconcileObservations(
		context.Background(),
		db,
		"scan-b",
		[]string{targetB},
	); err != nil {
		t.Fatalf("ReconcileObservations: %v", err)
	}
	calls := db.CallsTo("ExecuteWrite")
	if len(calls) == 0 {
		t.Fatal("no reconciliation write recorded")
	}
	params, _ := calls[0].Args[1].(map[string]any)
	prefixes, _ := params["domain_prefixes"].([]string)
	if !reflect.DeepEqual(prefixes, []string{targetB + "\x1f"}) {
		t.Fatalf("retirement prefixes = %q", prefixes)
	}
	for _, prefix := range prefixes {
		if strings.HasPrefix(prefix, targetA) {
			t.Fatalf("target B scan would retire target A: %q", prefix)
		}
	}
}

func TestPruneUnownedObservationNodesRunsAfterCompositeCleanup(t *testing.T) {
	db := &MockGraphDB{ExecuteWriteResult: 4}
	deleted, err := PruneUnownedObservationNodes(context.Background(), db)
	if err != nil {
		t.Fatalf("PruneUnownedObservationNodes: %v", err)
	}
	if deleted != 4 {
		t.Fatalf("deleted = %d, want 4", deleted)
	}
	calls := db.CallsTo("ExecuteWrite")
	if len(calls) != 1 {
		t.Fatalf("unexpected prune query: %+v", calls)
	}
	pruneQuery, ok := calls[0].Args[0].(string)
	if !ok {
		t.Fatalf("prune query type = %T", calls[0].Args[0])
	}
	if !strings.Contains(pruneQuery, "NOT EXISTS { MATCH (n)--() }") {
		t.Fatalf("unexpected prune query: %s", pruneQuery)
	}
}

func TestObservationCompletenessIncludesLegacyAndUnscopedFacts(t *testing.T) {
	db := &MockGraphDB{QueryResult: []map[string]any{{
		"legacy_nodes":                      int64(1),
		"legacy_relationships":              int64(2),
		"unscoped_nodes":                    int64(3),
		"unscoped_relationships":            int64(4),
		"incomplete_property_nodes":         int64(5),
		"incomplete_property_relationships": int64(6),
		"identity_quarantined_nodes":        int64(7),
	}}}
	completeness, err := GetObservationCompleteness(context.Background(), db)
	if err != nil {
		t.Fatalf("GetObservationCompleteness: %v", err)
	}
	if completeness.Complete() ||
		completeness.LegacyNodes != 1 ||
		completeness.UnscopedRelationships != 4 ||
		completeness.IncompletePropertyRelationships != 6 ||
		completeness.IdentityQuarantinedNodes != 7 {
		t.Fatalf("observation completeness = %+v", completeness)
	}
	calls := db.CallsTo("Query")
	if len(calls) != 1 {
		t.Fatalf("query calls = %d, want one", len(calls))
	}
	params, _ := calls[0].Args[1].(map[string]any)
	prefixes, _ := params["unscoped_prefixes"].([]string)
	if want := []string{"mcp\x1f", "a2a\x1f", "config\x1f"}; !reflect.DeepEqual(prefixes, want) {
		t.Fatalf("unscoped prefixes = %q, want %q", prefixes, want)
	}
}
