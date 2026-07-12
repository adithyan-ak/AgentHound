package graph

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
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
	results := []int{0, 0, 7, 3, 5, 2}
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
	if len(calls) != 6 {
		t.Fatalf("ExecuteWrite calls = %d, want 6", len(calls))
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
	retireQuery, ok := calls[2].Args[0].(string)
	if !ok {
		t.Fatalf("retire query type = %T", calls[0].Args[0])
	}
	if !strings.Contains(retireQuery, "token IN $current_tokens") {
		t.Fatal("current observation tokens must survive owner retirement")
	}
	deleteQuery, ok := calls[3].Args[0].(string)
	if !ok {
		t.Fatalf("delete query type = %T", calls[1].Args[0])
	}
	if !strings.Contains(deleteQuery, "type(r) IN $raw_edge_kinds") {
		t.Fatal("relationship retirement must remain limited to managed raw edges")
	}
}

func TestReconcileDependencyEdgeRetiresWhenEitherDomainChanges(t *testing.T) {
	db := &MockGraphDB{}
	domainA := "a2a:target:sha256:a"
	if _, err := ReconcileObservations(
		context.Background(),
		db,
		"scan-current",
		[]string{domainA},
	); err != nil {
		t.Fatalf("ReconcileObservations: %v", err)
	}

	calls := db.CallsTo("ExecuteWrite")
	if len(calls) == 0 {
		t.Fatal("dependency reconciliation was not executed")
	}
	query, _ := calls[0].Args[0].(string)
	for _, fragment := range []string{
		"r.observation_semantics = $all_dependencies_semantics",
		"r.observation_dependency_tokens",
		"token IN $current_tokens",
		"DELETE r",
	} {
		if !strings.Contains(query, fragment) {
			t.Fatalf("dependency reconciliation missing %q:\n%s", fragment, query)
		}
	}
	params, _ := calls[0].Args[1].(map[string]any)
	if params["all_dependencies_semantics"] !=
		string(ingest.ObservationSemanticsAllDependencies) {
		t.Fatalf("dependency semantics parameter = %v", params["all_dependencies_semantics"])
	}
	prefixes, _ := params["domain_prefixes"].([]string)
	if !reflect.DeepEqual(prefixes, []string{domainA + "\x1f"}) {
		t.Fatalf("dependency retirement prefixes = %q", prefixes)
	}
	retireQuery, _ := calls[1].Args[0].(string)
	for _, fragment := range []string{
		"SET r.observation_dependency_tokens",
		"OR token IN $current_tokens",
	} {
		if !strings.Contains(retireQuery, fragment) {
			t.Fatalf("dependency token retirement missing %q:\n%s", fragment, retireQuery)
		}
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

func TestObservationCompletenessScopesToPublicManagedRawFacts(t *testing.T) {
	db := &MockGraphDB{QueryResult: []map[string]any{{
		"incomplete_property_nodes":         int64(5),
		"incomplete_property_relationships": int64(6),
	}}}
	completeness, err := GetObservationCompleteness(context.Background(), db)
	if err != nil {
		t.Fatalf("GetObservationCompleteness: %v", err)
	}
	if completeness.Complete() ||
		completeness.IncompletePropertyNodes != 5 ||
		completeness.IncompletePropertyRelationships != 6 {
		t.Fatalf("observation completeness = %+v", completeness)
	}
	calls := db.CallsTo("Query")
	if len(calls) != 1 {
		t.Fatalf("query calls = %d, want one", len(calls))
	}
	query, _ := calls[0].Args[0].(string)
	if !strings.Contains(query, "label IN $public_kinds") {
		t.Fatalf("observation completeness includes internal nodes:\n%s", query)
	}
	if !strings.Contains(query, "type(r) IN $raw_edge_kinds") ||
		!strings.Contains(query, "size(coalesce(n.observation_tokens, [])) > 0") ||
		!strings.Contains(query, "size(coalesce(r.observation_tokens, [])) > 0") {
		t.Fatalf("observation completeness is not scoped to managed raw facts:\n%s", query)
	}
	params, _ := calls[0].Args[1].(map[string]any)
	if publicKinds, _ := params["public_kinds"].([]string); !reflect.DeepEqual(publicKinds, ingest.PublicNodeLabels) {
		t.Fatalf("public kinds = %v, want %v", publicKinds, ingest.PublicNodeLabels)
	}
	rawKinds, _ := params["raw_edge_kinds"].([]string)
	if !reflect.DeepEqual(rawKinds, rawEdgeKinds()) {
		t.Fatalf("raw edge kinds = %v, want %v", rawKinds, rawEdgeKinds())
	}
}
