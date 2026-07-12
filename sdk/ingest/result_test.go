package ingest

import (
	"encoding/json"
	"testing"
)

func TestIngestResultUsesCanonicalNestedCounts(t *testing.T) {
	result := IngestResult{
		ScanID:    "scan-1",
		Submitted: FactCounts{Nodes: 2, Edges: 1},
		WriteRows: FactCounts{Nodes: 2, Edges: 1},
		Collection: CollectionReport{
			State:        OutcomeComplete,
			CoverageKeys: []string{"mcp:target:sha256:test"},
			Outcomes: []CollectionOutcome{{
				Collector: "mcp",
				State:     OutcomeComplete,
			}},
		},
		GraphTotals: FrozenGraphTotals{
			Before: &GraphTotals{NodeCounts: map[string]int64{}, EdgeCounts: map[string]int64{}},
			After:  &GraphTotals{NodeCounts: map[string]int64{"MCPServer": 1}, EdgeCounts: map[string]int64{}},
		},
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(encoded, &body); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"submitted", "write_rows", "graph_totals", "collection"} {
		if _, ok := body[field]; !ok {
			t.Errorf("missing %q in %s", field, encoded)
		}
	}
	for _, removed := range []string{
		"nodes_written", "edges_written", "nodes_submitted", "edges_submitted",
		"count_semantics", "graph_before", "graph_after",
	} {
		if _, ok := body[removed]; ok {
			t.Errorf("removed field %q present in %s", removed, encoded)
		}
	}
}
