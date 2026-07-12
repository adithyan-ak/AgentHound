package model

import (
	"encoding/json"
	"testing"
)

func TestScanUsesCanonicalNestedCounts(t *testing.T) {
	beforeNodes, beforeEdges := int64(3), int64(2)
	afterNodes, afterEdges := int64(5), int64(4)
	scan := Scan{
		ID:                    "scan-1",
		NodeWriteRows:         2,
		EdgeWriteRows:         2,
		GraphTotalNodesBefore: &beforeNodes,
		GraphTotalEdgesBefore: &beforeEdges,
		GraphTotalNodesAfter:  &afterNodes,
		GraphTotalEdgesAfter:  &afterEdges,
		Metadata: map[string]any{
			"submitted": map[string]any{"nodes": float64(2), "edges": float64(2)},
		},
	}
	encoded, err := json.Marshal(scan)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(encoded, &body); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"submitted", "write_rows", "graph_totals"} {
		if _, ok := body[field]; !ok {
			t.Errorf("missing %q in %s", field, encoded)
		}
	}
	for _, removed := range []string{
		"node_count", "edge_count",
		"graph_total_nodes_before", "graph_total_edges_before",
		"graph_total_nodes_after", "graph_total_edges_after",
	} {
		if _, ok := body[removed]; ok {
			t.Errorf("removed field %q present in %s", removed, encoded)
		}
	}
}
