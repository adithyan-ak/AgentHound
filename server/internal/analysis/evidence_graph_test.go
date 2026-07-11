package analysis

import "testing"

func TestEvidenceGraphLinearizesOnlyCompleteDirectedPath(t *testing.T) {
	path, err := parseAttackPath(evidenceRow(
		[]string{"a", "b", "c"},
		[]map[string]any{
			evidenceEdge("a", "b", "TRUSTS_SERVER", map[string]any{"risk_weight": 0.1}),
			evidenceEdge("b", "c", "PROVIDES_TOOL", map[string]any{"risk_weight": 0.2}),
		},
	))
	if err != nil {
		t.Fatal(err)
	}
	markExpectedEvidenceEndpoints(path, "a", "c")

	if path.Shape != EvidenceShapeLinear ||
		path.Continuity.State != "continuous" ||
		path.Direction != EvidenceDirectionForward ||
		path.Linearization == nil {
		t.Fatalf("linear evidence metadata = %+v", path)
	}
	if path.Completeness.State != EvidenceStateComplete {
		t.Fatalf("completeness = %+v", path.Completeness)
	}
	if path.Cost.State != EvidenceStateComplete ||
		path.Cost.Value == nil ||
		*path.Cost.Value < 0.299 ||
		*path.Cost.Value > 0.301 {
		t.Fatalf("cost = %+v", path.Cost)
	}
}

func TestEvidenceGraphMissingWeightHasNullableIncompleteCost(t *testing.T) {
	path, err := parseAttackPath(evidenceRow(
		[]string{"a", "b", "c"},
		[]map[string]any{
			evidenceEdge("a", "b", "TRUSTS_SERVER", map[string]any{"risk_weight": 0.1}),
			evidenceEdge("b", "c", "PROVIDES_TOOL", map[string]any{}),
		},
	))
	if err != nil {
		t.Fatal(err)
	}

	if path.Cost.State != EvidenceStateIncomplete ||
		path.Cost.Value != nil ||
		path.TotalRiskWeight != nil {
		t.Fatalf("missing weight became a numeric cost: cost=%+v legacy=%v", path.Cost, path.TotalRiskWeight)
	}
	if len(path.Cost.MissingWeightEdgeIndexes) != 1 ||
		path.Cost.MissingWeightEdgeIndexes[0] != 1 {
		t.Fatalf("missing indexes = %v", path.Cost.MissingWeightEdgeIndexes)
	}
	if len(path.Cost.Reasons) != 1 || path.Cost.Reasons[0] != "missing_risk_weight" {
		t.Fatalf("cost reasons = %v", path.Cost.Reasons)
	}
}

func TestEvidenceGraphPreservesBranchedAndDisconnectedShapes(t *testing.T) {
	t.Run("branched", func(t *testing.T) {
		path, err := parseAttackPath(evidenceRow(
			[]string{"a", "b", "c", "d"},
			[]map[string]any{
				evidenceEdge("a", "b", "TRUSTS_SERVER", map[string]any{"risk_weight": 0.1}),
				evidenceEdge("a", "c", "TRUSTS_SERVER", map[string]any{"risk_weight": 0.1}),
				evidenceEdge("a", "d", "TRUSTS_SERVER", map[string]any{"risk_weight": 0.1}),
			},
		))
		if err != nil {
			t.Fatal(err)
		}
		if path.Shape != EvidenceShapeBranched ||
			path.Continuity.State != "continuous" ||
			path.Linearization != nil {
			t.Fatalf("branched evidence was linearized: %+v", path)
		}
		if path.Cost.State != EvidenceStateNotApplicable ||
			path.TotalRiskWeight != nil {
			t.Fatalf("branched evidence received an attack-path cost: %+v", path.Cost)
		}
	})

	t.Run("disconnected", func(t *testing.T) {
		path, err := parseAttackPath(evidenceRow(
			[]string{"a", "b", "c", "d"},
			[]map[string]any{
				evidenceEdge("a", "b", "PROVIDES_TOOL", map[string]any{"risk_weight": 0.1}),
				evidenceEdge("c", "d", "PROVIDES_TOOL", map[string]any{"risk_weight": 0.1}),
			},
		))
		if err != nil {
			t.Fatal(err)
		}
		if path.Shape != EvidenceShapeDisconnected ||
			path.Continuity.State != "discontinuous" ||
			path.Continuity.ComponentCount != 2 ||
			path.Linearization != nil {
			t.Fatalf("disconnected evidence was linearized: %+v", path)
		}
		// Disconnected can still be a complete literal graph; completeness
		// describes supplied data, while continuity describes topology.
		if path.Completeness.State != EvidenceStateComplete {
			t.Fatalf("complete disconnected evidence marked incomplete: %+v", path.Completeness)
		}
	})
}

func TestEvidenceGraphMarksSyntheticJoinProvenance(t *testing.T) {
	path, err := parseAttackPath(evidenceRow(
		[]string{"credential-a", "credential-b"},
		[]map[string]any{
			evidenceEdge(
				"credential-a",
				"credential-b",
				"VALUE_HASH_MATCH",
				map[string]any{
					"is_synthetic":     true,
					"provenance_type":  "identity_correlation",
					"provenance_basis": "value_hash",
					"source_collector": "cross_service_credential_chain",
				},
			),
		},
	))
	if err != nil {
		t.Fatal(err)
	}
	edge := path.Edges[0]
	if !edge.Synthetic ||
		edge.Provenance == nil ||
		edge.Provenance.Type != "identity_correlation" ||
		edge.Provenance.Basis != "value_hash" {
		t.Fatalf("synthetic provenance = %+v", edge)
	}
}

func TestEvidenceGraphWithholdsMixedDirectionLinearization(t *testing.T) {
	path, err := parseAttackPath(evidenceRow(
		[]string{"a", "b", "c"},
		[]map[string]any{
			evidenceEdge("a", "b", "RUNS_ON", map[string]any{"risk_weight": 0.1}),
			evidenceEdge("c", "b", "RUNS_ON", map[string]any{"risk_weight": 0.1}),
		},
	))
	if err != nil {
		t.Fatal(err)
	}
	if path.Shape != EvidenceShapeLinear ||
		path.Direction != EvidenceDirectionMixed ||
		path.Linearization != nil {
		t.Fatalf("mixed-direction chain was presented as a path: %+v", path)
	}
	if path.Cost.State != EvidenceStateNotApplicable ||
		path.TotalRiskWeight != nil {
		t.Fatalf("mixed-direction evidence received an attack-path cost: %+v", path.Cost)
	}
}

func TestEvidenceGraphWithholdsReverseToFindingLinearization(t *testing.T) {
	path, err := parseAttackPath(evidenceRow(
		[]string{"a", "b", "c"},
		[]map[string]any{
			evidenceEdge("c", "b", "RUNS_ON", map[string]any{"risk_weight": 0.1}),
			evidenceEdge("b", "a", "RUNS_ON", map[string]any{"risk_weight": 0.1}),
		},
	))
	if err != nil {
		t.Fatal(err)
	}
	markExpectedEvidenceEndpoints(path, "a", "c")
	if path.Direction != EvidenceDirectionReverse ||
		path.Linearization != nil ||
		path.Cost.State != EvidenceStateNotApplicable ||
		path.TotalRiskWeight != nil {
		t.Fatalf("reverse evidence was presented as an attack path: %+v", path)
	}
}

func evidenceRow(nodeIDs []string, edges []map[string]any) map[string]any {
	nodes := make([]any, 0, len(nodeIDs))
	for _, id := range nodeIDs {
		nodes = append(nodes, map[string]any{
			"id":         id,
			"kinds":      []any{"TestNode"},
			"properties": map[string]any{"name": id},
		})
	}
	rawEdges := make([]any, 0, len(edges))
	for _, edge := range edges {
		rawEdges = append(rawEdges, edge)
	}
	return map[string]any{"nodes": nodes, "edges": rawEdges}
}

func evidenceEdge(
	source, target, kind string,
	properties map[string]any,
) map[string]any {
	return map[string]any{
		"source": source, "target": target, "kind": kind, "properties": properties,
	}
}
