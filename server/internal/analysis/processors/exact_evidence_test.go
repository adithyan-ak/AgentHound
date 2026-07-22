package processors

import (
	"context"
	"strings"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

type evidenceProcessor interface {
	Process(context.Context, graph.GraphDB, string) (graph.ProcessingStats, error)
}

func TestCompositeCypherProcessorsPersistExactWitnessReferences(t *testing.T) {
	processors := map[string]evidenceProcessor{
		"can_execute":                    &CanExecute{},
		"cross_protocol":                 &CrossProtocol{},
		"cross_service_credential_chain": &CrossServiceCredentialChain{},
		"has_access_to":                  &HasAccessTo{},
		"can_reach":                      &CanReach{},
		"can_exfiltrate":                 &CanExfiltrate{},
		"poisoned_description":           &PoisonedDescription{},
		"poisoned_instructions":          &PoisonedInstructions{},
		"confused_deputy":                &ConfusedDeputy{},
		"shadows":                        &Shadows{},
		"taints":                         &Taints{},
		"ifc_violation":                  &IfcViolation{},
	}
	for name, processor := range processors {
		t.Run(name, func(t *testing.T) {
			db := &graph.MockGraphDB{ExecuteWriteResult: 1}
			if _, err := processor.Process(context.Background(), db, "scan-1"); err != nil {
				t.Fatal(err)
			}
			calls := db.CallsTo("ExecuteWrite")
			if len(calls) == 0 {
				t.Fatal("processor emitted no write query")
			}
			for _, call := range calls {
				cypher, _ := call.Args[0].(string)
				if !strings.Contains(cypher, "MERGE") {
					continue
				}
				if !strings.Contains(cypher, "e.evidence_version = 1") ||
					!strings.Contains(cypher, "e.evidence_node_ids") ||
					!strings.Contains(cypher, "e.evidence_relationship_ids") {
					t.Fatalf("composite write lacks exact witness references:\n%s", cypher)
				}
			}
		})
	}
}

func TestCanImpersonatePersistsExactWitnessNodes(t *testing.T) {
	db := &graph.MockGraphDB{}
	// Keep the documents identical enough to cross the similarity threshold.
	db.QueryFunc = func(_ context.Context, cypher string, params map[string]any) ([]map[string]any, error) {
		if strings.Contains(cypher, "RETURN a.objectid AS id") {
			return []map[string]any{
				{"id": "agent-a", "provider": "one", "scope_kind": "network_context", "scope_id": "network-a", "collection_point_id": "point-a", "network_context_id": "network-a"},
				{"id": "agent-b", "provider": "two", "scope_kind": "network_context", "scope_id": "network-a", "collection_point_id": "point-a", "network_context_id": "network-a"},
				{"id": "agent-c", "provider": "three", "scope_kind": "network_context", "scope_id": "network-a", "collection_point_id": "point-a", "network_context_id": "network-a"},
			}, nil
		}
		if params["id"] == "agent-c" {
			return []map[string]any{{"description": "unrelated image generation"}}, nil
		}
		return []map[string]any{{"description": "shared orchestration capability"}}, nil
	}
	if _, err := (&CanImpersonate{}).Process(context.Background(), db, "scan-1"); err != nil {
		t.Fatal(err)
	}
	calls := db.CallsTo("WriteCompositeEdges")
	if len(calls) != 1 {
		t.Fatalf("WriteCompositeEdges calls = %d", len(calls))
	}
	edges, _ := calls[0].Args[0].([]ingest.Edge)
	if len(edges) != 2 {
		t.Fatalf("edges = %+v", edges)
	}
	for _, edge := range edges {
		if edge.Properties["evidence_version"] != 1 {
			t.Fatalf("edge evidence version = %v", edge.Properties["evidence_version"])
		}
		nodes, ok := edge.Properties["evidence_node_ids"].([]string)
		if !ok || len(nodes) != 2 {
			t.Fatalf("edge witness nodes = %#v", edge.Properties["evidence_node_ids"])
		}
	}
}
