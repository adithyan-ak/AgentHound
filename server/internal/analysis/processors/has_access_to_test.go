package processors

import (
	"context"
	"strings"
	"testing"

	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

func TestHasAccessTo_Name(t *testing.T) {
	p := &HasAccessTo{}
	if p.Name() != "has_access_to" {
		t.Errorf("Name() = %q, want has_access_to", p.Name())
	}
}

func TestHasAccessTo_Dependencies(t *testing.T) {
	p := &HasAccessTo{}
	if deps := p.Dependencies(); deps != nil {
		t.Errorf("Dependencies() = %v, want nil", deps)
	}
}

func TestHasAccessTo_ProcessSuccess(t *testing.T) {
	mock := &graph.MockGraphDB{
		ExecuteWriteResult: 3,
	}

	p := &HasAccessTo{}
	stats, err := p.Process(context.Background(), mock, "scan-1")
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if stats.ProcessorName != "has_access_to" {
		t.Errorf("ProcessorName = %q", stats.ProcessorName)
	}
	// 3 Cypher queries x 3 results each = 9
	if stats.EdgesCreated != 9 {
		t.Errorf("EdgesCreated = %d, want 9", stats.EdgesCreated)
	}

	calls := mock.CallsTo("ExecuteWrite")
	if len(calls) != 3 {
		t.Errorf("ExecuteWrite called %d times, want 3", len(calls))
	}
	for _, c := range calls {
		params, _ := c.Args[1].(map[string]any)
		if params["scan_id"] != "scan-1" {
			t.Errorf("scan_id = %v, want scan-1", params["scan_id"])
		}
		cypher, _ := c.Args[0].(string)
		if !strings.Contains(cypher, "SET e.confidence =") ||
			!strings.Contains(cypher, "e.match_type =") ||
			!strings.Contains(cypher, "e.evidence_version = 1") ||
			!strings.Contains(cypher, "id(provides_tool)") ||
			!strings.Contains(cypher, "id(provides_resource)") {
			t.Errorf("inferred access metadata is not refreshed on MERGE:\n%s", cypher)
		}
	}
	descriptionQuery, _ := calls[2].Args[0].(string)
	if !strings.Contains(descriptionQuery, "size(token) >= 4") ||
		!strings.Contains(descriptionQuery, "NOT token IN matched") ||
		!strings.Contains(descriptionQuery, ")) >= 2") {
		t.Fatalf("description access must require two distinct meaningful resource-name tokens:\n%s", descriptionQuery)
	}
}

func TestHasAccessTo_ProcessPartialError(t *testing.T) {
	callCount := 0
	mock := &graph.MockGraphDB{
		ExecuteWriteFunc: func(_ context.Context, _ string, _ map[string]any) (int, error) {
			callCount++
			if callCount == 2 {
				return 0, context.Canceled
			}
			return 5, nil
		},
	}

	p := &HasAccessTo{}
	stats, err := p.Process(context.Background(), mock, "scan-1")
	if err == nil {
		t.Fatal("expected error on second query failure")
	}
	if stats.ProcessorName != "has_access_to" {
		t.Errorf("ProcessorName = %q", stats.ProcessorName)
	}
}

func TestHasAccessTo_ProcessZeroResults(t *testing.T) {
	mock := &graph.MockGraphDB{
		ExecuteWriteResult: 0,
	}

	p := &HasAccessTo{}
	stats, err := p.Process(context.Background(), mock, "scan-1")
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if stats.EdgesCreated != 0 {
		t.Errorf("EdgesCreated = %d, want 0", stats.EdgesCreated)
	}
}
