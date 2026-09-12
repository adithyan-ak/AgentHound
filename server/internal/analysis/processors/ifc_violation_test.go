package processors

import (
	"context"
	"errors"
	"testing"

	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

func TestIfcViolation_Name(t *testing.T) {
	p := &IfcViolation{}
	if p.Name() != "ifc_violation" {
		t.Errorf("Name() = %q, want ifc_violation", p.Name())
	}
}

func TestIfcViolation_Dependencies(t *testing.T) {
	p := &IfcViolation{}
	deps := p.Dependencies()
	if len(deps) != 1 || deps[0] != "has_access_to" {
		t.Errorf("Dependencies() = %v, want [has_access_to]", deps)
	}
}

func TestIfcViolation_ProcessSuccess(t *testing.T) {
	mock := &graph.MockGraphDB{ExecuteWriteResult: 2}

	p := &IfcViolation{}
	stats, err := p.Process(context.Background(), mock, "scan-1")
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if stats.ProcessorName != "ifc_violation" {
		t.Errorf("ProcessorName = %q", stats.ProcessorName)
	}
	if stats.EdgesCreated != 2 {
		t.Errorf("EdgesCreated = %d, want 2", stats.EdgesCreated)
	}

	calls := mock.CallsTo("ExecuteWrite")
	if len(calls) != 1 {
		t.Fatalf("ExecuteWrite called %d times, want 1", len(calls))
	}
	params, _ := calls[0].Args[1].(map[string]any)
	if params["scan_id"] != "scan-1" {
		t.Errorf("scan_id = %v, want scan-1", params["scan_id"])
	}

	cypher, _ := calls[0].Args[0].(string)
	for _, want := range []string{
		"IFC_VIOLATION",
		"*1..3",
		"capability_surface",
		"credential_access",
		"sensitive.mcp_annotation_destructive_hint = true",
		"coalesce(sensitive.mcp_annotation_read_only_hint, false) = false",
		"source_collector = 'mcp'",
	} {
		if !contains(cypher, want) {
			t.Errorf("Cypher missing load-bearing predicate %q; query:\n%s", want, cypher)
		}
	}
}

func TestIfcViolation_ProcessError(t *testing.T) {
	mock := &graph.MockGraphDB{ExecuteWriteError: errors.New("db error")}

	p := &IfcViolation{}
	_, err := p.Process(context.Background(), mock, "scan-1")
	if err == nil {
		t.Fatal("expected error")
	}
}
