package processors

import (
	"context"
	"errors"
	"testing"

	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

func TestCrossProtocol_Name(t *testing.T) {
	p := &CrossProtocol{}
	if p.Name() != "cross_protocol" {
		t.Errorf("Name() = %q, want cross_protocol", p.Name())
	}
}

func TestCrossProtocol_Dependencies(t *testing.T) {
	p := &CrossProtocol{}
	deps := p.Dependencies()
	if len(deps) != 1 || deps[0] != "has_access_to" {
		t.Errorf("Dependencies() = %v, want [has_access_to]", deps)
	}
}

func TestCrossProtocol_ProcessSuccess(t *testing.T) {
	mock := &graph.MockGraphDB{ExecuteWriteResult: 3}

	p := &CrossProtocol{}
	stats, err := p.Process(context.Background(), mock, "scan-1")
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if stats.ProcessorName != "cross_protocol" {
		t.Errorf("ProcessorName = %q", stats.ProcessorName)
	}
	if stats.EdgesCreated != 3 {
		t.Errorf("EdgesCreated = %d, want 3", stats.EdgesCreated)
	}

	calls := mock.CallsTo("ExecuteWrite")
	if len(calls) != 1 {
		t.Fatalf("ExecuteWrite called %d times, want 1", len(calls))
	}
	params, _ := calls[0].Args[1].(map[string]any)
	if params["scan_id"] != "scan-1" {
		t.Errorf("scan_id = %v", params["scan_id"])
	}
}

func TestCrossProtocol_ProcessError(t *testing.T) {
	mock := &graph.MockGraphDB{ExecuteWriteError: errors.New("fail")}

	p := &CrossProtocol{}
	_, err := p.Process(context.Background(), mock, "scan-1")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCrossProtocol_ProcessZero(t *testing.T) {
	mock := &graph.MockGraphDB{ExecuteWriteResult: 0}

	p := &CrossProtocol{}
	stats, err := p.Process(context.Background(), mock, "scan-1")
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if stats.EdgesCreated != 0 {
		t.Errorf("EdgesCreated = %d, want 0", stats.EdgesCreated)
	}
}
