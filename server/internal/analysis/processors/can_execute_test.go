package processors

import (
	"context"
	"errors"
	"testing"

	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

func TestCanExecute_Name(t *testing.T) {
	p := &CanExecute{}
	if p.Name() != "can_execute" {
		t.Errorf("Name() = %q, want can_execute", p.Name())
	}
}

func TestCanExecute_Dependencies(t *testing.T) {
	p := &CanExecute{}
	if deps := p.Dependencies(); deps != nil {
		t.Errorf("Dependencies() = %v, want nil", deps)
	}
}

func TestCanExecute_ProcessSuccess(t *testing.T) {
	mock := &graph.MockGraphDB{ExecuteWriteResult: 5}

	p := &CanExecute{}
	stats, err := p.Process(context.Background(), mock, "scan-1")
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if stats.ProcessorName != "can_execute" {
		t.Errorf("ProcessorName = %q", stats.ProcessorName)
	}
	if stats.EdgesCreated != 5 {
		t.Errorf("EdgesCreated = %d, want 5", stats.EdgesCreated)
	}
	if stats.Duration <= 0 {
		t.Error("Duration should be positive")
	}

	calls := mock.CallsTo("ExecuteWrite")
	if len(calls) != 1 {
		t.Fatalf("ExecuteWrite called %d times, want 1", len(calls))
	}
	params, _ := calls[0].Args[1].(map[string]any)
	if params["scan_id"] != "scan-1" {
		t.Errorf("scan_id = %v, want scan-1", params["scan_id"])
	}
}

func TestCanExecute_ProcessError(t *testing.T) {
	mock := &graph.MockGraphDB{ExecuteWriteError: errors.New("neo4j down")}

	p := &CanExecute{}
	stats, err := p.Process(context.Background(), mock, "scan-1")
	if err == nil {
		t.Fatal("expected error")
	}
	if stats.ProcessorName != "can_execute" {
		t.Errorf("ProcessorName = %q", stats.ProcessorName)
	}
}

func TestCanExecute_ProcessZero(t *testing.T) {
	mock := &graph.MockGraphDB{ExecuteWriteResult: 0}

	p := &CanExecute{}
	stats, err := p.Process(context.Background(), mock, "scan-1")
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if stats.EdgesCreated != 0 {
		t.Errorf("EdgesCreated = %d, want 0", stats.EdgesCreated)
	}
}
