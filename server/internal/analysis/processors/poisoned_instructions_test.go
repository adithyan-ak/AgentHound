package processors

import (
	"context"
	"errors"
	"testing"

	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

func TestPoisonedInstructions_Name(t *testing.T) {
	p := &PoisonedInstructions{}
	if p.Name() != "poisoned_instructions" {
		t.Errorf("Name() = %q, want poisoned_instructions", p.Name())
	}
}

func TestPoisonedInstructions_Dependencies(t *testing.T) {
	p := &PoisonedInstructions{}
	if deps := p.Dependencies(); deps != nil {
		t.Errorf("Dependencies() = %v, want nil", deps)
	}
}

func TestPoisonedInstructions_ProcessSuccess(t *testing.T) {
	mock := &graph.MockGraphDB{ExecuteWriteResult: 1}

	p := &PoisonedInstructions{}
	stats, err := p.Process(context.Background(), mock, "scan-1")
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if stats.ProcessorName != "poisoned_instructions" {
		t.Errorf("ProcessorName = %q", stats.ProcessorName)
	}
	if stats.EdgesCreated != 1 {
		t.Errorf("EdgesCreated = %d, want 1", stats.EdgesCreated)
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

func TestPoisonedInstructions_ProcessError(t *testing.T) {
	mock := &graph.MockGraphDB{ExecuteWriteError: errors.New("fail")}

	p := &PoisonedInstructions{}
	_, err := p.Process(context.Background(), mock, "scan-1")
	if err == nil {
		t.Fatal("expected error")
	}
}
