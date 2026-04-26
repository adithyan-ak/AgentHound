package processors

import (
	"context"
	"errors"
	"testing"

	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

func TestPoisonedDescription_Name(t *testing.T) {
	p := &PoisonedDescription{}
	if p.Name() != "poisoned_description" {
		t.Errorf("Name() = %q, want poisoned_description", p.Name())
	}
}

func TestPoisonedDescription_Dependencies(t *testing.T) {
	p := &PoisonedDescription{}
	if deps := p.Dependencies(); deps != nil {
		t.Errorf("Dependencies() = %v, want nil", deps)
	}
}

func TestPoisonedDescription_ProcessSuccess(t *testing.T) {
	mock := &graph.MockGraphDB{ExecuteWriteResult: 3}

	p := &PoisonedDescription{}
	stats, err := p.Process(context.Background(), mock, "scan-1")
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if stats.ProcessorName != "poisoned_description" {
		t.Errorf("ProcessorName = %q", stats.ProcessorName)
	}
	if stats.EdgesCreated != 3 {
		t.Errorf("EdgesCreated = %d, want 3", stats.EdgesCreated)
	}
}

func TestPoisonedDescription_ProcessError(t *testing.T) {
	mock := &graph.MockGraphDB{ExecuteWriteError: errors.New("fail")}

	p := &PoisonedDescription{}
	_, err := p.Process(context.Background(), mock, "scan-1")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestPoisonedDescription_ProcessZero(t *testing.T) {
	mock := &graph.MockGraphDB{ExecuteWriteResult: 0}

	p := &PoisonedDescription{}
	stats, err := p.Process(context.Background(), mock, "scan-1")
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if stats.EdgesCreated != 0 {
		t.Errorf("EdgesCreated = %d, want 0", stats.EdgesCreated)
	}
}
