package processors

import (
	"context"
	"errors"
	"testing"

	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

func TestCanExfiltrate_Name(t *testing.T) {
	p := &CanExfiltrate{}
	if p.Name() != "can_exfiltrate" {
		t.Errorf("Name() = %q, want can_exfiltrate", p.Name())
	}
}

func TestCanExfiltrate_Dependencies(t *testing.T) {
	p := &CanExfiltrate{}
	deps := p.Dependencies()
	if len(deps) != 1 || deps[0] != "can_reach" {
		t.Errorf("Dependencies() = %v, want [can_reach]", deps)
	}
}

func TestCanExfiltrate_ProcessSuccess(t *testing.T) {
	mock := &graph.MockGraphDB{ExecuteWriteResult: 2}

	p := &CanExfiltrate{}
	stats, err := p.Process(context.Background(), mock, "scan-1")
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if stats.ProcessorName != "can_exfiltrate" {
		t.Errorf("ProcessorName = %q", stats.ProcessorName)
	}
	if stats.EdgesCreated != 2 {
		t.Errorf("EdgesCreated = %d, want 2", stats.EdgesCreated)
	}

	calls := mock.CallsTo("ExecuteWrite")
	if len(calls) != 1 {
		t.Fatalf("ExecuteWrite called %d times, want 1", len(calls))
	}
}

func TestCanExfiltrate_ProcessError(t *testing.T) {
	mock := &graph.MockGraphDB{ExecuteWriteError: errors.New("write failed")}

	p := &CanExfiltrate{}
	_, err := p.Process(context.Background(), mock, "scan-1")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCanExfiltrate_ProcessZero(t *testing.T) {
	mock := &graph.MockGraphDB{ExecuteWriteResult: 0}

	p := &CanExfiltrate{}
	stats, err := p.Process(context.Background(), mock, "scan-1")
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if stats.EdgesCreated != 0 {
		t.Errorf("EdgesCreated = %d, want 0", stats.EdgesCreated)
	}
}
