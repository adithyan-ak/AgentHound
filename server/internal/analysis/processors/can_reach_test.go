package processors

import (
	"context"
	"errors"
	"testing"

	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

func TestCanReach_Name(t *testing.T) {
	p := &CanReach{}
	if p.Name() != "can_reach" {
		t.Errorf("Name() = %q, want can_reach", p.Name())
	}
}

func TestCanReach_Dependencies(t *testing.T) {
	p := &CanReach{}
	deps := p.Dependencies()
	if len(deps) != 1 || deps[0] != "has_access_to" {
		t.Errorf("Dependencies() = %v, want [has_access_to]", deps)
	}
}

func TestCanReach_ProcessSuccess(t *testing.T) {
	mock := &graph.MockGraphDB{ExecuteWriteResult: 4}

	p := &CanReach{}
	stats, err := p.Process(context.Background(), mock, "scan-1")
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if stats.ProcessorName != "can_reach" {
		t.Errorf("ProcessorName = %q", stats.ProcessorName)
	}
	// 2 queries x 4 each = 8
	if stats.EdgesCreated != 8 {
		t.Errorf("EdgesCreated = %d, want 8", stats.EdgesCreated)
	}

	calls := mock.CallsTo("ExecuteWrite")
	if len(calls) != 2 {
		t.Errorf("ExecuteWrite called %d times, want 2 (direct + credential chain)", len(calls))
	}
}

func TestCanReach_ProcessFirstQueryError(t *testing.T) {
	mock := &graph.MockGraphDB{ExecuteWriteError: errors.New("query failed")}

	p := &CanReach{}
	_, err := p.Process(context.Background(), mock, "scan-1")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCanReach_ProcessSecondQueryError(t *testing.T) {
	callCount := 0
	mock := &graph.MockGraphDB{
		ExecuteWriteFunc: func(_ context.Context, _ string, _ map[string]any) (int, error) {
			callCount++
			if callCount == 2 {
				return 0, errors.New("credential chain query failed")
			}
			return 3, nil
		},
	}

	p := &CanReach{}
	_, err := p.Process(context.Background(), mock, "scan-1")
	if err == nil {
		t.Fatal("expected error on second query")
	}
}
