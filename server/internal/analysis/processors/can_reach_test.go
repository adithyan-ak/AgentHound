package processors

import (
	"context"
	"errors"
	"strings"
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
	direct, _ := calls[0].Args[0].(string)
	if strings.Contains(direct, "WHERE NOT EXISTS((a)-[:CAN_REACH]->(r))") {
		t.Fatalf("direct CAN_REACH must refresh an existing inferred edge:\n%s", direct)
	}
	credential, _ := calls[1].Args[0].(string)
	if !strings.Contains(credential, "current.scan_id = $scan_id") {
		t.Fatalf("credential pass must preserve a direct path refreshed this scan:\n%s", credential)
	}
	if !strings.Contains(credential, "NOT EXISTS {") ||
		!strings.Contains(credential, "MATCH (a)-[current:CAN_REACH]->(r)") {
		t.Fatalf("credential pass must use Neo4j-4.4-compatible EXISTS subquery:\n%s", credential)
	}
	if strings.Contains(credential, "s1.auth_method IS NULL OR") ||
		!strings.Contains(credential, "s1.auth_assurance IN ['unauthenticated', 'weak']") {
		t.Fatalf("unknown auth must not satisfy credential delegation:\n%s", credential)
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
