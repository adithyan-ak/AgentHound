package processors

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

func TestCanImpersonate_Name(t *testing.T) {
	p := &CanImpersonate{}
	if p.Name() != "can_impersonate" {
		t.Errorf("Name() = %q, want can_impersonate", p.Name())
	}
}

func TestCanImpersonate_Dependencies(t *testing.T) {
	p := &CanImpersonate{}
	if deps := p.Dependencies(); deps != nil {
		t.Errorf("Dependencies() = %v, want nil", deps)
	}
}

func TestCanImpersonate_ProcessNoAgents(t *testing.T) {
	mock := &graph.MockGraphDB{QueryResult: nil}

	p := &CanImpersonate{}
	stats, err := p.Process(context.Background(), mock, "scan-1")
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if stats.EdgesCreated != 0 {
		t.Errorf("EdgesCreated = %d, want 0", stats.EdgesCreated)
	}
}

func TestCanImpersonate_ProcessOneAgent(t *testing.T) {
	mock := &graph.MockGraphDB{
		QueryResult: []map[string]any{
			{"id": "agent-1", "name": "Agent A", "provider": "acme"},
		},
	}

	p := &CanImpersonate{}
	stats, err := p.Process(context.Background(), mock, "scan-1")
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if stats.EdgesCreated != 0 {
		t.Errorf("EdgesCreated = %d, want 0 (need at least 2 agents)", stats.EdgesCreated)
	}
}

func TestCanImpersonate_ProcessSimilarAgents(t *testing.T) {
	// For TF-IDF with N=2 docs, identical terms yield IDF=log(2/2)=0 (zero vectors).
	// Use highly overlapping but not identical descriptions so shared terms
	// get IDF=0 but each doc has a unique term with IDF=log(2)>0, producing
	// high cosine similarity.
	// Actually, to get similarity >= 0.8 we need many shared unique terms.
	// Easiest: 3+ documents where terms appear in 1 or 2 of them.
	mock := &graph.MockGraphDB{
		QueryFunc: func(_ context.Context, cypher string, params map[string]any) ([]map[string]any, error) {
			if strings.Contains(cypher, "A2AAgent)") && !strings.Contains(cypher, "ADVERTISES_SKILL") {
				return []map[string]any{
					{"id": "agent-1", "name": "Agent A", "provider": ""},
					{"id": "agent-2", "name": "Agent B", "provider": ""},
					{"id": "agent-3", "name": "Agent C", "provider": ""},
				}, nil
			}
			if params != nil {
				switch params["id"] {
				case "agent-1":
					return []map[string]any{
						{"description": "database query search records analysis retrieval indexing"},
					}, nil
				case "agent-2":
					return []map[string]any{
						{"description": "database query search records analysis retrieval indexing"},
					}, nil
				case "agent-3":
					return []map[string]any{
						{"description": "image processing computer vision neural network training"},
					}, nil
				}
			}
			return nil, nil
		},
		WriteEdgesResult: 2,
	}

	p := &CanImpersonate{}
	stats, err := p.Process(context.Background(), mock, "scan-1")
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	// Agents 1 and 2 have identical descriptions (high similarity), agent 3 is different.
	// Should produce bidirectional CAN_IMPERSONATE between agent-1 and agent-2.
	if stats.EdgesCreated != 2 {
		t.Errorf("EdgesCreated = %d, want 2", stats.EdgesCreated)
	}

	calls := mock.CallsTo("WriteEdges")
	if len(calls) != 1 {
		t.Fatalf("WriteEdges called %d times, want 1", len(calls))
	}
	edges, _ := calls[0].Args[0].([]ingest.Edge)
	if len(edges) != 2 {
		t.Fatalf("wrote %d edges, want 2", len(edges))
	}
	if edges[0].Kind != "CAN_IMPERSONATE" {
		t.Errorf("edge kind = %q", edges[0].Kind)
	}
	if edges[0].Source != "agent-1" || edges[0].Target != "agent-2" {
		t.Errorf("edge 0: %s -> %s", edges[0].Source, edges[0].Target)
	}
	if edges[1].Source != "agent-2" || edges[1].Target != "agent-1" {
		t.Errorf("edge 1: %s -> %s", edges[1].Source, edges[1].Target)
	}
}

func TestCanImpersonate_ProcessDissimilarAgents(t *testing.T) {
	mock := &graph.MockGraphDB{
		QueryFunc: func(_ context.Context, cypher string, params map[string]any) ([]map[string]any, error) {
			if strings.Contains(cypher, "A2AAgent)") && !strings.Contains(cypher, "ADVERTISES_SKILL") {
				return []map[string]any{
					{"id": "agent-1", "name": "Agent A", "provider": ""},
					{"id": "agent-2", "name": "Agent B", "provider": ""},
				}, nil
			}
			if params != nil {
				if params["id"] == "agent-1" {
					return []map[string]any{
						{"description": "financial transaction payment processing banking"},
					}, nil
				}
				if params["id"] == "agent-2" {
					return []map[string]any{
						{"description": "image recognition computer vision neural network"},
					}, nil
				}
			}
			return nil, nil
		},
	}

	p := &CanImpersonate{}
	stats, err := p.Process(context.Background(), mock, "scan-1")
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if stats.EdgesCreated != 0 {
		t.Errorf("EdgesCreated = %d, want 0 (dissimilar agents)", stats.EdgesCreated)
	}
}

func TestCanImpersonate_ProcessSameProviderSkipped(t *testing.T) {
	mock := &graph.MockGraphDB{
		QueryFunc: func(_ context.Context, cypher string, params map[string]any) ([]map[string]any, error) {
			if strings.Contains(cypher, "A2AAgent)") && !strings.Contains(cypher, "ADVERTISES_SKILL") {
				return []map[string]any{
					{"id": "agent-1", "name": "Agent A", "provider": "acme"},
					{"id": "agent-2", "name": "Agent B", "provider": "acme"},
				}, nil
			}
			return []map[string]any{
				{"description": "search query database records analysis"},
			}, nil
		},
	}

	p := &CanImpersonate{}
	stats, err := p.Process(context.Background(), mock, "scan-1")
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if stats.EdgesCreated != 0 {
		t.Errorf("EdgesCreated = %d, want 0 (same provider)", stats.EdgesCreated)
	}
}

func TestCanImpersonate_ProcessQueryError(t *testing.T) {
	mock := &graph.MockGraphDB{QueryError: errors.New("query failed")}

	p := &CanImpersonate{}
	_, err := p.Process(context.Background(), mock, "scan-1")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCanImpersonate_ProcessWriteError(t *testing.T) {
	mock := &graph.MockGraphDB{
		QueryFunc: func(_ context.Context, cypher string, params map[string]any) ([]map[string]any, error) {
			if strings.Contains(cypher, "A2AAgent)") && !strings.Contains(cypher, "ADVERTISES_SKILL") {
				return []map[string]any{
					{"id": "agent-1", "name": "Agent A", "provider": ""},
					{"id": "agent-2", "name": "Agent B", "provider": ""},
					{"id": "agent-3", "name": "Agent C", "provider": ""},
				}, nil
			}
			if params != nil {
				switch params["id"] {
				case "agent-1", "agent-2":
					return []map[string]any{
						{"description": "database query search records analysis retrieval indexing"},
					}, nil
				case "agent-3":
					return []map[string]any{
						{"description": "image processing computer vision neural network training"},
					}, nil
				}
			}
			return nil, nil
		},
		WriteEdgesError: errors.New("write failed"),
	}

	p := &CanImpersonate{}
	_, err := p.Process(context.Background(), mock, "scan-1")
	if err == nil {
		t.Fatal("expected error")
	}
}
