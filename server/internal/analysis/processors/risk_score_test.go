package processors

import (
	"context"
	"errors"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

func TestRiskScore_Name(t *testing.T) {
	p := &RiskScore{}
	if p.Name() != "risk_score" {
		t.Errorf("Name() = %q, want risk_score", p.Name())
	}
}

func TestRiskScore_Dependencies(t *testing.T) {
	p := &RiskScore{}
	deps := p.Dependencies()
	expected := []string{
		"has_access_to", "can_execute", "shadows", "poisoned_description",
		"poisoned_instructions", "can_reach", "can_exfiltrate",
		"can_impersonate", "cross_protocol",
	}
	if len(deps) != len(expected) {
		t.Fatalf("Dependencies() len = %d, want %d", len(deps), len(expected))
	}
	for i, d := range deps {
		if d != expected[i] {
			t.Errorf("Dependencies()[%d] = %q, want %q", i, d, expected[i])
		}
	}
}

func TestRiskScore_ProcessSuccess(t *testing.T) {
	mock := &graph.MockGraphDB{
		ListNodesResult: []ingest.Node{
			{ID: "node-1", Kinds: []string{"AgentInstance"}},
		},
		QueryFunc: func(_ context.Context, _ string, _ map[string]any) ([]map[string]any, error) {
			return nil, nil
		},
	}

	p := &RiskScore{}
	stats, err := p.Process(context.Background(), mock, "scan-1")
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if stats.ProcessorName != "risk_score" {
		t.Errorf("ProcessorName = %q", stats.ProcessorName)
	}
	// 3 kinds (AgentInstance, MCPServer, MCPTool) each with 1 node = 3 updated
	if stats.NodesUpdated != 3 {
		t.Errorf("NodesUpdated = %d, want 3", stats.NodesUpdated)
	}

	updateCalls := mock.CallsTo("UpdateNodeProperties")
	if len(updateCalls) != 3 {
		t.Fatalf("UpdateNodeProperties called %d times, want 3", len(updateCalls))
	}
	for _, c := range updateCalls {
		props, _ := c.Args[1].(map[string]any)
		if _, ok := props["risk_score"]; !ok {
			t.Error("expected risk_score property in update")
		}
	}
}

func TestRiskScore_ProcessListError(t *testing.T) {
	mock := &graph.MockGraphDB{
		ListNodesError: errors.New("list failed"),
	}

	p := &RiskScore{}
	_, err := p.Process(context.Background(), mock, "scan-1")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestRiskScore_ProcessNoNodes(t *testing.T) {
	mock := &graph.MockGraphDB{
		ListNodesResult: nil,
	}

	p := &RiskScore{}
	stats, err := p.Process(context.Background(), mock, "scan-1")
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if stats.NodesUpdated != 0 {
		t.Errorf("NodesUpdated = %d, want 0", stats.NodesUpdated)
	}
}

func TestRiskScore_ProcessUpdateError(t *testing.T) {
	mock := &graph.MockGraphDB{
		ListNodesResult: []ingest.Node{
			{ID: "node-1", Kinds: []string{"AgentInstance"}},
		},
		QueryFunc: func(_ context.Context, _ string, _ map[string]any) ([]map[string]any, error) {
			return nil, nil
		},
		UpdateNodeError: errors.New("update failed"),
	}

	p := &RiskScore{}
	stats, err := p.Process(context.Background(), mock, "scan-1")
	if err != nil {
		t.Fatalf("Process() error = %v (update errors are logged, not propagated)", err)
	}
	// Nodes exist but updates fail — NodesUpdated stays 0
	if stats.NodesUpdated != 0 {
		t.Errorf("NodesUpdated = %d, want 0", stats.NodesUpdated)
	}
}
