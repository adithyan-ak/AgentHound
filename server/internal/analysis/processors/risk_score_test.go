package processors

import (
	"context"
	"errors"
	"fmt"
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
	// 4 kinds (AgentInstance, A2AAgent, MCPServer, MCPTool) each with 1 node = 4 updated
	if stats.NodesUpdated != 4 {
		t.Errorf("NodesUpdated = %d, want 4", stats.NodesUpdated)
	}

	updateCalls := mock.CallsTo("UpdateNodeProperties")
	if len(updateCalls) != 4 {
		t.Fatalf("UpdateNodeProperties called %d times, want 4", len(updateCalls))
	}
	for _, c := range updateCalls {
		props, _ := c.Args[1].(map[string]any)
		for _, key := range []string{
			"risk_score",
			"risk_score_min",
			"risk_score_max",
			"risk_assessment_complete",
			"risk_unknown_factors",
		} {
			if _, ok := props[key]; !ok {
				t.Errorf("expected %s property in update: %+v", key, props)
			}
		}
	}
}

func TestRiskScore_ProcessIncludesA2AAgents(t *testing.T) {
	mock := &graph.MockGraphDB{
		ListNodesResult: []ingest.Node{{ID: "node-1", Kinds: []string{"A2AAgent"}}},
		QueryFunc: func(_ context.Context, _ string, _ map[string]any) ([]map[string]any, error) {
			return nil, nil
		},
	}

	p := &RiskScore{}
	_, err := p.Process(context.Background(), mock, "scan-1")
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}

	var sawA2A bool
	for _, call := range mock.CallsTo("ListNodesPage") {
		if kind, _ := call.Args[0].(string); kind == "A2AAgent" {
			sawA2A = true
		}
	}
	if !sawA2A {
		t.Fatal("risk_score did not list A2AAgent nodes")
	}
}

func TestScoreNodesPagesPastLegacyTenThousandCap(t *testing.T) {
	const total = 10001
	mock := &graph.MockGraphDB{}
	mock.ListNodesPageFunc = func(_ context.Context, kind string, limit, offset int, revision string) ([]ingest.Node, graph.PageInfo, error) {
		if kind != "MCPTool" {
			t.Fatalf("kind = %q, want MCPTool", kind)
		}
		if offset > 0 && revision != "rev-1" {
			t.Fatalf("continuation revision = %q, want rev-1", revision)
		}
		end := min(offset+limit, total)
		nodes := make([]ingest.Node, 0, end-offset)
		for i := offset; i < end; i++ {
			nodes = append(nodes, ingest.Node{ID: fmt.Sprintf("tool-%05d", i)})
		}
		return nodes, graph.PageInfo{
			Offset: offset, Limit: limit, Total: total,
			HasMore: end < total, Complete: end == total, Revision: "rev-1",
		}, nil
	}

	updated, err := scoreNodes(
		context.Background(),
		mock,
		"MCPTool",
		func(_ context.Context, _ graph.GraphDB, _ string) (float64, error) {
			return 0.5, nil
		},
	)
	if err != nil {
		t.Fatalf("scoreNodes() error = %v", err)
	}
	if updated != total {
		t.Fatalf("updated = %d, want %d", updated, total)
	}
	if got := len(mock.CallsTo("ListNodesPage")); got != 11 {
		t.Fatalf("ListNodesPage calls = %d, want 11", got)
	}
}

func TestScoreNodesRejectsIncompleteCollectionBeforeUpdating(t *testing.T) {
	tests := []struct {
		name string
		page graph.PageInfo
	}{
		{
			name: "incomplete final page",
			page: graph.PageInfo{
				Offset: 0, Limit: 1000, Total: 1,
				Complete: false, Revision: "rev-1",
			},
		},
		{
			name: "count mismatch",
			page: graph.PageInfo{
				Offset: 0, Limit: 1000, Total: 2,
				Complete: true, Revision: "rev-1",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &graph.MockGraphDB{
				ListNodesPageFunc: func(
					_ context.Context,
					_ string,
					_, _ int,
					_ string,
				) ([]ingest.Node, graph.PageInfo, error) {
					return []ingest.Node{{ID: "tool-1"}}, tt.page, nil
				},
			}
			scoreCalls := 0

			updated, err := scoreNodes(
				context.Background(),
				mock,
				"MCPTool",
				func(_ context.Context, _ graph.GraphDB, _ string) (float64, error) {
					scoreCalls++
					return 0.5, nil
				},
			)

			if err == nil {
				t.Fatal("scoreNodes() error = nil, want incomplete collection error")
			}
			if updated != 0 || scoreCalls != 0 ||
				len(mock.CallsTo("UpdateNodeProperties")) != 0 {
				t.Fatalf(
					"partial collection was scored: updated=%d score_calls=%d",
					updated,
					scoreCalls,
				)
			}
		})
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
