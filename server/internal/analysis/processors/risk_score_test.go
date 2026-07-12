package processors

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/server/internal/analysis/riskscore"
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

func TestRiskScore_ProcessPersistsBoundedAgentAuthAssessment(t *testing.T) {
	mock := &graph.MockGraphDB{
		ListNodesResult: []ingest.Node{
			{ID: "agent-unknown-auth", Kinds: []string{"AgentInstance"}},
		},
		QueryFunc: func(_ context.Context, cypher string, _ map[string]any) ([]map[string]any, error) {
			if strings.Contains(cypher, "auth_assessment_complete") {
				return []map[string]any{{
					"rw":                       0.5,
					"auth_assessment_complete": false,
				}}, nil
			}
			return nil, nil
		},
	}

	if _, err := (&RiskScore{}).Process(context.Background(), mock, "scan-1"); err != nil {
		t.Fatalf("Process() error = %v", err)
	}

	var agentAssessment map[string]any
	for _, call := range mock.CallsTo("UpdateNodeProperties") {
		properties, _ := call.Args[1].(map[string]any)
		factors, _ := properties["risk_unknown_factors"].([]string)
		if len(factors) == 1 && factors[0] == "agent_auth" {
			agentAssessment = properties
			break
		}
	}
	if agentAssessment == nil {
		t.Fatal("AgentInstance update omitted agent_auth uncertainty")
	}
	if agentAssessment["risk_score"] != float64(20) ||
		agentAssessment["risk_score_min"] != float64(0) ||
		agentAssessment["risk_score_max"] != float64(20) ||
		agentAssessment["risk_assessment_complete"] != false {
		t.Fatalf("AgentInstance assessment = %+v, want incomplete [0,20]", agentAssessment)
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

func TestScoreNodesAssessmentPagesPastLegacyTenThousandCap(t *testing.T) {
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

	updated, err := scoreNodesAssessment(
		context.Background(),
		mock,
		"MCPTool",
		func(_ context.Context, _ graph.GraphDB, _ string) (riskscore.Assessment, error) {
			return riskscore.ExactAssessment(0.5), nil
		},
	)
	if err != nil {
		t.Fatalf("scoreNodesAssessment() error = %v", err)
	}
	if updated != total {
		t.Fatalf("updated = %d, want %d", updated, total)
	}
	if got := len(mock.CallsTo("ListNodesPage")); got != 11 {
		t.Fatalf("ListNodesPage calls = %d, want 11", got)
	}
}

func TestScoreNodesAssessmentRejectsIncompleteCollectionBeforeUpdating(t *testing.T) {
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

			updated, err := scoreNodesAssessment(
				context.Background(),
				mock,
				"MCPTool",
				func(_ context.Context, _ graph.GraphDB, _ string) (riskscore.Assessment, error) {
					scoreCalls++
					return riskscore.ExactAssessment(0.5), nil
				},
			)

			if err == nil {
				t.Fatal("scoreNodesAssessment() error = nil, want incomplete collection error")
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
	if err == nil {
		t.Fatal("Process() error = nil, want joined update failures")
	}
	// Nodes exist but updates fail — NodesUpdated stays 0
	if stats.NodesUpdated != 0 {
		t.Errorf("NodesUpdated = %d, want 0", stats.NodesUpdated)
	}
	if got := len(mock.CallsTo("UpdateNodeProperties")); got != 4 {
		t.Fatalf("UpdateNodeProperties calls = %d, want all 4 node kinds attempted", got)
	}
	for _, kind := range []string{"AgentInstance", "A2AAgent", "MCPServer", "MCPTool"} {
		if !strings.Contains(err.Error(), "update "+kind+" node-1") {
			t.Errorf("joined error missing %s failure: %v", kind, err)
		}
	}
}

func TestRiskScore_ProcessComputationErrorsContinueAcrossKinds(t *testing.T) {
	mock := &graph.MockGraphDB{
		ListNodesResult: []ingest.Node{{ID: "node-1"}},
		QueryError:      errors.New("score failed"),
	}

	stats, err := (&RiskScore{}).Process(context.Background(), mock, "scan-1")
	if err == nil {
		t.Fatal("Process() error = nil, want joined computation failures")
	}
	if stats.NodesUpdated != 0 {
		t.Fatalf("NodesUpdated = %d, want 0", stats.NodesUpdated)
	}
	for _, kind := range []string{"AgentInstance", "A2AAgent", "MCPServer", "MCPTool"} {
		if !strings.Contains(err.Error(), "scoring "+kind+" nodes") {
			t.Errorf("joined error missing %s failure: %v", kind, err)
		}
	}
}
