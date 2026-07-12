package processors

import (
	"context"
	"errors"
	"strings"
	"testing"

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

// isListQuery reports whether a cypher is one of scoreNodes' per-kind listing
// queries (as opposed to the risk-score sub-queries the scorer functions run).
func isListQuery(cypher string) bool {
	return strings.Contains(cypher, "RETURN n.objectid AS id") && strings.Contains(cypher, "SKIP $offset")
}

func TestRiskScore_ProcessSuccess(t *testing.T) {
	// The list query returns exactly one node per kind; the scorer sub-queries
	// return nothing (default scores). Each of the 4 kinds therefore yields one
	// scored node -> one risk_score write.
	mock := &graph.MockGraphDB{
		QueryFunc: func(_ context.Context, cypher string, _ map[string]any) ([]map[string]any, error) {
			if isListQuery(cypher) {
				return []map[string]any{{"id": "node-1"}}, nil
			}
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

	// Each scored node is persisted via a scan-scoped ExecuteWrite that sets
	// risk_score. Exactly 4 such writes are expected.
	var riskWrites int
	for _, c := range mock.CallsTo("ExecuteWrite") {
		cypher, _ := c.Args[0].(string)
		if !strings.Contains(cypher, "risk_score") {
			continue
		}
		riskWrites++
		params, _ := c.Args[1].(map[string]any)
		if params["scan_id"] != "scan-1" {
			t.Errorf("risk_score write not scan-scoped: params=%v", params)
		}
	}
	if riskWrites != 4 {
		t.Fatalf("risk_score ExecuteWrite called %d times, want 4", riskWrites)
	}
}

func TestRiskScore_ProcessIncludesA2AAgents(t *testing.T) {
	mock := &graph.MockGraphDB{
		QueryFunc: func(_ context.Context, cypher string, _ map[string]any) ([]map[string]any, error) {
			if isListQuery(cypher) {
				return []map[string]any{{"id": "node-1"}}, nil
			}
			return nil, nil
		},
	}

	p := &RiskScore{}
	_, err := p.Process(context.Background(), mock, "scan-1")
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}

	var sawA2A bool
	for _, call := range mock.CallsTo("Query") {
		cypher, _ := call.Args[0].(string)
		if isListQuery(cypher) && strings.Contains(cypher, "(n:A2AAgent)") {
			sawA2A = true
		}
	}
	if !sawA2A {
		t.Fatal("risk_score did not list A2AAgent nodes")
	}
}

// pagingGraphDB embeds MockGraphDB and serves a fixed number of full pages
// (riskScorePageSize each) followed by a short final page for the list query,
// so the exhaustive paging loop in scoreNodes can be exercised without a live
// Neo4j.
type pagingGraphDB struct {
	*graph.MockGraphDB
	pageCalls int
	fullPages int // number of full pages before a short (final) page
}

func (p *pagingGraphDB) Query(ctx context.Context, cypher string, params map[string]any) ([]map[string]any, error) {
	if !isListQuery(cypher) {
		return p.MockGraphDB.Query(ctx, cypher, params)
	}
	p.pageCalls++
	limit, _ := params["limit"].(int)
	offset, _ := params["offset"].(int)
	if limit <= 0 {
		limit = riskScorePageSize
	}
	page := offset / limit
	if page < p.fullPages {
		out := make([]map[string]any, limit)
		for i := range out {
			out[i] = map[string]any{"id": "n"}
		}
		return out, nil
	}
	// Short final page ends the walk.
	return []map[string]any{{"id": "last"}}, nil
}

func TestRiskScore_PagesToExhaustion(t *testing.T) {
	base := &graph.MockGraphDB{}
	db := &pagingGraphDB{MockGraphDB: base, fullPages: 2}

	updated, err := scoreNodes(context.Background(), db, "scan-1", "AgentInstance",
		func(_ context.Context, _ graph.GraphDB, _ string) (float64, error) { return 1.0, nil })
	if err != nil {
		t.Fatalf("scoreNodes: %v", err)
	}
	// 2 full pages (riskScorePageSize each) + 1 short page (1 node).
	want := 2*riskScorePageSize + 1
	if updated != want {
		t.Errorf("expected %d nodes scored across pages, got %d", want, updated)
	}
	// One page call per full page plus the terminating short page = 3.
	if db.pageCalls != 3 {
		t.Errorf("expected 3 page reads, got %d", db.pageCalls)
	}
}

func TestRiskScore_ProcessListError(t *testing.T) {
	mock := &graph.MockGraphDB{
		QueryError: errors.New("list failed"),
	}

	p := &RiskScore{}
	_, err := p.Process(context.Background(), mock, "scan-1")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestRiskScore_ProcessNoNodes(t *testing.T) {
	mock := &graph.MockGraphDB{
		QueryFunc: func(_ context.Context, _ string, _ map[string]any) ([]map[string]any, error) {
			return nil, nil
		},
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
	// Nodes exist (list query returns one per kind) but the risk_score write
	// fails: update errors are logged, not propagated, and NodesUpdated stays 0.
	mock := &graph.MockGraphDB{
		QueryFunc: func(_ context.Context, cypher string, _ map[string]any) ([]map[string]any, error) {
			if isListQuery(cypher) {
				return []map[string]any{{"id": "node-1"}}, nil
			}
			return nil, nil
		},
		ExecuteWriteError: errors.New("update failed"),
	}

	p := &RiskScore{}
	stats, err := p.Process(context.Background(), mock, "scan-1")
	if err != nil {
		t.Fatalf("Process() error = %v (update errors are logged, not propagated)", err)
	}
	if stats.NodesUpdated != 0 {
		t.Errorf("NodesUpdated = %d, want 0", stats.NodesUpdated)
	}
}
