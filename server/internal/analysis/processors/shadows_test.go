package processors

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

func TestShadows_Name(t *testing.T) {
	p := &Shadows{}
	if p.Name() != "shadows" {
		t.Errorf("Name() = %q, want shadows", p.Name())
	}
}

func TestShadows_Dependencies(t *testing.T) {
	p := &Shadows{}
	if deps := p.Dependencies(); deps != nil {
		t.Errorf("Dependencies() = %v, want nil", deps)
	}
}

func TestShadows_ProcessSuccess(t *testing.T) {
	mock := &graph.MockGraphDB{ExecuteWriteResult: 2}

	p := &Shadows{}
	stats, err := p.Process(context.Background(), mock, "scan-1")
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if stats.ProcessorName != "shadows" {
		t.Errorf("ProcessorName = %q", stats.ProcessorName)
	}
	// Two ExecuteWrite passes now run: SHADOWS, then POISONS_CONTEXT. The
	// mock returns 2 for each, so EdgesCreated sums to 4.
	if stats.EdgesCreated != 4 {
		t.Errorf("EdgesCreated = %d, want 4 (SHADOWS + POISONS_CONTEXT)", stats.EdgesCreated)
	}

	calls := mock.CallsTo("ExecuteWrite")
	if len(calls) != 2 {
		t.Fatalf("ExecuteWrite called %d times, want 2 (SHADOWS + POISONS_CONTEXT)", len(calls))
	}
	params, _ := calls[0].Args[1].(map[string]any)
	if params["scan_id"] != "scan-1" {
		t.Errorf("scan_id = %v, want scan-1", params["scan_id"])
	}

	shadowsCypher, _ := calls[0].Args[0].(string)
	if !contains(shadowsCypher, "SHADOWS") {
		t.Errorf("first pass should emit SHADOWS, got:\n%s", shadowsCypher)
	}
	poisonsCypher, _ := calls[1].Args[0].(string)
	if !contains(poisonsCypher, "POISONS_CONTEXT") {
		t.Errorf("second pass should emit POISONS_CONTEXT, got:\n%s", poisonsCypher)
	}
	// The POISONS_CONTEXT pass must stay AGENT-SCOPED (src and snk co-resident
	// under one AgentInstance's trusted servers). A regression to two bare
	// MATCH (:MCPTool) clauses would re-globalize the cross product into a
	// cross-tenant false-positive cascade — assert the scoping path and the
	// per-(agent, source) grouping are present. See shadows.go + FEATURE_RESEARCH.md §5.
	for _, want := range []string{
		"AgentInstance",
		"TRUSTS_SERVER",
		"PROVIDES_TOOL",
		"WITH a, source_server",
		"head(collect({",
		"collect({",
		"})[..20] AS sinks",
		"e.evidence_relationship_ids",
	} {
		if !contains(poisonsCypher, want) {
			t.Errorf("POISONS_CONTEXT pass missing %q (agent-scope/cap regression), got:\n%s", want, poisonsCypher)
		}
	}
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }

func TestShadows_ProcessError(t *testing.T) {
	mock := &graph.MockGraphDB{ExecuteWriteError: errors.New("db error")}

	p := &Shadows{}
	_, err := p.Process(context.Background(), mock, "scan-1")
	if err == nil {
		t.Fatal("expected error")
	}
}
