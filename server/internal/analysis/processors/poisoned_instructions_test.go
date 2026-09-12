package processors

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

func TestPoisonedInstructions_Name(t *testing.T) {
	p := &PoisonedInstructions{}
	if p.Name() != "poisoned_instructions" {
		t.Errorf("Name() = %q, want poisoned_instructions", p.Name())
	}
}

func TestPoisonedInstructions_Dependencies(t *testing.T) {
	p := &PoisonedInstructions{}
	if deps := p.Dependencies(); deps != nil {
		t.Errorf("Dependencies() = %v, want nil", deps)
	}
}

func TestPoisonedInstructions_ProcessSuccess(t *testing.T) {
	mock := &graph.MockGraphDB{ExecuteWriteResult: 1}

	p := &PoisonedInstructions{}
	stats, err := p.Process(context.Background(), mock, "scan-1")
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if stats.ProcessorName != "poisoned_instructions" {
		t.Errorf("ProcessorName = %q", stats.ProcessorName)
	}
	if stats.EdgesCreated != 3 {
		t.Errorf("EdgesCreated = %d, want 3", stats.EdgesCreated)
	}

	calls := mock.CallsTo("ExecuteWrite")
	if len(calls) != 3 {
		t.Fatalf("ExecuteWrite called %d times, want 3", len(calls))
	}
	for _, call := range calls {
		params, _ := call.Args[1].(map[string]any)
		if params["scan_id"] != "scan-1" {
			t.Errorf("scan_id = %v", params["scan_id"])
		}
	}
	poisoningQuery, _ := calls[0].Args[0].(string)
	if !strings.Contains(poisoningQuery, ":POISONED_INSTRUCTIONS") ||
		!strings.Contains(poisoningQuery, "f.instruction_verdict = 'poisoning'") ||
		!strings.Contains(poisoningQuery, "['exact_project', 'exact_user']") {
		t.Fatalf("poisoning projection does not enforce verdict and active scope:\n%s", poisoningQuery)
	}
	signalQuery, _ := calls[1].Args[0].(string)
	if !strings.Contains(signalQuery, ":INSTRUCTION_SIGNAL") ||
		!strings.Contains(signalQuery, "f.instruction_verdict = 'signal'") ||
		!strings.Contains(signalQuery, "f.instruction_scope = 'deep'") {
		t.Fatalf("signal projection does not include signals and deep poisoning:\n%s", signalQuery)
	}
	destructivePathQuery, _ := calls[2].Args[0].(string)
	for _, want := range []string{
		"(a:AgentInstance)-[loads:LOADS_INSTRUCTIONS]->(f:InstructionFile)",
		"(a)-[sink_trust:TRUSTS_SERVER]->(sink_server:MCPServer)",
		"[sink_provides:PROVIDES_TOOL]->(snk:MCPTool)",
		"f.instruction_scope IN ['exact_project', 'exact_user']",
		"snk.mcp_annotation_destructive_hint = true",
		"coalesce(snk.mcp_annotation_read_only_hint, false) = false",
		"})[..20] AS sinks",
		"head(collect({",
		"MERGE (f)-[e:POISONS_CONTEXT]->(snk)",
		"e.source_collector = 'config'",
		"id(witness.loads)",
		"id(witness.trust)",
		"id(witness.provides)",
	} {
		if !strings.Contains(destructivePathQuery, want) {
			t.Errorf("destructive instruction path missing %q:\n%s", want, destructivePathQuery)
		}
	}
}

func TestPoisonedInstructions_ProcessError(t *testing.T) {
	mock := &graph.MockGraphDB{ExecuteWriteError: errors.New("fail")}

	p := &PoisonedInstructions{}
	_, err := p.Process(context.Background(), mock, "scan-1")
	if err == nil {
		t.Fatal("expected error")
	}
}
