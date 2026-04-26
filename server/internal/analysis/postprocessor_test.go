package analysis

import (
	"context"
	"strings"
	"testing"

	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

func TestValidateDependencyOrder_Valid(t *testing.T) {
	processors := allProcessors()
	if err := validateDependencyOrder(processors); err != nil {
		t.Fatalf("expected valid order for allProcessors(), got error: %v", err)
	}
}

func TestValidateDependencyOrder_MissingDep(t *testing.T) {
	fake := fakeProcessor{name: "fake", deps: []string{"nonexistent"}}
	err := validateDependencyOrder([]PostProcessor{&fake})
	if err == nil {
		t.Fatal("expected error for missing dependency, got nil")
	}
	if !strings.Contains(err.Error(), "nonexistent") {
		t.Fatalf("error should mention missing dep name, got: %v", err)
	}
}

func TestCleanStaleCompositeEdges_EmptyCollectors(t *testing.T) {
	db := &graph.MockGraphDB{}
	n, err := cleanStaleCompositeEdges(context.Background(), db, "scan-1", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected 0 deleted, got %d", n)
	}
	if len(db.Calls) != 0 {
		t.Fatalf("expected no DB calls for empty collectors, got %d", len(db.Calls))
	}
}

func TestCleanStaleCompositeEdges_CallsExecuteWrite(t *testing.T) {
	db := &graph.MockGraphDB{ExecuteWriteResult: 5}
	n, err := cleanStaleCompositeEdges(context.Background(), db, "scan-42", []string{"mcp", "config"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 5 {
		t.Fatalf("expected 5 deleted, got %d", n)
	}

	calls := db.CallsTo("ExecuteWrite")
	if len(calls) != 1 {
		t.Fatalf("expected 1 ExecuteWrite call, got %d", len(calls))
	}

	cypher, _ := calls[0].Args[0].(string)
	if !strings.Contains(cypher, "DELETE r") {
		t.Fatalf("cypher should contain DELETE r, got: %s", cypher)
	}

	params, _ := calls[0].Args[1].(map[string]any)
	if params["current_scan_id"] != "scan-42" {
		t.Fatalf("expected current_scan_id=scan-42, got %v", params["current_scan_id"])
	}
	collectors, _ := params["collectors"].([]string)
	if len(collectors) != 2 || collectors[0] != "mcp" || collectors[1] != "config" {
		t.Fatalf("unexpected collectors param: %v", params["collectors"])
	}
}

func TestRunPostProcessors_RunsAll(t *testing.T) {
	db := &graph.MockGraphDB{
		ExecuteWriteResult: 0,
		QueryResult:        nil,
	}

	stats, err := RunPostProcessors(context.Background(), db, "scan-test", []string{"mcp"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	processors := allProcessors()
	if len(stats) != len(processors) {
		t.Fatalf("expected %d stats entries, got %d", len(processors), len(stats))
	}

	namesSeen := make(map[string]bool)
	for _, s := range stats {
		if s.ProcessorName == "" {
			t.Fatal("stat entry has empty ProcessorName")
		}
		namesSeen[s.ProcessorName] = true
	}

	for _, p := range processors {
		if !namesSeen[p.Name()] {
			t.Errorf("processor %q not found in stats", p.Name())
		}
	}
}

// fakeProcessor implements PostProcessor for testing dependency validation.
type fakeProcessor struct {
	name string
	deps []string
}

func (f *fakeProcessor) Name() string           { return f.name }
func (f *fakeProcessor) Dependencies() []string { return f.deps }
func (f *fakeProcessor) Process(_ context.Context, _ graph.GraphDB, _ string) (graph.ProcessingStats, error) {
	return graph.ProcessingStats{ProcessorName: f.name}, nil
}
