package analysis

import (
	"context"
	"errors"
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

func TestBeginCompositeEpoch_RetiresAllDerivedState(t *testing.T) {
	db := &graph.MockGraphDB{ExecuteWriteResult: 5}
	n, err := beginCompositeEpoch(context.Background(), db)
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
	if !strings.Contains(cypher, "r.is_composite = true") {
		t.Fatalf("cypher should restrict retirement to composite edges: %s", cypher)
	}
	if !strings.Contains(cypher, "REMOVE c.blast_radius") {
		t.Fatalf("cypher should reset processor-owned blast radius: %s", cypher)
	}
	if strings.Contains(cypher, "source_collector") ||
		strings.Contains(cypher, "scan_id") {
		t.Fatalf("epoch retirement must not be collector- or scan-scoped: %s", cypher)
	}
}

func TestRunPostProcessors_CompleteNarrowDomainRetiresCrossDomainEvidence(t *testing.T) {
	domains := []string{
		"mcp:target:sha256:mcp-scope",
		"config:path:sha256:config-scope",
		"a2a:target:sha256:a2a-scope",
	}
	for _, domain := range domains {
		t.Run(strings.SplitN(domain, ":", 2)[0], func(t *testing.T) {
			remaining := map[string]bool{
				"cross_protocol:a2a":                              true,
				"transitive_reach:mcp":                            true,
				"credential_chain:cross_service_credential_chain": true,
				"instruction_poisoning:config":                    true,
			}
			retireCalls := 0
			processorWrites := 0
			db := &graph.MockGraphDB{
				ExecuteWriteFunc: func(_ context.Context, cypher string, _ map[string]any) (int, error) {
					if strings.Contains(cypher, "REMOVE c.blast_radius") {
						retireCalls++
						if strings.Contains(cypher, "source_collector") {
							t.Fatalf(
								"narrow %s replacement used collector-scoped cleanup: %s",
								domain,
								cypher,
							)
						}
						for evidence := range remaining {
							delete(remaining, evidence)
						}
						return 4, nil
					}
					processorWrites++
					return 0, nil
				},
			}

			if _, err := RunPostProcessors(
				context.Background(),
				db,
				"narrow-complete",
				[]string{domain},
			); err != nil {
				t.Fatalf("RunPostProcessors: %v", err)
			}
			if retireCalls != 1 {
				t.Fatalf("composite epoch retire calls = %d, want 1", retireCalls)
			}
			if len(remaining) != 0 {
				t.Fatalf("cross-domain composite evidence survived %s replacement: %v", domain, remaining)
			}
			if processorWrites == 0 {
				t.Fatalf("complete %s replacement retired without recomputing", domain)
			}
		})
	}
}

func TestRunPostProcessors_NoCompleteDomainPreservesCompositeEpoch(t *testing.T) {
	db := &graph.MockGraphDB{}
	if _, err := RunPostProcessors(
		context.Background(),
		db,
		"partial-scan",
		[]string{"", " "},
	); err != nil {
		t.Fatalf("RunPostProcessors: %v", err)
	}
	if len(db.Calls) != 0 {
		t.Fatalf("partial/failed coverage ran derived processing: %+v", db.Calls)
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
	writes := db.CallsTo("ExecuteWrite")
	if len(writes) == 0 {
		t.Fatal("expected epoch retirement and processor writes")
	}
	firstCypher, _ := writes[0].Args[0].(string)
	if !strings.Contains(firstCypher, "REMOVE c.blast_radius") {
		t.Fatalf("composite retirement was not the first write: %s", firstCypher)
	}
}

func TestRunPostProcessors_RetirementFailureStopsBeforeProcessors(t *testing.T) {
	db := &graph.MockGraphDB{
		ExecuteWriteError: errors.New("retirement failed"),
	}

	_, err := RunPostProcessors(context.Background(), db, "scan-test", []string{"mcp"})
	if err == nil {
		t.Fatal("expected retirement failure")
	}
	if calls := db.CallsTo("ExecuteWrite"); len(calls) != 1 {
		t.Fatalf("ExecuteWrite calls = %d, want only the failed retirement", len(calls))
	}
}

func TestRunPostProcessors_ProcessorFailureLeavesIncompleteNewEpoch(t *testing.T) {
	var writes int
	db := &graph.MockGraphDB{
		ExecuteWriteFunc: func(_ context.Context, cypher string, _ map[string]any) (int, error) {
			writes++
			if writes == 1 {
				if !strings.Contains(cypher, "REMOVE c.blast_radius") {
					t.Fatalf("first write did not retire the prior epoch: %s", cypher)
				}
				return 3, nil
			}
			return 0, errors.New("processor write failed")
		},
	}

	_, err := RunPostProcessors(context.Background(), db, "scan-test", []string{"mcp"})
	if err == nil {
		t.Fatal("expected processor failure")
	}
	retireCalls := 0
	for _, call := range db.CallsTo("ExecuteWrite") {
		cypher, _ := call.Args[0].(string)
		if strings.Contains(cypher, "REMOVE c.blast_radius") {
			retireCalls++
		}
	}
	if retireCalls != 1 {
		t.Fatalf("composite epoch retire calls = %d, want 1", retireCalls)
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
