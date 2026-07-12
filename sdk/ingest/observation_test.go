package ingest

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestTagObservationDomainPreservesSharedOwners(t *testing.T) {
	configScope := CanonicalCoverageKey("config", "path", "/tmp/config.json")
	mcpScope := CanonicalCoverageKey("mcp", "target", "https://mcp.example")
	graph := GraphData{
		Nodes: []Node{{ID: "shared", ObservationDomains: []string{configScope}}},
		Edges: []Edge{{Source: "a", Target: "b", Kind: "RUNS_ON"}},
	}

	TagObservationDomain(&graph, mcpScope)
	TagObservationDomain(&graph, mcpScope)

	if got, want := graph.Nodes[0].ObservationDomains, []string{configScope, mcpScope}; !reflect.DeepEqual(got, want) {
		t.Fatalf("node domains = %v, want %v", got, want)
	}
	if got, want := graph.Edges[0].ObservationDomains, []string{mcpScope}; !reflect.DeepEqual(got, want) {
		t.Fatalf("edge domains = %v, want %v", got, want)
	}
}

func TestObservationDomainsRoundTripAdditively(t *testing.T) {
	scope := CanonicalCoverageKey("mcp", "target", "https://mcp.example")
	original := GraphData{
		Nodes: []Node{{
			ID: "node", Kinds: []string{"MCPServer"},
			ObservationDomains: []string{scope},
		}},
		Edges: []Edge{{
			Source: "node", Target: "tool", Kind: "PROVIDES_TOOL",
			ObservationDomains:   []string{scope, CanonicalCoverageKey("config", "path", "/tmp/config.json")},
			ObservationSemantics: ObservationSemanticsAllDependencies,
		}},
	}
	encoded, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	var decoded GraphData
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded, original) {
		t.Fatalf("round trip = %+v, want %+v", decoded, original)
	}
}

func TestCoverageStatesKeepsCompleteChildOfPartialScan(t *testing.T) {
	configScope := CanonicalCoverageKey("config", "path", "/tmp/config.json")
	mcpScope := CanonicalCoverageKey("mcp", "target", "https://mcp.example")
	report := &CollectionReport{
		State:        OutcomePartial,
		CoverageKeys: []string{configScope, mcpScope},
		Outcomes: []CollectionOutcome{
			{Collector: "config", CoverageKey: configScope, State: OutcomeComplete},
			{Collector: "mcp", CoverageKey: mcpScope, State: OutcomeFailed},
		},
	}

	states := CoverageStates(report)
	if states[configScope] != OutcomeComplete {
		t.Fatalf("config state = %q, want complete", states[configScope])
	}
	if states[mcpScope] != OutcomeFailed {
		t.Fatalf("mcp state = %q, want failed", states[mcpScope])
	}
	if got := CompleteCoverageDomains(report); !reflect.DeepEqual(got, []string{configScope}) {
		t.Fatalf("complete domains = %v, want [%s]", got, configScope)
	}
	if CollectionCoverageComplete(report) {
		t.Fatal("partial multi-domain report must not be globally complete")
	}
}

func TestCoverageStatesDoesNotPromoteUnattributedMultiDomainReport(t *testing.T) {
	report := &CollectionReport{
		State: OutcomeComplete,
		CoverageKeys: []string{
			CanonicalCoverageKey("config", "path", "/tmp/config.json"),
			CanonicalCoverageKey("mcp", "target", "https://mcp.example"),
		},
	}

	if got := CompleteCoverageDomains(report); len(got) != 0 {
		t.Fatalf("unattributed domains = %v, want none", got)
	}
	if CollectionCoverageComplete(report) {
		t.Fatal("report-level complete must not promote multiple unattributed domains")
	}
}

func TestCoverageStatesUsesTargetScopedOutcomeKey(t *testing.T) {
	targetA := CanonicalCoverageKey("mcp", "target", "server-a")
	targetB := CanonicalCoverageKey("mcp", "target", "server-b")
	report := &CollectionReport{
		State:        OutcomePartial,
		CoverageKeys: []string{targetA, targetB},
		Outcomes: []CollectionOutcome{
			{Collector: "mcp", CoverageKey: targetA, State: OutcomeComplete},
			{Collector: "mcp", CoverageKey: targetB, State: OutcomeFailed},
		},
	}

	states := CoverageStates(report)
	if states[targetA] != OutcomeComplete || states[targetB] != OutcomeFailed {
		t.Fatalf("target-scoped states = %v", states)
	}
	if got := CompleteCoverageDomains(report); !reflect.DeepEqual(got, []string{targetA}) {
		t.Fatalf("complete target scopes = %v, want [%s]", got, targetA)
	}
}

func TestCanonicalCoverageKeySeparatesScopesWithoutLeakingTarget(t *testing.T) {
	first := CanonicalCoverageKey("a2a", "target", "https://one.example/agent")
	second := CanonicalCoverageKey("a2a", "target", "https://two.example/agent")
	if first == second {
		t.Fatal("different canonical targets produced the same coverage key")
	}
	if first != CanonicalCoverageKey(" A2A ", " TARGET ", "https://one.example/agent") {
		t.Fatal("collector and scope kind normalization is not stable")
	}
	if strings.Contains(first, "one.example") {
		t.Fatalf("coverage key leaks target material: %q", first)
	}
}

func TestCanonicalURLScopeNormalizesEquivalentTargets(t *testing.T) {
	first := CanonicalURLScope(" HTTPS://Example.COM:443/mcp/?b=2&a=1#fragment ")
	second := CanonicalURLScope("https://example.com/mcp?a=1&b=2")
	if first != second {
		t.Fatalf("canonical URL scopes differ: %q != %q", first, second)
	}
	if first != "https://example.com/mcp?a=1&b=2" {
		t.Fatalf("canonical URL scope = %q", first)
	}
}
