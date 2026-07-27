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

func TestCoverageLimitedSeparatesUnknownFromNotApplicable(t *testing.T) {
	scope := CanonicalCoverageKey("a2a", "target", "https://agent.example")
	for _, test := range []struct {
		name  string
		state OutcomeState
		want  bool
	}{
		{name: "complete", state: OutcomeComplete, want: false},
		{name: "not applicable", state: OutcomeNotApplicable, want: false},
		{name: "partial", state: OutcomePartial, want: true},
		{name: "failed", state: OutcomeFailed, want: true},
		{name: "truncated", state: OutcomeTruncated, want: true},
		{name: "unknown", state: OutcomeUnknown, want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			report := &CollectionReport{
				State:        AggregateOutcomeState([]CollectionOutcome{{State: test.state}}),
				CoverageKeys: []string{scope},
				Outcomes: []CollectionOutcome{{
					Collector: "a2a", CoverageKey: scope, State: test.state,
				}},
			}
			if got := CoverageLimited(report); got != test.want {
				t.Fatalf("CoverageLimited(%s) = %t, want %t", test.state, got, test.want)
			}
		})
	}
	if !CoverageLimited(nil) {
		t.Fatal("missing collection report was treated as complete coverage")
	}
	if !CoverageLimited(&CollectionReport{}) {
		t.Fatal("zero declared scopes were treated as complete coverage")
	}
}

func TestCompleteAuthoritativeRootsRequiresCompleteRootAndChildren(t *testing.T) {
	root := CanonicalCoverageKey("mcp", "root", "collect")
	child := CanonicalCoverageKey("mcp", "target", "server-a")
	report := &CollectionReport{
		State:        OutcomeComplete,
		CoverageKeys: []string{root, child},
		AuthoritativeRoots: []CoverageRoot{{
			CoverageKey:       root,
			ChildCoverageKeys: []string{child},
		}},
		Outcomes: []CollectionOutcome{
			{CoverageKey: root, State: OutcomeComplete},
			{CoverageKey: child, State: OutcomeComplete},
		},
	}
	if got := CompleteAuthoritativeRoots(report); !reflect.DeepEqual(
		got,
		report.AuthoritativeRoots,
	) {
		t.Fatalf("complete authoritative roots = %+v, want %+v", got, report.AuthoritativeRoots)
	}

	report.Outcomes[1].State = OutcomeFailed
	if got := CompleteAuthoritativeRoots(report); len(got) != 0 {
		t.Fatalf("failed child produced authoritative root: %+v", got)
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

func TestNonBlockingInstructionCoverageDomainsIncludesRecognizedIncompleteRoots(t *testing.T) {
	contract := CurrentInstructionRegistryContract()
	for _, mode := range []struct {
		name   string
		method string
		kind   string
	}{
		{"exact_user", InstructionMethodExactUser, "instruction-exact-user"},
		{"exact_project", InstructionMethodExactProject, "instruction-exact-project"},
		{"deep", InstructionMethodDeep, "instruction-deep"},
	} {
		for _, state := range []OutcomeState{
			OutcomeTruncated,
			OutcomePartial,
			OutcomeFailed,
		} {
			t.Run(mode.name+"/"+string(state), func(t *testing.T) {
				root := CanonicalCoverageKey("config", mode.kind, "/home/example")
				child := CanonicalCoverageKey("config", "instruction-source", root+"\x00AGENTS.md")
				report := &CollectionReport{
					State:        state,
					CoverageKeys: []string{root, child},
					AuthoritativeRoots: []CoverageRoot{{
						CoverageKey:       root,
						ChildCoverageKeys: []string{child},
						RegistryContract:  &contract,
					}},
					Outcomes: []CollectionOutcome{
						{
							Collector: "config", CoverageKey: root,
							Method: mode.method, State: state,
						},
						{
							Collector: "config", CoverageKey: child, ParentCoverageKey: root,
							Method: InstructionMethodSource, State: OutcomeComplete,
						},
					},
				}
				if got := NonBlockingInstructionCoverageDomains(report); !reflect.DeepEqual(
					got,
					[]string{root, child},
				) {
					t.Fatalf("non-blocking domains = %v, want [%s %s]", got, root, child)
				}
				if !InstructionCoverageLimited(report) {
					t.Fatal("recognized incomplete instruction root was not coverage-limited")
				}
				if got := CompleteAuthoritativeRoots(report); len(got) != 0 {
					t.Fatalf("incomplete root became authoritative: %+v", got)
				}
			})
		}
	}
	if strings.Contains(CoverageLimitationWarning, "deep") {
		t.Fatalf("coverage warning remains deep-specific: %q", CoverageLimitationWarning)
	}
}

func TestNonBlockingInstructionCoverageDomainsStopsAtDirectChildren(t *testing.T) {
	contract := CurrentInstructionRegistryContract()
	root := CanonicalCoverageKey("config", "instruction-deep", "/home/example")
	child := CanonicalCoverageKey("config", "instruction-source", root+"\x00AGENTS.md")
	grandchild := CanonicalCoverageKey("config", "path", child+"\x00descendant")
	report := &CollectionReport{
		State:        OutcomePartial,
		CoverageKeys: []string{root, child, grandchild},
		AuthoritativeRoots: []CoverageRoot{{
			CoverageKey:       root,
			ChildCoverageKeys: []string{child},
			RegistryContract:  &contract,
		}},
		Outcomes: []CollectionOutcome{
			{
				Collector: "config", CoverageKey: root,
				Method: InstructionMethodDeep, State: OutcomePartial,
			},
			{
				Collector: "config", CoverageKey: child, ParentCoverageKey: root,
				Method: InstructionMethodSource, State: OutcomeComplete,
			},
			{
				Collector: "config", CoverageKey: grandchild, ParentCoverageKey: child,
				Method: "config_discovery", State: OutcomeComplete,
			},
		},
	}
	if got := NonBlockingInstructionCoverageDomains(report); !reflect.DeepEqual(
		got,
		[]string{root, child},
	) {
		t.Fatalf("non-blocking domains = %v, want direct instruction ownership only", got)
	}
}

func TestNonBlockingInstructionCoverageDomainsRejectsCompleteOrMalformedRoots(t *testing.T) {
	root := CanonicalCoverageKey("config", "instruction-exact-user", "/home/example")
	child := CanonicalCoverageKey("config", "instruction-source", root+"\x00AGENTS.md")
	contract := CurrentInstructionRegistryContract()
	report := &CollectionReport{
		State:        OutcomeComplete,
		CoverageKeys: []string{root, child},
		AuthoritativeRoots: []CoverageRoot{{
			CoverageKey:       root,
			ChildCoverageKeys: []string{child},
			RegistryContract:  &contract,
		}},
		Outcomes: []CollectionOutcome{
			{
				Collector: "config", CoverageKey: root,
				Method: InstructionMethodExactUser, State: OutcomeComplete,
			},
			{
				Collector: "config", CoverageKey: child, ParentCoverageKey: root,
				Method: InstructionMethodSource, State: OutcomeComplete,
			},
		},
	}
	if got := NonBlockingInstructionCoverageDomains(report); len(got) != 0 {
		t.Fatalf("complete exact root became non-blocking: %v", got)
	}
	if InstructionCoverageLimited(report) {
		t.Fatal("complete exact root was coverage-limited")
	}

	report.Outcomes[0].State = OutcomePartial
	report.AuthoritativeRoots[0].RegistryContract = nil
	if got := NonBlockingInstructionCoverageDomains(report); len(got) != 0 {
		t.Fatalf("contractless root became non-blocking: %v", got)
	}
	if InstructionCoverageLimited(report) {
		t.Fatal("contractless root was coverage-limited")
	}

	malformed := contract
	malformed.Digest = "sha256:forged"
	report.AuthoritativeRoots[0].RegistryContract = &malformed
	if got := NonBlockingInstructionCoverageDomains(report); len(got) != 0 {
		t.Fatalf("malformed-contract root became non-blocking: %v", got)
	}
	if InstructionCoverageLimited(report) {
		t.Fatal("malformed-contract root was coverage-limited")
	}
}

func TestAuthoritativeCoverageCompleteIgnoresLimitedInstructionFamily(t *testing.T) {
	root := CanonicalCoverageKey("config", "instruction-exact-project", "/work/project")
	child := CanonicalCoverageKey("config", "instruction-source", root+"\x00AGENTS.md")
	config := CanonicalCoverageKey("config", "path", "/work/project/config.json")
	contract := CurrentInstructionRegistryContract()
	report := &CollectionReport{
		State:        OutcomePartial,
		CoverageKeys: []string{root, child, config},
		AuthoritativeRoots: []CoverageRoot{{
			CoverageKey:       root,
			ChildCoverageKeys: []string{child},
			RegistryContract:  &contract,
		}},
		Outcomes: []CollectionOutcome{
			{
				Collector: "config", CoverageKey: root,
				Method: InstructionMethodExactProject, State: OutcomeFailed,
			},
			{
				Collector: "config", CoverageKey: child, ParentCoverageKey: root,
				Method: InstructionMethodSource, State: OutcomeComplete,
			},
			{
				Collector: "config", CoverageKey: config,
				Method: "config_discovery", State: OutcomeComplete,
			},
		},
	}
	if !AuthoritativeCoverageComplete(report) {
		t.Fatal("complete blocking config domain was suppressed by limited instruction coverage")
	}
}
