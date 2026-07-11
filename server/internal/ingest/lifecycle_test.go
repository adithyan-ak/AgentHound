package ingest

import (
	"testing"

	sdkingest "github.com/adithyan-ak/agenthound/sdk/ingest"
)

func TestComparisonKeyRequiresCompleteKnownInputs(t *testing.T) {
	data := &sdkingest.IngestData{
		Meta: sdkingest.IngestMeta{
			Collection: &sdkingest.CollectionReport{
				State:        sdkingest.OutcomeComplete,
				CoverageKeys: []string{"mcp", "config"},
				Outcomes: []sdkingest.CollectionOutcome{
					{Collector: "mcp", State: sdkingest.OutcomeComplete},
					{Collector: "config", State: sdkingest.OutcomeComplete},
				},
			},
			Ruleset: &sdkingest.RulesetManifest{
				Digest:    "sha256:rules",
				LoadState: sdkingest.OutcomeComplete,
			},
			IdentitySchemes: []sdkingest.IdentityScheme{
				{EntityKind: "MCPServer", Scheme: "v2", Version: 2},
			},
		},
	}

	key := comparisonKey(data, true)
	if key == "" {
		t.Fatal("complete known inputs produced no comparison key")
	}
	data.Meta.Collection.State = sdkingest.OutcomePartial
	data.Meta.Collection.Outcomes[0].State = sdkingest.OutcomeFailed
	if got := comparisonKey(data, true); got != "" {
		t.Fatalf("partial coverage comparison key = %q", got)
	}
	data.Meta.Collection.Outcomes[0].State = sdkingest.OutcomeComplete
	data.Meta.Collection.State = sdkingest.OutcomeComplete
	if got := comparisonKey(data, false); got != "" {
		t.Fatalf("unattributed comparison key = %q", got)
	}
}

func TestComparisonKeyIncludesCanonicalTargetAndConfigScope(t *testing.T) {
	scopeA := sdkingest.CanonicalCoverageKey("a2a", "target", "https://a.example")
	scopeB := sdkingest.CanonicalCoverageKey("a2a", "target", "https://b.example")
	makeData := func(scope string) *sdkingest.IngestData {
		return &sdkingest.IngestData{
			Meta: sdkingest.IngestMeta{
				Collection: &sdkingest.CollectionReport{
					State:        sdkingest.OutcomeComplete,
					CoverageKeys: []string{scope},
					Outcomes: []sdkingest.CollectionOutcome{{
						Collector:   "a2a",
						CoverageKey: scope,
						State:       sdkingest.OutcomeComplete,
					}},
				},
				Ruleset: &sdkingest.RulesetManifest{
					Digest:    "sha256:rules",
					LoadState: sdkingest.OutcomeComplete,
				},
				IdentitySchemes: []sdkingest.IdentityScheme{{
					EntityKind: "A2AAgent",
					Scheme:     "url_v1",
					Version:    1,
				}},
			},
		}
	}

	keyA := comparisonKey(makeData(scopeA), true)
	keyB := comparisonKey(makeData(scopeB), true)
	if keyA == "" || keyB == "" {
		t.Fatalf("scoped comparison keys are empty: %q %q", keyA, keyB)
	}
	if keyA == keyB {
		t.Fatalf("different targets received the same comparison key %q", keyA)
	}

	configA := sdkingest.CanonicalCoverageKey("config", "path", "/configs/a.json")
	configB := sdkingest.CanonicalCoverageKey("config", "path", "/configs/b.json")
	configKeyA := comparisonKey(makeData(configA), true)
	configKeyB := comparisonKey(makeData(configB), true)
	if configKeyA == "" || configKeyB == "" {
		t.Fatalf("config comparison keys are empty: %q %q", configKeyA, configKeyB)
	}
	if configKeyA == configKeyB {
		t.Fatalf("different config scopes received the same comparison key %q", configKeyA)
	}
	if configKeyA == keyA {
		t.Fatalf("target and config scopes received the same comparison key %q", keyA)
	}
}

func TestCoalesceObservationGraphPreservesAllCurrentOwners(t *testing.T) {
	graph := coalesceObservationGraph(sdkingest.GraphData{
		Nodes: []sdkingest.Node{
			{
				ID:                 "shared",
				Kinds:              []string{"MCPServer"},
				Properties:         map[string]any{"mcp_only": true},
				ObservationDomains: []string{"mcp:target:sha256:a"},
			},
			{
				ID:                 "shared",
				Kinds:              []string{"MCPServer", "AIService"},
				Properties:         map[string]any{"config_only": true},
				ObservationDomains: []string{"config:path:sha256:b"},
			},
		},
		Edges: []sdkingest.Edge{
			{
				Source:             "shared",
				Target:             "host",
				Kind:               "RUNS_ON",
				Properties:         map[string]any{"first": true},
				ObservationDomains: []string{"mcp:target:sha256:a"},
			},
			{
				Source:             "shared",
				Target:             "host",
				Kind:               "RUNS_ON",
				Properties:         map[string]any{"second": true},
				ObservationDomains: []string{"config:path:sha256:b"},
			},
		},
	})

	if len(graph.Nodes) != 1 || len(graph.Edges) != 1 {
		t.Fatalf("coalesced graph = %+v", graph)
	}
	node := graph.Nodes[0]
	if node.Properties["mcp_only"] != true || node.Properties["config_only"] != true ||
		len(node.ObservationDomains) != 2 || len(node.Kinds) != 2 {
		t.Fatalf("coalesced node lost provenance: %+v", node)
	}
	edge := graph.Edges[0]
	if edge.Properties["first"] != true || edge.Properties["second"] != true ||
		len(edge.ObservationDomains) != 2 {
		t.Fatalf("coalesced edge lost provenance: %+v", edge)
	}
}

func TestPrepareObservationDomainsRejectsScopeOutsideCoverage(t *testing.T) {
	declared := sdkingest.CanonicalCoverageKey("mcp", "target", "declared")
	unrelated := sdkingest.CanonicalCoverageKey("mcp", "target", "unrelated")
	data := &sdkingest.IngestData{
		Meta: sdkingest.IngestMeta{
			Collection: &sdkingest.CollectionReport{
				State:        sdkingest.OutcomeComplete,
				CoverageKeys: []string{declared, unrelated},
				Outcomes: []sdkingest.CollectionOutcome{
					{
						Collector:   "mcp",
						CoverageKey: declared,
						State:       sdkingest.OutcomeComplete,
					},
					{
						Collector:   "mcp",
						CoverageKey: unrelated,
						State:       sdkingest.OutcomeComplete,
					},
				},
			},
		},
		Graph: sdkingest.GraphData{Nodes: []sdkingest.Node{{
			ID:                 "node",
			ObservationDomains: []string{"mcp:target:sha256:not-declared"},
		}}},
	}
	if prepareObservationDomains(data) {
		t.Fatal("fact scope outside declared coverage was accepted")
	}
}

func TestCoverageCollectorsMapsScopedKeysForCompositeCleanup(t *testing.T) {
	keys := []string{
		sdkingest.CanonicalCoverageKey("mcp", "target", "server"),
		sdkingest.CanonicalCoverageKey("config", "path", "/config"),
		sdkingest.CanonicalCoverageKey("mcp", "target", "other-server"),
	}
	got := coverageCollectors(keys)
	if len(got) != 2 || got[0] != "config" || got[1] != "mcp" {
		t.Fatalf("coverage collectors = %v, want [config mcp]", got)
	}
}
