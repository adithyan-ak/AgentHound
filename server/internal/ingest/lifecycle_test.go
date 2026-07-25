package ingest

import (
	"strings"
	"testing"

	sdkingest "github.com/adithyan-ak/agenthound/sdk/ingest"
)

func TestComparisonKeyRequiresCompleteKnownInputs(t *testing.T) {
	mcpScope := sdkingest.CanonicalCoverageKey("mcp", "target", "https://mcp.example")
	configScope := sdkingest.CanonicalCoverageKey("config", "path", "/tmp/config.json")
	data := &sdkingest.IngestData{
		Meta: sdkingest.IngestMeta{
			Collection: &sdkingest.CollectionReport{
				State:        sdkingest.OutcomeComplete,
				CoverageKeys: []string{mcpScope, configScope},
				Outcomes: []sdkingest.CollectionOutcome{
					{Collector: "mcp", CoverageKey: mcpScope, State: sdkingest.OutcomeComplete},
					{Collector: "config", CoverageKey: configScope, State: sdkingest.OutcomeComplete},
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
		collector := strings.SplitN(scope, ":", 2)[0]
		return &sdkingest.IngestData{
			Meta: sdkingest.IngestMeta{
				Collection: &sdkingest.CollectionReport{
					State:        sdkingest.OutcomeComplete,
					CoverageKeys: []string{scope},
					Outcomes: []sdkingest.CollectionOutcome{{
						Collector:   collector,
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

func TestPromotableAuthoritativeRootsAcceptsRecognizedIncompleteInstructionRoots(t *testing.T) {
	exactRoot := sdkingest.CanonicalCoverageKey("config", "instruction-exact-user", "/home/op")
	exactChild := sdkingest.CanonicalCoverageKey("config", "instruction-source", exactRoot+"\x00AGENTS.md")
	contract := sdkingest.CurrentInstructionRegistryContract()
	for _, state := range []sdkingest.OutcomeState{
		sdkingest.OutcomeTruncated,
		sdkingest.OutcomePartial,
		sdkingest.OutcomeFailed,
	} {
		t.Run(string(state), func(t *testing.T) {
			report := &sdkingest.CollectionReport{
				State:        state,
				CoverageKeys: []string{exactRoot, exactChild},
				AuthoritativeRoots: []sdkingest.CoverageRoot{{
					CoverageKey:       exactRoot,
					ChildCoverageKeys: []string{exactChild},
					RegistryContract:  &contract,
				}},
				Outcomes: []sdkingest.CollectionOutcome{
					{
						Collector:   "config",
						CoverageKey: exactRoot,
						Method:      sdkingest.InstructionMethodExactUser,
						State:       state,
					},
					{
						Collector:         "config",
						CoverageKey:       exactChild,
						ParentCoverageKey: exactRoot,
						Method:            sdkingest.InstructionMethodSource,
						State:             sdkingest.OutcomeComplete,
					},
				},
			}
			roots := promotableAuthoritativeRoots(report)
			if len(roots) != 1 || roots[0].CoverageKey != exactRoot {
				t.Fatalf("promotable roots = %+v, want limited exact root", roots)
			}
			if got := sdkingest.CompleteAuthoritativeRoots(report); len(got) != 0 {
				t.Fatalf("limited root became authoritative: %+v", got)
			}
		})
	}

	nonInstructionRoot := sdkingest.CollectorRootCoverageKey("mcp")
	report := &sdkingest.CollectionReport{
		State:        sdkingest.OutcomePartial,
		CoverageKeys: []string{nonInstructionRoot},
		AuthoritativeRoots: []sdkingest.CoverageRoot{{
			CoverageKey: nonInstructionRoot,
		}},
		Outcomes: []sdkingest.CollectionOutcome{{
			Collector: "mcp", CoverageKey: nonInstructionRoot,
			Method: "collect", State: sdkingest.OutcomePartial,
		}},
	}
	if roots := promotableAuthoritativeRoots(report); len(roots) != 0 {
		t.Fatalf("incomplete non-instruction root promoted: %+v", roots)
	}
}

func TestComparisonKeyRejectsEveryIncompleteInstructionRoot(t *testing.T) {
	exactRoot := sdkingest.CanonicalCoverageKey("config", "instruction-exact-user", "/home/op")
	contract := sdkingest.CurrentInstructionRegistryContract()
	data := &sdkingest.IngestData{
		Meta: sdkingest.IngestMeta{
			Collection: &sdkingest.CollectionReport{
				State:        sdkingest.OutcomePartial,
				CoverageKeys: []string{exactRoot},
				AuthoritativeRoots: []sdkingest.CoverageRoot{{
					CoverageKey: exactRoot, RegistryContract: &contract,
				}},
				Outcomes: []sdkingest.CollectionOutcome{
					{
						Collector:   "config",
						CoverageKey: exactRoot,
						Method:      sdkingest.InstructionMethodExactUser,
						State:       sdkingest.OutcomeFailed,
					},
				},
			},
			Ruleset: &sdkingest.RulesetManifest{
				Digest:    "sha256:rules",
				LoadState: sdkingest.OutcomeComplete,
			},
			IdentitySchemes: []sdkingest.IdentityScheme{{
				EntityKind: "InstructionFile",
				Scheme:     "path_v1",
				Version:    1,
			}},
		},
	}
	if got := comparisonKey(data, true); got != "" {
		t.Fatalf("failed exact root comparison key = %q, want empty", got)
	}

	data.Meta.Collection.Outcomes[0].State = sdkingest.OutcomeComplete
	data.Meta.Collection.State = sdkingest.OutcomeComplete
	if got := comparisonKey(data, true); got == "" {
		t.Fatal("complete exact root did not produce a comparison key")
	}
}
