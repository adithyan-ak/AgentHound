package ingest

import "testing"

func TestBuildMCPIdentityAliasesQuarantinesAmbiguousLegacyID(t *testing.T) {
	legacy := ComputeLegacyMCPServerID("stdio", "node", "a.js", "b.js")
	nodes := []Node{
		stdioIdentityNode("node", []string{"a.js", "b.js"}, legacy),
		stdioIdentityNode("node", []string{"b.js", "a.js"}, legacy),
	}

	aliases := BuildMCPIdentityAliases(nodes, true)
	if len(aliases) != 1 || aliases[0].State != IdentityAliasAmbiguous {
		t.Fatalf("ambiguous v1 aggregate was not quarantined: %+v", aliases)
	}
	if len(aliases[0].CurrentIDs) != 2 || aliases[0].CurrentIDs[0] == aliases[0].CurrentIDs[1] {
		t.Fatalf("current candidates missing: %+v", aliases[0])
	}
}

func TestBuildMCPIdentityAliasesRequiresCompleteCoverage(t *testing.T) {
	legacy := ComputeLegacyMCPServerID("stdio", "npx", "pkg")
	node := stdioIdentityNode("npx", []string{"pkg"}, legacy)

	incomplete := BuildMCPIdentityAliases([]Node{node}, false)
	if len(incomplete) != 1 || incomplete[0].State != IdentityAliasUnresolved {
		t.Fatalf("incomplete coverage claimed an alias: %+v", incomplete)
	}
	complete := BuildMCPIdentityAliases([]Node{node}, true)
	if len(complete) != 1 || complete[0].State != IdentityAliasOneToOne {
		t.Fatalf("complete one-to-one alias not recognized: %+v", complete)
	}

	duplicateAcrossCollectors := BuildMCPIdentityAliases([]Node{node, node}, true)
	if len(duplicateAcrossCollectors) != 1 ||
		duplicateAcrossCollectors[0].State != IdentityAliasOneToOne ||
		len(duplicateAcrossCollectors[0].CurrentIDs) != 1 {
		t.Fatalf("same v2 identity from two collectors looked ambiguous: %+v", duplicateAcrossCollectors)
	}
}

func TestMergeCollectionReportsPreservesCompleteEmptyState(t *testing.T) {
	merged := MergeCollectionReports(&CollectionReport{
		State:        OutcomeComplete,
		CoverageKeys: []string{"config"},
		Outcomes:     []CollectionOutcome{},
	})

	if merged.State != OutcomeComplete {
		t.Fatalf("merged state = %q, want complete", merged.State)
	}
	if len(merged.Outcomes) != 0 {
		t.Fatalf("synthetic outcomes leaked into merged report: %+v", merged.Outcomes)
	}
}

func TestMergeCollectionReportsAggregatesReportStates(t *testing.T) {
	merged := MergeCollectionReports(
		&CollectionReport{
			State:        OutcomeComplete,
			CoverageKeys: []string{"mcp"},
		},
		&CollectionReport{
			State:        OutcomeFailed,
			CoverageKeys: []string{"a2a"},
			Outcomes: []CollectionOutcome{{
				Collector: "a2a",
				State:     OutcomeFailed,
			}},
		},
	)

	if merged.State != OutcomePartial {
		t.Fatalf("merged state = %q, want partial", merged.State)
	}
	if len(merged.CoverageKeys) != 2 ||
		merged.CoverageKeys[0] != "a2a" ||
		merged.CoverageKeys[1] != "mcp" {
		t.Fatalf("merged coverage keys = %v", merged.CoverageKeys)
	}
	if len(merged.Outcomes) != 1 {
		t.Fatalf("merged outcomes = %d, want 1", len(merged.Outcomes))
	}
}

func stdioIdentityNode(command string, args []string, legacy string) Node {
	id := ComputeMCPServerID("stdio", command, args...)
	return Node{
		ID:    id,
		Kinds: []string{"MCPServer"},
		Properties: map[string]any{
			"id_scheme":       MCPStdioIdentitySchemeV2,
			"legacy_objectid": legacy,
		},
	}
}
