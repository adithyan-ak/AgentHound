package ingest

import "testing"

func TestMergeCollectionReportsPreservesCompleteEmptyState(t *testing.T) {
	scope := CanonicalCoverageKey("config", "path", "/tmp/missing.json")
	merged := MergeCollectionReports(&CollectionReport{
		State:        OutcomeComplete,
		CoverageKeys: []string{scope},
		Outcomes: []CollectionOutcome{{
			Collector:   "config",
			CoverageKey: scope,
			Target:      "/tmp/missing.json",
			Method:      "config_discovery",
			State:       OutcomeComplete,
			Items:       0,
		}},
	})

	if merged.State != OutcomeComplete {
		t.Fatalf("merged state = %q, want complete", merged.State)
	}
	if len(merged.Outcomes) != 1 {
		t.Fatalf("explicit complete-empty outcome was lost: %+v", merged.Outcomes)
	}
}

func TestMergeCollectionReportsAggregatesReportStates(t *testing.T) {
	mcpScope := CanonicalCoverageKey("mcp", "target", "https://mcp.example")
	a2aScope := CanonicalCoverageKey("a2a", "target", "https://a2a.example")
	merged := MergeCollectionReports(
		&CollectionReport{
			State:        OutcomeComplete,
			CoverageKeys: []string{mcpScope},
			Outcomes: []CollectionOutcome{{
				Collector:   "mcp",
				CoverageKey: mcpScope,
				Target:      "https://mcp.example",
				Method:      "enumerate",
				State:       OutcomeComplete,
			}},
		},
		&CollectionReport{
			State:        OutcomeFailed,
			CoverageKeys: []string{a2aScope},
			Outcomes: []CollectionOutcome{{
				Collector:   "a2a",
				CoverageKey: a2aScope,
				Target:      "https://a2a.example",
				Method:      "agent_card",
				State:       OutcomeFailed,
			}},
		},
	)

	if merged.State != OutcomePartial {
		t.Fatalf("merged state = %q, want partial", merged.State)
	}
	if len(merged.CoverageKeys) != 2 ||
		merged.CoverageKeys[0] != a2aScope ||
		merged.CoverageKeys[1] != mcpScope {
		t.Fatalf("merged coverage keys = %v", merged.CoverageKeys)
	}
	if len(merged.Outcomes) != 2 {
		t.Fatalf("merged outcomes = %d, want 2", len(merged.Outcomes))
	}
}

func TestMergeCollectionReportsPreservesAuthoritativeActiveSet(t *testing.T) {
	root := CanonicalCoverageKey("mcp", "root", "collect")
	child := CanonicalCoverageKey("mcp", "target", "https://mcp.example")
	merged := MergeCollectionReports(&CollectionReport{
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
	})

	if len(merged.AuthoritativeRoots) != 1 ||
		merged.AuthoritativeRoots[0].CoverageKey != root ||
		len(merged.AuthoritativeRoots[0].ChildCoverageKeys) != 1 ||
		merged.AuthoritativeRoots[0].ChildCoverageKeys[0] != child {
		t.Fatalf("merged authoritative roots = %+v", merged.AuthoritativeRoots)
	}
}
