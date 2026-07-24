package ingest

import (
	"reflect"
	"testing"
)

func TestAdvisoryCoverageDomains(t *testing.T) {
	root := CollectorRootCoverageKey("config")
	advisory := CanonicalCoverageKey("config", "instruction-traversal", "/home/op")
	mixed := CanonicalCoverageKey("config", "instruction-tree", "/home/op/.cursor/rules")

	report := &CollectionReport{
		CoverageKeys: []string{root, advisory, mixed},
		Outcomes: []CollectionOutcome{
			{Collector: "config", CoverageKey: root, State: OutcomeComplete},
			{Collector: "config", CoverageKey: advisory, State: OutcomeTruncated, Advisory: true},
			// A key with one advisory and one non-advisory outcome is NOT advisory.
			{Collector: "config", CoverageKey: mixed, State: OutcomeComplete, Advisory: true},
			{Collector: "config", CoverageKey: mixed, State: OutcomeComplete},
		},
	}

	got := AdvisoryCoverageDomains(report)
	if want := []string{advisory}; !reflect.DeepEqual(got, want) {
		t.Fatalf("AdvisoryCoverageDomains = %v, want %v", got, want)
	}
}

func TestAuthoritativeCoverageComplete(t *testing.T) {
	root := CollectorRootCoverageKey("config")
	advisory := CanonicalCoverageKey("config", "instruction-traversal", "/home/op")

	// Root complete, advisory truncated -> authoritative coverage is complete
	// (the truncated best-effort key is ignored) even though the strict check fails.
	report := &CollectionReport{
		CoverageKeys: []string{root, advisory},
		Outcomes: []CollectionOutcome{
			{Collector: "config", CoverageKey: root, State: OutcomeComplete},
			{Collector: "config", CoverageKey: advisory, State: OutcomeTruncated, Advisory: true},
		},
	}
	if !AuthoritativeCoverageComplete(report) {
		t.Fatal("advisory truncation must not fail authoritative completeness")
	}
	if CollectionCoverageComplete(report) {
		t.Fatal("strict completeness must still fail on the truncated key")
	}

	// A truncated NON-advisory key blocks authoritative completeness.
	report.Outcomes[1].Advisory = false
	if AuthoritativeCoverageComplete(report) {
		t.Fatal("non-advisory truncation must fail authoritative completeness")
	}
}
