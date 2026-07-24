package cli

import (
	"os"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

// A truncated best-effort (--deep) instruction outcome must not taint the
// collect root's authoritative coverage state, or AuthoritativeCoverageComplete
// fails on the root and withholds publication — defeating the advisory contract.
// The report-level State must stay honestly truncated for collection_status.
func TestRootedCollectionReportAdvisoryDoesNotTaintRoot(t *testing.T) {
	rootKey := ingest.CollectorRootCoverageKey("config")
	advisory := ingest.CanonicalCoverageKey("config", "instruction-traversal", "/home/op")
	cfgPath := ingest.CanonicalCoverageKey("config", "path", "/home/op/.cursor/mcp.json")

	report := &ingest.CollectionReport{
		State:        ingest.OutcomeTruncated,
		CoverageKeys: []string{cfgPath, advisory},
		Outcomes: []ingest.CollectionOutcome{
			{Collector: "config", CoverageKey: cfgPath, Target: "/home/op/.cursor/mcp.json", Method: "config_discovery", State: ingest.OutcomeComplete},
			{Collector: "config", CoverageKey: advisory, Target: "/home/op", Method: "cursor_rule_traversal", State: ingest.OutcomeTruncated, Advisory: true},
		},
	}

	rooted := rootedCollectionReport("config", report, true)

	var rootState ingest.OutcomeState
	found := false
	for _, oc := range rooted.Outcomes {
		if oc.CoverageKey == rootKey && oc.Method == "collect" {
			rootState = oc.State
			found = true
		}
	}
	if !found {
		t.Fatal("no collect root outcome produced")
	}
	if rootState != ingest.OutcomeComplete {
		t.Fatalf("collect root state = %q, want complete (advisory truncation must not taint the authoritative root)", rootState)
	}
	if rooted.State != ingest.OutcomeTruncated {
		t.Fatalf("report state = %q, want truncated (collection_status must stay honest)", rooted.State)
	}
}

// Without advisory outcomes, the authoritative report State is preserved verbatim.
func TestRootedCollectionReportPreservesNonAdvisoryState(t *testing.T) {
	cfgPath := ingest.CanonicalCoverageKey("config", "path", "/home/op/.cursor/mcp.json")
	report := &ingest.CollectionReport{
		State:        ingest.OutcomePartial,
		CoverageKeys: []string{cfgPath},
		Outcomes: []ingest.CollectionOutcome{
			{Collector: "config", CoverageKey: cfgPath, Target: "/home/op/.cursor/mcp.json", Method: "config_discovery", State: ingest.OutcomePartial},
		},
	}
	rooted := rootedCollectionReport("config", report, true)
	rootKey := ingest.CollectorRootCoverageKey("config")
	for _, oc := range rooted.Outcomes {
		if oc.CoverageKey == rootKey && oc.Method == "collect" && oc.State != ingest.OutcomePartial {
			t.Fatalf("collect root state = %q, want partial preserved", oc.State)
		}
	}
}

func TestResolveInstructionRecursion(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("no home dir: %v", err)
	}

	tests := []struct {
		name              string
		projectDir        string
		projectDirChanged bool
		deep              bool
		deepRoot          string
		wantRoot          string
		wantDeep          bool
	}{
		{name: "default host scan does not recurse"},
		{
			name:              "project-dir is a strict root",
			projectDir:        "/repo",
			projectDirChanged: true,
			wantRoot:          "/repo",
		},
		{
			name:     "deep defaults to home",
			deep:     true,
			wantRoot: home,
			wantDeep: true,
		},
		{
			name:     "deep-root overrides",
			deep:     true,
			deepRoot: "/srv/other",
			wantRoot: "/srv/other",
			wantDeep: true,
		},
		{
			name:              "deep wins over project-dir",
			projectDir:        "/repo",
			projectDirChanged: true,
			deep:              true,
			wantRoot:          home,
			wantDeep:          true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root, isDeep, err := resolveInstructionRecursion(tc.projectDir, tc.projectDirChanged, tc.deep, tc.deepRoot)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if root != tc.wantRoot || isDeep != tc.wantDeep {
				t.Fatalf("resolveInstructionRecursion = (%q, %v), want (%q, %v)", root, isDeep, tc.wantRoot, tc.wantDeep)
			}
		})
	}
}
