package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

func TestRootedCollectionReportKeepsInstructionLifecycleIndependent(t *testing.T) {
	collectorRoot := ingest.CollectorRootCoverageKey("config")
	deepRoot := ingest.CanonicalCoverageKey("config", "instruction-deep", "/home/op")
	deepChild := ingest.CanonicalCoverageKey("config", "instruction-source", deepRoot+"\x00/home/op/repo/AGENTS.md")
	cfgPath := ingest.CanonicalCoverageKey("config", "path", "/home/op/.cursor/mcp.json")
	contract := ingest.CurrentInstructionRegistryContract()

	report := &ingest.CollectionReport{
		State:        ingest.OutcomeTruncated,
		CoverageKeys: []string{cfgPath, deepRoot, deepChild},
		AuthoritativeRoots: []ingest.CoverageRoot{{
			CoverageKey:       deepRoot,
			ChildCoverageKeys: []string{deepChild},
			RegistryContract:  &contract,
		}},
		Outcomes: []ingest.CollectionOutcome{
			{Collector: "config", CoverageKey: cfgPath, Target: "/home/op/.cursor/mcp.json", Method: "config_discovery", State: ingest.OutcomeComplete},
			{Collector: "config", CoverageKey: deepChild, ParentCoverageKey: deepRoot, Target: "/home/op/repo/AGENTS.md", Method: ingest.InstructionMethodSource, State: ingest.OutcomeComplete},
			{Collector: "config", CoverageKey: deepRoot, Target: "/home/op", Method: ingest.InstructionMethodDeep, State: ingest.OutcomeTruncated},
		},
	}

	rooted := rootedCollectionReport("config", report, true)
	var rootState ingest.OutcomeState
	for _, outcome := range rooted.Outcomes {
		if outcome.CoverageKey == collectorRoot && outcome.Method == "collect" {
			rootState = outcome.State
		}
	}
	if rootState != ingest.OutcomeComplete {
		t.Fatalf("collector root state = %q, want config-only complete", rootState)
	}
	if rooted.State != ingest.OutcomeTruncated {
		t.Fatalf("report state = %q, want honest truncated", rooted.State)
	}
	for _, root := range rooted.AuthoritativeRoots {
		if root.CoverageKey != collectorRoot {
			continue
		}
		if containsCoverageKey(root.ChildCoverageKeys, deepRoot) || containsCoverageKey(root.ChildCoverageKeys, deepChild) {
			t.Fatalf("collector root captured independent instruction owners: %+v", root)
		}
		if !containsCoverageKey(root.ChildCoverageKeys, cfgPath) {
			t.Fatalf("collector root lost config child: %+v", root)
		}
	}
}

func containsCoverageKey(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestRootedCollectionReportPreservesOrdinaryPartialState(t *testing.T) {
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
	for _, outcome := range rooted.Outcomes {
		if outcome.CoverageKey == rootKey && outcome.Method == "collect" && outcome.State != ingest.OutcomePartial {
			t.Fatalf("collector root state = %q, want partial", outcome.State)
		}
	}
}

func TestResolveInstructionRecursion(t *testing.T) {
	if root, deep, err := resolveInstructionRecursion(false); err != nil || root != "" || deep {
		t.Fatalf("default resolution = (%q, %v, %v), want no deep root", root, deep, err)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("no home dir: %v", err)
	}
	want, err := filepath.Abs(home)
	if err != nil {
		t.Fatal(err)
	}
	root, deep, err := resolveInstructionRecursion(true)
	if err != nil {
		t.Fatal(err)
	}
	if root != filepath.Clean(want) || !deep {
		t.Fatalf("deep resolution = (%q, %v), want canonical home %q", root, deep, filepath.Clean(want))
	}
	if scanCmd.Flags().Lookup("deep-root") != nil {
		t.Fatal("removed --deep-root flag is still registered")
	}
}
