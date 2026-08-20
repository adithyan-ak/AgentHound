package cli

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/common"
	"github.com/adithyan-ak/agenthound/sdk/contact"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/spf13/cobra"
)

func TestConfiguredMCPURLSeedsHostDiscovery(t *testing.T) {
	for _, test := range []struct {
		raw  string
		want string
		ok   bool
	}{
		{raw: "https://mcp.example:9443/mcp", want: "mcp.example", ok: true},
		{raw: "http://[2001:db8::1]:8080/mcp", want: "2001:db8::1", ok: true},
		{raw: "stdio://local", ok: false},
		{raw: "not a URL", ok: false},
	} {
		got, ok := configuredNetworkSeed(test.raw)
		if got != test.want || ok != test.ok {
			t.Fatalf("configuredNetworkSeed(%q) = (%q, %t), want (%q, %t)", test.raw, got, ok, test.want, test.ok)
		}
	}
}

func TestProtocolDiscoveryRetainsBothProtocolsAtSameEndpoint(t *testing.T) {
	runtime := &scanRuntime{
		artifact: &ingest.IngestData{},
		rootKey:  ingest.CollectorRootCoverageKey("scan"),
	}
	base := "http://127.0.0.1:8080"
	runtime.recordProtocolDiscoveries([]action.Target{
		{Kind: "host", Address: "127.0.0.1:8080", Meta: map[string]string{
			"protocol": "a2a", "url": base,
			"agent_card_url": base + "/.well-known/agent-card.json",
		}},
		{Kind: "host", Address: "127.0.0.1:8080", Meta: map[string]string{
			"protocol": "mcp", "url": base,
		}},
	})
	if len(runtime.targets) != 2 {
		t.Fatalf("targets = %+v, want both MCP and A2A", runtime.targets)
	}
	if len(runtime.artifact.Graph.Nodes) != 2 {
		t.Fatalf("discovery nodes = %+v, want both positive observations", runtime.artifact.Graph.Nodes)
	}
	for _, node := range runtime.artifact.Graph.Nodes {
		if len(node.ObservationDomains) != 1 || node.ObservationDomains[0] != runtime.rootKey {
			t.Fatalf("node %q domains = %v, want scan root", node.ID, node.ObservationDomains)
		}
	}
}

func TestPersistedExclusionsRebuildRecoveryContactPolicy(t *testing.T) {
	execution := ingest.NewScanExecution(ingest.ScanModeActive, false, time.Now())
	execution.Exclusions = []string{"blocked.example", "10.20.0.0/16"}
	policy, err := contact.NewPolicy(execution.Exclusions)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"BLOCKED.EXAMPLE.", "10.20.3.4"} {
		if err := policy.AdmitAddress(target); !errors.Is(err, contact.ErrExcluded) {
			t.Fatalf("recovery policy admitted %q: %v", target, err)
		}
	}
}

func TestNormalizedExclusionsAreStableAndDeduplicated(t *testing.T) {
	got := normalizedExclusions([]string{
		" Blocked.Example. ", "blocked.example", "10.20.3.9/16", "[2001:0db8::1]",
	})
	want := []string{"10.20.0.0/16", "2001:db8::1", "blocked.example"}
	if len(got) != len(want) {
		t.Fatalf("normalized exclusions = %v, want %v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("normalized exclusions = %v, want %v", got, want)
		}
	}
}

func TestExcludedDiscoveryIsNotACollectionFailure(t *testing.T) {
	runtime := &scanRuntime{
		artifact: &ingest.IngestData{Meta: ingest.IngestMeta{Collection: &ingest.CollectionReport{}}},
		rootKey:  ingest.CollectorRootCoverageKey("scan"),
	}
	runtime.recordExcludedDiscovery("127.0.0.1")
	if len(runtime.artifact.Meta.Collection.Outcomes) != 2 {
		t.Fatalf("excluded outcomes = %+v, want port and protocol skips", runtime.artifact.Meta.Collection.Outcomes)
	}
	for _, outcome := range runtime.artifact.Meta.Collection.Outcomes {
		if outcome.State != ingest.OutcomeNotApplicable || outcome.Error != "skipped by --exclude" {
			t.Fatalf("excluded outcome = %+v, want not_applicable", outcome)
		}
	}
	if runtime.artifact.Meta.Collection.State != ingest.OutcomeComplete {
		t.Fatalf("collection state = %q, want complete for exclusions only", runtime.artifact.Meta.Collection.State)
	}
}

func TestOnlyDirectDiscoverySpecsArePreAdmitted(t *testing.T) {
	for _, test := range []struct {
		spec string
		want bool
	}{
		{spec: "127.0.0.1", want: true},
		{spec: "service.internal", want: true},
		{spec: "10.20.0.0/24", want: false},
		{spec: "@targets.txt", want: false},
		{spec: "file:///tmp/targets.txt", want: false},
	} {
		if got := isDirectDiscoverySpec(test.spec); got != test.want {
			t.Fatalf("isDirectDiscoverySpec(%q) = %t, want %t", test.spec, got, test.want)
		}
	}
}

func TestExplicitMissingTargetsFileFailsFinalExecution(t *testing.T) {
	rootKey := ingest.CollectorRootCoverageKey("scan")
	artifact := common.NewIngestData("scan", "explicit-target-rejection")
	artifact.Meta.Collection = &ingest.CollectionReport{
		State: ingest.OutcomePartial, CoverageKeys: []string{rootKey},
		Outcomes: []ingest.CollectionOutcome{{
			Collector: "scan", CoverageKey: rootKey, Target: "scan",
			Method: "autonomous_scan", State: ingest.OutcomePartial,
		}},
	}
	policy, err := contact.NewPolicy(nil)
	if err != nil {
		t.Fatal(err)
	}
	execution := ingest.NewScanExecution(ingest.ScanModeActive, false, time.Now())
	runtime := &scanRuntime{
		cmd: &cobra.Command{}, ctx: context.Background(), policy: policy,
		artifact: artifact, execution: execution, rootKey: rootKey,
		output: filepath.Join(t.TempDir(), "failed.json"), quiet: true,
	}
	missing := "@" + filepath.Join(t.TempDir(), "missing-targets.txt")
	runErr := runtime.preflightExplicitTarget([]string{missing})
	if runErr == nil || !strings.Contains(runErr.Error(), "explicit target") {
		t.Fatalf("preflight error = %v, want explicit target rejection", runErr)
	}
	if runtime.explicitSpec != missing {
		t.Fatalf("preflight cached spec = %q, want %q", runtime.explicitSpec, missing)
	}
	foundValidationFailure := false
	for _, outcome := range artifact.Meta.Collection.Outcomes {
		if outcome.Target == missing && outcome.Method == "target_validation" && outcome.State == ingest.OutcomeFailed {
			foundValidationFailure = true
		}
	}
	if !foundValidationFailure {
		t.Fatalf("outcomes = %+v, want failed target_validation outcome", artifact.Meta.Collection.Outcomes)
	}
	if err := runtime.finish(runErr); err == nil {
		t.Fatal("finish accepted rejected explicit target")
	}
	if execution.Status != ingest.ScanExecutionFailed {
		t.Fatalf("execution status = %q, want failed", execution.Status)
	}
}

func TestRunScanPreflightsExplicitTargetBeforeExpiredDeadline(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	output := filepath.Join(t.TempDir(), "failed.json")
	missing := "@" + filepath.Join(t.TempDir(), "missing-targets.txt")
	cmd := &cobra.Command{}
	cmd.Flags().Bool("deep", false, "")
	cmd.Flags().Bool("stealth", false, "")
	cmd.Flags().Duration("timeout", time.Nanosecond, "")
	cmd.Flags().StringSlice("exclude", nil, "")
	cmd.Flags().Bool("insecure", false, "")
	cmd.Flags().String("output", output, "")
	cmd.Flags().Bool("quiet", true, "")

	runErr := runScan(cmd, []string{missing})
	if runErr == nil || !strings.Contains(runErr.Error(), "explicit target") {
		t.Fatalf("runScan error = %v, want explicit target rejection", runErr)
	}
	document, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var artifact ingest.IngestData
	if err := json.Unmarshal(document, &artifact); err != nil {
		t.Fatal(err)
	}
	execution, present, err := ingest.GetScanExecution(artifact.Meta)
	if err != nil || !present {
		t.Fatalf("scan execution = (%+v, %t, %v)", execution, present, err)
	}
	if execution.Status != ingest.ScanExecutionFailed {
		t.Fatalf("execution status = %q, want failed", execution.Status)
	}
}
