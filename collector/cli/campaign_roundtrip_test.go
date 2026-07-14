package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/adithyan-ak/agenthound/sdk/campaign"
)

// fakeRoundtripScenario mirrors the mcp-poison-roundtrip contract at the CLI
// boundary: it requires no witness, reads its parameters from RunInput.Params,
// plans on dry-run, and returns a RoundtripReport on commit.
type fakeRoundtripScenario struct{}

func (f *fakeRoundtripScenario) ID() string                    { return "cli-roundtrip-fake" }
func (f *fakeRoundtripScenario) Version() int                  { return 1 }
func (f *fakeRoundtripScenario) Description() string           { return "fake round-trip" }
func (f *fakeRoundtripScenario) RequiresWitness() bool         { return false }
func (f *fakeRoundtripScenario) RequiresMutationConsent() bool { return true }
func (f *fakeRoundtripScenario) Run(_ context.Context, in campaign.RunInput) (*campaign.RunResult, error) {
	if strings.TrimSpace(in.Params["target-id"]) == "" || strings.TrimSpace(in.Params["inject"]) == "" {
		return nil, campaign.ErrNotRunnable
	}
	if !in.Commit {
		return &campaign.RunResult{DryRun: true, Plan: "ROUNDTRIP PLAN\n"}, nil
	}
	return &campaign.RunResult{Report: &campaign.RunReport{
		ReportVersion: campaign.RunReportVersion,
		ScenarioID:    "cli-roundtrip-fake", ScenarioVersion: 1,
		CampaignRunID: "run-fake", EngagementID: in.EngagementID,
		Standalone: true, MutationTargetID: in.Params["target-id"],
		TargetRef: "https://mcp.example/mcp",
		Steps:     []campaign.StepObservation{},
		Oracle: campaign.OracleReport{
			Type:    campaign.OracleTypeReversibleMutationRoundtrip,
			Outcome: string(campaign.OracleMutationVerified),
		},
		Cleanup: campaign.CleanupReport{Status: campaign.CleanupRestored, Postcondition: "original_confirmed", ReceiptRetained: true},
	}}, nil
}

var fakeRoundtripScenarioRegistered = func() bool {
	campaign.Register(&fakeRoundtripScenario{})
	return true
}()

// newCampaignRoundtripTestCmd builds a campaign test command with the full flag
// set, including the mcp-poison-roundtrip mutation flags.
func newCampaignRoundtripTestCmd(t *testing.T, out *bytes.Buffer) *cobra.Command {
	t.Helper()
	root := &cobra.Command{Use: "agenthound"}
	root.PersistentFlags().String("output", "-", "")
	cmd := &cobra.Command{Use: "campaign"}
	cmd.Flags().String("scenario", "", "")
	cmd.Flags().String("witness", "", "")
	cmd.Flags().String("engagement-id", "", "")
	cmd.Flags().Bool("commit", false, "")
	cmd.Flags().Bool("insecure", false, "")
	cmd.Flags().Duration("timeout", 0, "")
	cmd.Flags().String("credential-env", defaultCredentialEnv, "")
	cmd.Flags().Bool("credential-stdin", false, "")
	cmd.Flags().String("target-id", "", "")
	cmd.Flags().String("inject", "", "")
	cmd.Flags().String("mode", "", "")
	cmd.Flags().String("update-method", "", "")
	cmd.Flags().String("update-path", "", "")
	cmd.Flags().String("list-path", "", "")
	cmd.Flags().String("auth-token", "", "")
	root.AddCommand(cmd)
	cmd.SetIn(strings.NewReader(""))
	cmd.SetOut(out)
	cmd.SetErr(out)
	return cmd
}

// TestRunCampaignRoundtripNeedsNoWitness: a RequiresWitness()=false scenario runs
// from --target-id/--inject with NO witness and reports oracle + cleanup
// separately, without writing a differential envelope.
func TestRunCampaignRoundtripCommit(t *testing.T) {
	_ = fakeRoundtripScenarioRegistered
	writeCampaignSentinelForTest(t)
	writePoisonSentinelForTest(t)

	out := &bytes.Buffer{}
	cmd := newCampaignRoundtripTestCmd(t, out)
	mustSetFlag(t, cmd, "scenario", "cli-roundtrip-fake")
	mustSetFlag(t, cmd, "engagement-id", "ENG-RT")
	mustSetFlag(t, cmd, "target-id", "support_lookup")
	mustSetFlag(t, cmd, "inject", "TEST MUTATION")
	mustSetFlag(t, cmd, "commit", "true")

	if err := runCampaign(cmd, []string{"https://mcp.example/mcp"}); err != nil {
		t.Fatalf("runCampaign round-trip commit: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "STANDALONE target-mutation validation") {
		t.Fatalf("expected standalone banner, got: %s", got)
	}
	if !strings.Contains(got, "oracle=mutation_verified") || !strings.Contains(got, "cleanup=restored") {
		t.Fatalf("expected separate oracle + cleanup outcomes, got: %s", got)
	}
}

// TestRunCampaignRoundtripDryRun: dry-run plans only for the non-witness path.
func TestRunCampaignRoundtripDryRun(t *testing.T) {
	_ = fakeRoundtripScenarioRegistered
	writeCampaignSentinelForTest(t)

	out := &bytes.Buffer{}
	cmd := newCampaignRoundtripTestCmd(t, out)
	mustSetFlag(t, cmd, "scenario", "cli-roundtrip-fake")
	mustSetFlag(t, cmd, "engagement-id", "ENG-RT")
	mustSetFlag(t, cmd, "target-id", "support_lookup")
	mustSetFlag(t, cmd, "inject", "TEST MUTATION")

	if err := runCampaign(cmd, []string{"https://mcp.example/mcp"}); err != nil {
		t.Fatalf("runCampaign round-trip dry-run: %v", err)
	}
	if !strings.Contains(out.String(), "DRY-RUN") || !strings.Contains(out.String(), "ROUNDTRIP PLAN") {
		t.Fatalf("expected dry-run plan, got: %s", out.String())
	}
}

func TestRunCampaignRoundtripRequiresDistinctMutationConsent(t *testing.T) {
	_ = fakeRoundtripScenarioRegistered
	writeCampaignSentinelForTest(t)
	out := &bytes.Buffer{}
	cmd := newCampaignRoundtripTestCmd(t, out)
	mustSetFlag(t, cmd, "scenario", "cli-roundtrip-fake")
	mustSetFlag(t, cmd, "engagement-id", "ENG-CONSENT")
	mustSetFlag(t, cmd, "target-id", "support_lookup")
	mustSetFlag(t, cmd, "inject", "not-run")
	mustSetFlag(t, cmd, "commit", "true")

	err := runCampaign(cmd, []string{"https://mcp.example/mcp"})
	if err == nil || !strings.Contains(err.Error(), "destructive acknowledgement") {
		t.Fatalf("missing poison consent error = %v", err)
	}
}

// TestRunCampaignRoundtripMissingParams: a non-witness scenario with missing
// mutation params surfaces the scenario's not-runnable precondition, not a
// witness error.
func TestRunCampaignRoundtripMissingParams(t *testing.T) {
	_ = fakeRoundtripScenarioRegistered
	writeCampaignSentinelForTest(t)

	out := &bytes.Buffer{}
	cmd := newCampaignRoundtripTestCmd(t, out)
	mustSetFlag(t, cmd, "scenario", "cli-roundtrip-fake")
	mustSetFlag(t, cmd, "engagement-id", "ENG-RT")
	mustSetFlag(t, cmd, "commit", "true")

	err := runCampaign(cmd, []string{"https://mcp.example/mcp"})
	if err == nil {
		t.Fatal("expected a precondition error for missing mutation params")
	}
	if strings.Contains(err.Error(), "witness") {
		t.Fatalf("non-witness scenario must not fail on witness, got: %v", err)
	}
}

func writePoisonSentinelForTest(t *testing.T) {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(home, ".agenthound")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "poison-acknowledged"), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
}

type unsafeRoundtripScenario struct{}

func (*unsafeRoundtripScenario) ID() string                    { return "cli-roundtrip-unsafe-fake" }
func (*unsafeRoundtripScenario) Version() int                  { return 1 }
func (*unsafeRoundtripScenario) Description() string           { return "unsafe fake" }
func (*unsafeRoundtripScenario) RequiresWitness() bool         { return false }
func (*unsafeRoundtripScenario) RequiresMutationConsent() bool { return true }
func (*unsafeRoundtripScenario) Run(_ context.Context, in campaign.RunInput) (*campaign.RunResult, error) {
	return &campaign.RunResult{Report: &campaign.RunReport{
		ReportVersion: campaign.RunReportVersion,
		ScenarioID:    "cli-roundtrip-unsafe-fake", ScenarioVersion: 1,
		CampaignRunID: "run-unsafe", EngagementID: in.EngagementID,
		Standalone: true, TargetRef: "https://mcp.example/mcp",
		Steps:   []campaign.StepObservation{},
		Oracle:  campaign.OracleReport{Type: campaign.OracleTypeReversibleMutationRoundtrip, Outcome: string(campaign.OracleMutationVerified)},
		Cleanup: campaign.CleanupReport{Status: campaign.CleanupConflict, Postcondition: "unconfirmed", ReceiptRetained: true},
	}}, campaign.ErrUnsafeCleanup
}

var unsafeRoundtripScenarioRegistered = func() bool {
	campaign.Register(&unsafeRoundtripScenario{})
	return true
}()

func TestRunCampaignEmitsUnsafeReportBeforeError(t *testing.T) {
	_ = unsafeRoundtripScenarioRegistered
	writeCampaignSentinelForTest(t)
	writePoisonSentinelForTest(t)
	out := &bytes.Buffer{}
	cmd := newCampaignRoundtripTestCmd(t, out)
	mustSetFlag(t, cmd, "scenario", "cli-roundtrip-unsafe-fake")
	mustSetFlag(t, cmd, "engagement-id", "ENG-UNSAFE")
	mustSetFlag(t, cmd, "target-id", "support_lookup")
	mustSetFlag(t, cmd, "inject", "not-reported")
	mustSetFlag(t, cmd, "commit", "true")

	err := runCampaign(cmd, []string{"https://mcp.example/mcp"})
	if !errors.Is(err, campaign.ErrUnsafeCleanup) {
		t.Fatalf("error = %v, want unsafe cleanup", err)
	}
	output := out.String()
	if !strings.Contains(output, "RUN_REPORT") ||
		!strings.Contains(output, `"status":"conflict"`) {
		t.Fatalf("unsafe final report was not emitted: %s", output)
	}
	if strings.Contains(output, "not-reported") {
		t.Fatal("mutation value leaked into report/diagnostic")
	}
}
