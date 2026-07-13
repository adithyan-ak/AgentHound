package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/adithyan-ak/agenthound/sdk/campaign"
)

// fakeRoundtripScenario mirrors the mcp-poison-roundtrip contract at the CLI
// boundary: it requires no witness, reads its parameters from RunInput.Params,
// plans on dry-run, and returns a RoundtripReport on commit.
type fakeRoundtripScenario struct{}

func (f *fakeRoundtripScenario) ID() string            { return "cli-roundtrip-fake" }
func (f *fakeRoundtripScenario) Version() int          { return 1 }
func (f *fakeRoundtripScenario) Description() string   { return "fake round-trip" }
func (f *fakeRoundtripScenario) RequiresWitness() bool { return false }
func (f *fakeRoundtripScenario) Run(_ context.Context, in campaign.RunInput) (*campaign.RunResult, error) {
	if strings.TrimSpace(in.Params["target-id"]) == "" || strings.TrimSpace(in.Params["inject"]) == "" {
		return nil, campaign.ErrNotRunnable
	}
	if !in.Commit {
		return &campaign.RunResult{DryRun: true, Plan: "ROUNDTRIP PLAN\n"}, nil
	}
	return &campaign.RunResult{Roundtrip: &campaign.RoundtripReport{
		ScenarioID:   "cli-roundtrip-fake",
		EngagementID: in.EngagementID,
		OracleType:   campaign.OracleTypeReversibleMutationRoundtrip,
		Standalone:   true,
		TargetID:     in.Params["target-id"],
		Oracle:       campaign.OracleMutationVerified,
		Cleanup:      campaign.CleanupRestored,
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
