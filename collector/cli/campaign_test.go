package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/adithyan-ak/agenthound/sdk/campaign"
	"github.com/adithyan-ak/agenthound/sdk/common"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

const (
	campTestServerID = "sha256:camp-server"
	campTestAgentID  = "sha256:camp-agent"
	campTestCredID   = "sha256:camp-credential"
	campTestResURI   = "postgres://prod/customers"
	campTestMaterial = "sk-campaign-secret"
)

func campTestWitness() campaign.Witness {
	resID := ingest.ComputeNodeID("MCPResource", campTestServerID, campTestResURI)
	return campaign.Witness{
		SchemaVersion:                campaign.WitnessSchemaVersion,
		TopologyNormalizationVersion: campaign.WitnessTopologyNormalizationVersion,
		PublicationRevision:          3,
		PredictedEdgeKind:            campaign.PredictedEdgeKindCanReach,
		AgentID:                      campTestAgentID,
		AgentKind:                    "AgentInstance",
		CredentialID:                 campTestCredID,
		CredentialKind:               "Credential",
		CredentialValueHash:          common.HashCredentialValue(campTestMaterial),
		CredentialMergeKey:           campaign.CredentialMergeKeyValueHash,
		ServerID:                     campTestServerID,
		ServerKind:                   "MCPServer",
		ResourceID:                   resID,
		ResourceKind:                 "MCPResource",
		ResourceIdentityInput:        campTestResURI,
		EvidenceNodeIDs:              []string{campTestAgentID, campTestServerID, campTestCredID, resID},
		EvidenceNodeKinds:            []string{"AgentInstance", "MCPServer", "Credential", "MCPResource"},
	}
}

func campTestEvidence(outcome campaign.Outcome) *campaign.Evidence {
	return &campaign.Evidence{
		ScenarioID:       "cred-reach",
		ScenarioVersion:  1,
		RunID:            "run-abc",
		EngagementID:     "ENG-CAMP",
		OracleType:       campaign.OracleTypeDifferentialCredentialReach,
		Outcome:          outcome,
		ControlStage:     campaign.ProbeStageResourceRead,
		ControlStatus:    campaign.ProbeDenied,
		ControlAddressed: true,
		AuthedStage:      campaign.ProbeStageResourceRead,
		AuthedStatus:     campaign.ProbeAllowed,
		AuthedAddressed:  true,
		VerifiedAt:       "2026-07-12T00:00:00Z",
		Witness:          campTestWitness(),
	}
}

func TestBuildCampaignEnvelopeVerified(t *testing.T) {
	env := buildCampaignEnvelope("cred-reach", 1, "ENG-CAMP", campTestEvidence(campaign.OutcomeCredentialGatedReachVerified))
	if env.Meta.Collector != "scan" {
		t.Fatalf("collector = %q, want scan", env.Meta.Collector)
	}
	if env.Meta.Collection.State != ingest.OutcomeComplete {
		t.Fatalf("state = %q, want complete", env.Meta.Collection.State)
	}
	if len(env.Graph.Nodes) != 2 || len(env.Graph.Edges) != 1 {
		t.Fatalf("graph = %d nodes / %d edges, want 2 / 1", len(env.Graph.Nodes), len(env.Graph.Edges))
	}
	if env.Graph.Edges[0].Kind != "CREDENTIAL_REACH_VERIFIED" {
		t.Fatalf("edge kind = %q", env.Graph.Edges[0].Kind)
	}
	// Every fact must be tagged with the deterministic coverage key.
	key := env.Meta.Collection.CoverageKeys[0]
	for _, n := range env.Graph.Nodes {
		if len(n.ObservationDomains) != 1 || n.ObservationDomains[0] != key {
			t.Fatalf("node %s not tagged with coverage key", n.ID)
		}
	}
	if env.Graph.Edges[0].ObservationDomains[0] != key {
		t.Fatal("edge not tagged with coverage key")
	}
}

// TestBuildCampaignEnvelopeRetireOnValidNegative: a not_observed run emits a
// COMPLETE coverage domain with an empty graph so ingest reconciliation retires
// the prior verification under the SAME deterministic domain.
func TestBuildCampaignEnvelopeRetireOnValidNegative(t *testing.T) {
	verified := buildCampaignEnvelope("cred-reach", 1, "ENG", campTestEvidence(campaign.OutcomeCredentialGatedReachVerified))
	negative := buildCampaignEnvelope("cred-reach", 1, "ENG", campTestEvidence(campaign.OutcomeNotObserved))

	if negative.Meta.Collection.State != ingest.OutcomeComplete {
		t.Fatalf("not_observed must be COMPLETE coverage to retire prior, got %q", negative.Meta.Collection.State)
	}
	if len(negative.Graph.Edges) != 0 {
		t.Fatalf("not_observed must emit no edge, got %d", len(negative.Graph.Edges))
	}
	// Same deterministic domain across both runs.
	if verified.Meta.Collection.CoverageKeys[0] != negative.Meta.Collection.CoverageKeys[0] {
		t.Fatal("coverage domain must be identical across outcomes for the same (scenario,cred,server,resource)")
	}
}

// TestBuildCampaignEnvelopeIndeterminatePreserves: indeterminate is PARTIAL so
// the domain is not promoted and prior evidence is preserved.
func TestBuildCampaignEnvelopeIndeterminatePreserves(t *testing.T) {
	env := buildCampaignEnvelope("cred-reach", 1, "ENG", campTestEvidence(campaign.OutcomeIndeterminate))
	if env.Meta.Collection.State != ingest.OutcomePartial {
		t.Fatalf("indeterminate must be PARTIAL coverage, got %q", env.Meta.Collection.State)
	}
	if len(env.Graph.Edges) != 0 {
		t.Fatalf("indeterminate must emit no edge, got %d", len(env.Graph.Edges))
	}
}

// TestCampaignCoverageDomainDeterministic: the domain excludes run id / outcome /
// timestamp; only (scenario id/version, agent, cred, server, resource) drive it.
func TestCampaignCoverageDomainDeterministic(t *testing.T) {
	a := campTestEvidence(campaign.OutcomeCredentialGatedReachVerified)
	a.RunID = "run-1"
	b := campTestEvidence(campaign.OutcomeNotObserved)
	b.RunID = "run-2"
	if campaignCoverageScope("cred-reach", 1, a.Witness) != campaignCoverageScope("cred-reach", 1, b.Witness) {
		t.Fatal("coverage scope must ignore run id and outcome")
	}
	// A different resource changes the domain.
	other := campTestWitness()
	other.ResourceID = "sha256:other-resource"
	if campaignCoverageScope("cred-reach", 1, a.Witness) == campaignCoverageScope("cred-reach", 1, other) {
		t.Fatal("coverage scope must change with the resource ID")
	}
	other = campTestWitness()
	other.AgentID = "sha256:other-agent"
	if campaignCoverageScope("cred-reach", 1, a.Witness) == campaignCoverageScope("cred-reach", 1, other) {
		t.Fatal("coverage scope must change with the source agent ID")
	}
}

func TestResolveCredentialMaterialEnv(t *testing.T) {
	t.Setenv("AGENTHOUND_CAMPAIGN_CREDENTIAL", "env-secret")
	got, err := resolveCredentialMaterial(false, "AGENTHOUND_CAMPAIGN_CREDENTIAL", strings.NewReader(""))
	if err != nil || got != "env-secret" {
		t.Fatalf("env material = %q err=%v, want env-secret", got, err)
	}
}

func TestResolveCredentialMaterialStdin(t *testing.T) {
	got, err := resolveCredentialMaterial(true, "", strings.NewReader("stdin-secret\n"))
	if err != nil || got != "stdin-secret" {
		t.Fatalf("stdin material = %q err=%v, want stdin-secret (newline trimmed)", got, err)
	}
}

func TestResolveWitnessStrictDecode(t *testing.T) {
	// Unknown fields are rejected so a tampered/forwarded witness fails early.
	bad := `{"schema_version":1,"unexpected_field":true}`
	if _, err := resolveWitness("-", strings.NewReader(bad)); err == nil {
		t.Fatal("witness with unknown field must be rejected")
	}
}

func writeCampaignSentinelForTest(t *testing.T) string {
	home := t.TempDir()
	t.Setenv("HOME", home)
	ahDir := filepath.Join(home, ".agenthound")
	if err := os.MkdirAll(ahDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ahDir, "campaign-acknowledged"), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return home
}

func newCampaignTestCmd(t *testing.T, stdin string, out *bytes.Buffer) *cobra.Command {
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
	root.AddCommand(cmd)
	cmd.SetIn(strings.NewReader(stdin))
	cmd.SetOut(out)
	cmd.SetErr(out)
	return cmd
}

// fakeCLIScenario mirrors real scenario behavior: dry-run plans only; empty
// material is not-runnable; commit returns verified evidence from the witness.
type fakeCLIScenario struct{}

func (f *fakeCLIScenario) ID() string          { return "cli-fake" }
func (f *fakeCLIScenario) Version() int        { return 1 }
func (f *fakeCLIScenario) Description() string { return "fake" }
func (f *fakeCLIScenario) Run(_ context.Context, in campaign.RunInput) (*campaign.RunResult, error) {
	if strings.TrimSpace(in.CredentialMaterial) == "" {
		return nil, fmt.Errorf("%w: no material", campaign.ErrNotRunnable)
	}
	if !in.Commit {
		return &campaign.RunResult{DryRun: true, Plan: "FAKE PLAN\n"}, nil
	}
	ev := &campaign.Evidence{
		ScenarioID: "cli-fake", ScenarioVersion: 1, RunID: "r1",
		EngagementID: in.EngagementID, OracleType: campaign.OracleTypeDifferentialCredentialReach,
		Outcome:      campaign.OutcomeCredentialGatedReachVerified,
		ControlStage: campaign.ProbeStageResourceRead, ControlStatus: campaign.ProbeDenied, ControlAddressed: true,
		AuthedStage: campaign.ProbeStageResourceRead, AuthedStatus: campaign.ProbeAllowed, AuthedAddressed: true,
		VerifiedAt: "2026-07-12T00:00:00Z", Witness: in.Witness,
	}
	return &campaign.RunResult{
		Outcome: ev.Outcome, Evidence: ev,
		ControlStatus: campaign.ProbeDenied, AuthedStatus: campaign.ProbeAllowed,
	}, nil
}

var fakeCLIScenarioRegistered = func() bool {
	campaign.Register(&fakeCLIScenario{})
	return true
}()

func TestRunCampaignDryRun(t *testing.T) {
	_ = fakeCLIScenarioRegistered
	writeCampaignSentinelForTest(t)
	t.Setenv("AGENTHOUND_CAMPAIGN_CREDENTIAL", campTestMaterial)

	witnessFile := filepath.Join(t.TempDir(), "witness.json")
	data, _ := json.Marshal(campTestWitness())
	if err := os.WriteFile(witnessFile, data, 0o600); err != nil {
		t.Fatal(err)
	}

	out := &bytes.Buffer{}
	cmd := newCampaignTestCmd(t, "", out)
	mustSetFlag(t, cmd, "scenario", "cli-fake")
	mustSetFlag(t, cmd, "witness", witnessFile)
	mustSetFlag(t, cmd, "engagement-id", "ENG-CAMP")

	if err := runCampaign(cmd, []string{"https://mcp.example/mcp"}); err != nil {
		t.Fatalf("runCampaign dry-run: %v", err)
	}
	if !strings.Contains(out.String(), "DRY-RUN") || !strings.Contains(out.String(), "FAKE PLAN") {
		t.Fatalf("expected dry-run plan output, got: %s", out.String())
	}
}

func TestRunCampaignRejectHashOnly(t *testing.T) {
	_ = fakeCLIScenarioRegistered
	writeCampaignSentinelForTest(t)
	// No credential env set => empty material => not runnable.
	t.Setenv("AGENTHOUND_CAMPAIGN_CREDENTIAL", "")

	witnessFile := filepath.Join(t.TempDir(), "witness.json")
	data, _ := json.Marshal(campTestWitness())
	_ = os.WriteFile(witnessFile, data, 0o600)

	out := &bytes.Buffer{}
	cmd := newCampaignTestCmd(t, "", out)
	mustSetFlag(t, cmd, "scenario", "cli-fake")
	mustSetFlag(t, cmd, "witness", witnessFile)
	mustSetFlag(t, cmd, "engagement-id", "ENG-CAMP")
	mustSetFlag(t, cmd, "commit", "true")

	err := runCampaign(cmd, []string{"https://mcp.example/mcp"})
	if err == nil || !strings.Contains(err.Error(), "not runnable") {
		t.Fatalf("expected not-runnable error, got: %v", err)
	}
	if !strings.Contains(out.String(), "NOT RUNNABLE") {
		t.Fatalf("expected NOT RUNNABLE output, got: %s", out.String())
	}
}

func TestRunCampaignCommitWritesEnvelope(t *testing.T) {
	_ = fakeCLIScenarioRegistered
	writeCampaignSentinelForTest(t)
	t.Setenv("AGENTHOUND_CAMPAIGN_CREDENTIAL", campTestMaterial)

	witnessFile := filepath.Join(t.TempDir(), "witness.json")
	data, _ := json.Marshal(campTestWitness())
	_ = os.WriteFile(witnessFile, data, 0o600)

	out := &bytes.Buffer{}
	cmd := newCampaignTestCmd(t, "", out)
	mustSetFlag(t, cmd, "scenario", "cli-fake")
	mustSetFlag(t, cmd, "witness", witnessFile)
	mustSetFlag(t, cmd, "engagement-id", "ENG-CAMP")
	mustSetFlag(t, cmd, "commit", "true")

	if err := runCampaign(cmd, []string{"https://mcp.example/mcp"}); err != nil {
		t.Fatalf("runCampaign commit: %v", err)
	}
	// Output goes to stdout ("-"), which writeCollectorOutputStdout writes to
	// os.Stdout, not the cmd buffer; assert the committed banner on stderr and
	// that no raw credential leaked into the banner.
	if !strings.Contains(out.String(), "COMMITTED") {
		t.Fatalf("expected COMMITTED banner, got: %s", out.String())
	}
	if strings.Contains(out.String(), campTestMaterial) {
		t.Fatal("raw credential material must never appear in campaign output")
	}
}

func TestRequireCampaignAcknowledgedEnvAck(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("AGENTHOUND_CAMPAIGN_AUTHORIZED", "AUTHORIZED")
	out := &bytes.Buffer{}
	// stdin consumed => must fall back to env ack.
	if err := requireCampaignAcknowledged(out, strings.NewReader(""), true); err != nil {
		t.Fatalf("env ack should satisfy gate: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, ".agenthound", "campaign-acknowledged")); err != nil {
		t.Fatalf("sentinel should be written after env ack: %v", err)
	}
}

func TestRequireCampaignAcknowledgedStdinConsumedNoAck(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("AGENTHOUND_CAMPAIGN_AUTHORIZED", "")
	out := &bytes.Buffer{}
	err := requireCampaignAcknowledged(out, strings.NewReader(""), true)
	if err == nil || !strings.Contains(err.Error(), "authorization required") {
		t.Fatalf("stdin-consumed without ack must error, got: %v", err)
	}
}

func TestRequireCampaignAcknowledgedInteractiveReject(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("AGENTHOUND_CAMPAIGN_AUTHORIZED", "")
	out := &bytes.Buffer{}
	err := requireCampaignAcknowledged(out, strings.NewReader("nope\n"), false)
	if err == nil || !strings.Contains(err.Error(), "authorization not confirmed") {
		t.Fatalf("interactive rejection expected, got: %v", err)
	}
}
