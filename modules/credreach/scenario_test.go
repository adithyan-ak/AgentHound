package credreach

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/adithyan-ak/agenthound/sdk/campaign"
	"github.com/adithyan-ak/agenthound/sdk/common"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

const (
	testHost       = "https://mcp.example/mcp"
	testServerID   = "sha256:server-node"
	testCredID     = "sha256:credential-node"
	testResURI     = "postgres://prod/customers"
	testCredMateri = "sk-live-secret"
)

// fakeProber returns preconfigured statuses and records whether each probe
// carried a credential, so tests can assert the control probe is unauthenticated.
type fakeProber struct {
	control campaign.ProbeStatus
	authed  campaign.ProbeStatus
	reqs    []campaign.ProbeRequest
}

func (f *fakeProber) Probe(_ context.Context, req campaign.ProbeRequest) campaign.ProbeResult {
	f.reqs = append(f.reqs, req)
	if req.Unauthenticated() {
		return campaign.ProbeResult{Status: f.control}
	}
	return campaign.ProbeResult{Status: f.authed}
}

func testWitness(t *testing.T) campaign.Witness {
	t.Helper()
	resID := ingest.ComputeNodeID("MCPResource", testServerID, testResURI)
	return campaign.Witness{
		SchemaVersion:       campaign.WitnessSchemaVersion,
		PublicationRevision: 4,
		PredictedEdgeKind:   campaign.PredictedEdgeKindCanReach,
		CredentialID:        testCredID,
		CredentialValueHash: common.HashCredentialValue(testCredMateri),
		CredentialMergeKey:  campaign.CredentialMergeKeyValueHash,
		ServerID:            testServerID,
		ResourceID:          resID,
		ResourceURI:         testResURI,
		PathTopology: []campaign.PathHop{
			{NodeID: "sha256:agent", Kind: "AgentInstance"},
			{NodeID: testServerID, Kind: "MCPServer"},
			{NodeID: testCredID, Kind: "Credential"},
			{NodeID: resID, Kind: "MCPResource"},
		},
	}
}

func commitInput(t *testing.T, prober campaign.Prober) campaign.RunInput {
	return campaign.RunInput{
		Witness:            testWitness(t),
		CredentialMaterial: testCredMateri,
		Host:               testHost,
		EngagementID:       "ENG-1",
		Commit:             true,
		Prober:             prober,
		Now:                func() time.Time { return time.Unix(0, 0).UTC() },
	}
}

func TestScenarioMatrix(t *testing.T) {
	cases := []struct {
		name    string
		control campaign.ProbeStatus
		authed  campaign.ProbeStatus
		want    campaign.Outcome
		edge    string // "" => no evidence edge
	}{
		{"verified", campaign.ProbeDenied, campaign.ProbeAllowed, campaign.OutcomeCredentialGatedReachVerified, "CREDENTIAL_REACH_VERIFIED"},
		{"anonymous", campaign.ProbeAllowed, campaign.ProbeAllowed, campaign.OutcomeAnonymousAccessObserved, "PUBLIC_ACCESS_OBSERVED"},
		{"anon+rejected", campaign.ProbeAllowed, campaign.ProbeDenied, campaign.OutcomeAnonymousAccessCredentialRejected, "PUBLIC_ACCESS_OBSERVED"},
		{"not_observed", campaign.ProbeDenied, campaign.ProbeDenied, campaign.OutcomeNotObserved, ""},
		{"404 => indeterminate", campaign.ProbeDenied, campaign.ProbeNotFound, campaign.OutcomeIndeterminate, ""},
		{"malformed => indeterminate", campaign.ProbeMalformedAuth, campaign.ProbeAllowed, campaign.OutcomeIndeterminate, ""},
		{"timeout => indeterminate", campaign.ProbeTimeout, campaign.ProbeDenied, campaign.OutcomeIndeterminate, ""},
	}
	s := &Scenario{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prober := &fakeProber{control: tc.control, authed: tc.authed}
			res, err := s.Run(context.Background(), commitInput(t, prober))
			if err != nil {
				t.Fatalf("Run error: %v", err)
			}
			if res.Outcome != tc.want {
				t.Fatalf("outcome = %q, want %q", res.Outcome, tc.want)
			}
			if res.Evidence == nil {
				t.Fatal("commit run must always produce Evidence for audit")
			}
			nodes, edges := res.Evidence.EvidenceGraph("scan-x")
			if tc.edge == "" {
				if len(edges) != 0 {
					t.Fatalf("%s must emit no evidence edge, got %d", tc.name, len(edges))
				}
				return
			}
			if len(edges) != 1 || edges[0].Kind != tc.edge {
				t.Fatalf("want one %s edge, got %+v", tc.edge, edges)
			}
			if len(nodes) != 2 {
				t.Fatalf("want 2 reference endpoints, got %d", len(nodes))
			}
		})
	}
}

// TestUnauthControlProbe asserts the control probe carries NO credential and the
// authed probe carries one.
func TestUnauthControlProbe(t *testing.T) {
	prober := &fakeProber{control: campaign.ProbeDenied, authed: campaign.ProbeAllowed}
	s := &Scenario{}
	if _, err := s.Run(context.Background(), commitInput(t, prober)); err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if len(prober.reqs) != 2 {
		t.Fatalf("want 2 probes, got %d", len(prober.reqs))
	}
	if !prober.reqs[0].Unauthenticated() {
		t.Fatal("first probe (control) must be unauthenticated")
	}
	if prober.reqs[1].Unauthenticated() {
		t.Fatal("second probe (authed) must carry the credential")
	}
	if prober.reqs[1].Credential != testCredMateri {
		t.Fatal("authed probe must carry the hash-matched credential material")
	}
}

func TestRejectHashOnly(t *testing.T) {
	s := &Scenario{}
	in := commitInput(t, &fakeProber{})
	in.CredentialMaterial = "" // hash-only / no material
	_, err := s.Run(context.Background(), in)
	if !errors.Is(err, campaign.ErrNotRunnable) {
		t.Fatalf("no material must be ErrNotRunnable (precondition), got %v", err)
	}
}

func TestRejectMismatchedMaterial(t *testing.T) {
	s := &Scenario{}
	in := commitInput(t, &fakeProber{})
	in.CredentialMaterial = "not-the-real-secret"
	_, err := s.Run(context.Background(), in)
	if !errors.Is(err, campaign.ErrNotRunnable) {
		t.Fatalf("mismatched material must be ErrNotRunnable, got %v", err)
	}
}

func TestDryRunPlansOnly(t *testing.T) {
	prober := &fakeProber{control: campaign.ProbeDenied, authed: campaign.ProbeAllowed}
	s := &Scenario{}
	in := commitInput(t, prober)
	in.Commit = false
	res, err := s.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("dry run error: %v", err)
	}
	if !res.DryRun || res.Plan == "" {
		t.Fatalf("dry run must return a plan, got %+v", res)
	}
	if res.Evidence != nil {
		t.Fatal("dry run must not produce evidence")
	}
	if len(prober.reqs) != 0 {
		t.Fatal("dry run must not probe the target")
	}
}

func TestInvalidWitnessRejected(t *testing.T) {
	s := &Scenario{}
	in := commitInput(t, &fakeProber{})
	w := in.Witness
	w.ResourceURI = "postgres://prod/tampered" // breaks resource_id binding
	in.Witness = w
	if _, err := s.Run(context.Background(), in); err == nil {
		t.Fatal("forged/mismatched witness must be rejected before probing")
	}
}

func TestScenarioRegistered(t *testing.T) {
	got, ok := campaign.Get("cred-reach")
	if !ok {
		t.Fatal("cred-reach scenario must self-register via init()")
	}
	if got.Version() != scenarioVersion || got.ID() != scenarioID {
		t.Fatalf("registered scenario mismatch: id=%q version=%d", got.ID(), got.Version())
	}
}
