package credreach

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/adithyan-ak/agenthound/sdk/campaign"
	"github.com/adithyan-ak/agenthound/sdk/common"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

const (
	testHost       = "https://mcp.example/mcp"
	testCredID     = "sha256:credential-node"
	testResURI     = "postgres://prod/customers"
	testCredMateri = "sk-live-secret"
)

// fakeProber returns preconfigured statuses and records whether each probe
// carried a credential, so tests can assert the control probe is unauthenticated.
type fakeProber struct {
	control campaign.ProbeResult
	authed  campaign.ProbeResult
	reqs    []campaign.ProbeRequest
}

func (f *fakeProber) Probe(_ context.Context, req campaign.ProbeRequest) campaign.ProbeResult {
	f.reqs = append(f.reqs, req)
	if req.Unauthenticated() {
		return f.control
	}
	return f.authed
}

func readProbe(status campaign.ProbeStatus) campaign.ProbeResult {
	return campaign.ProbeResult{
		Stage:             campaign.ProbeStageResourceRead,
		ResourceAddressed: true,
		Status:            status,
	}
}

func initializeProbe(status campaign.ProbeStatus) campaign.ProbeResult {
	return campaign.ProbeResult{Stage: campaign.ProbeStageInitialize, Status: status}
}

func testWitness(t *testing.T) campaign.Witness {
	t.Helper()
	testServerID := ingest.ResolveMCPServerIdentity("http", testHost).ObjectID
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
		control campaign.ProbeResult
		authed  campaign.ProbeResult
		want    campaign.Outcome
		edge    string // "" => no evidence edge
	}{
		{"control initialize denied verifies", initializeProbe(campaign.ProbeDenied), readProbe(campaign.ProbeAllowed), campaign.OutcomeCredentialGatedReachVerified, "CREDENTIAL_REACH_VERIFIED"},
		{"verified", readProbe(campaign.ProbeDenied), readProbe(campaign.ProbeAllowed), campaign.OutcomeCredentialGatedReachVerified, "CREDENTIAL_REACH_VERIFIED"},
		{"anonymous", readProbe(campaign.ProbeAllowed), readProbe(campaign.ProbeAllowed), campaign.OutcomeAnonymousAccessObserved, "PUBLIC_ACCESS_OBSERVED"},
		{"anon+rejected", readProbe(campaign.ProbeAllowed), readProbe(campaign.ProbeDenied), campaign.OutcomeAnonymousAccessCredentialRejected, "PUBLIC_ACCESS_OBSERVED"},
		{"not_observed", readProbe(campaign.ProbeDenied), readProbe(campaign.ProbeDenied), campaign.OutcomeNotObserved, ""},
		{"initialize denial negative => indeterminate", initializeProbe(campaign.ProbeDenied), readProbe(campaign.ProbeDenied), campaign.OutcomeIndeterminate, ""},
		{"404 => indeterminate", readProbe(campaign.ProbeDenied), readProbe(campaign.ProbeNotFound), campaign.OutcomeIndeterminate, ""},
		{"malformed => indeterminate", readProbe(campaign.ProbeMalformedAuth), readProbe(campaign.ProbeAllowed), campaign.OutcomeIndeterminate, ""},
		{"timeout => indeterminate", readProbe(campaign.ProbeTimeout), readProbe(campaign.ProbeDenied), campaign.OutcomeIndeterminate, ""},
		{"anonymous survives authed timeout", readProbe(campaign.ProbeAllowed), readProbe(campaign.ProbeTimeout), campaign.OutcomeAnonymousAccessObserved, "PUBLIC_ACCESS_OBSERVED"},
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
	prober := &fakeProber{control: readProbe(campaign.ProbeDenied), authed: readProbe(campaign.ProbeAllowed)}
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
	prober := &fakeProber{control: readProbe(campaign.ProbeDenied), authed: readProbe(campaign.ProbeAllowed)}
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

func TestEndpointIdentityMismatchRejectedBeforeProbe(t *testing.T) {
	prober := &fakeProber{
		control: readProbe(campaign.ProbeDenied),
		authed:  readProbe(campaign.ProbeAllowed),
	}
	in := commitInput(t, prober)
	in.Host = "https://other.example/mcp"
	if _, err := (&Scenario{}).Run(context.Background(), in); !errors.Is(err, campaign.ErrNotRunnable) {
		t.Fatalf("endpoint mismatch must be not-runnable, got %v", err)
	}
	if len(prober.reqs) != 0 {
		t.Fatalf("endpoint mismatch dispatched %d probes", len(prober.reqs))
	}
}

func TestAcceptedQueryNeverAppearsInPlan(t *testing.T) {
	const endpoint = "https://mcp.example/mcp?opaque=potentially-sensitive"
	prober := &fakeProber{}
	in := commitInput(t, prober)
	in.Host = endpoint
	in.Witness.ServerID = ingest.ResolveMCPServerIdentity("http", endpoint).ObjectID
	in.Witness.ResourceID = ingest.ComputeNodeID("MCPResource", in.Witness.ServerID, in.Witness.ResourceURI)
	for i := range in.Witness.PathTopology {
		switch in.Witness.PathTopology[i].Kind {
		case "MCPServer":
			in.Witness.PathTopology[i].NodeID = in.Witness.ServerID
		case "MCPResource":
			in.Witness.PathTopology[i].NodeID = in.Witness.ResourceID
		}
	}
	in.Commit = false

	res, err := (&Scenario{}).Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if strings.Contains(res.Plan, "opaque=") || strings.Contains(res.TargetRef, "opaque=") {
		t.Fatalf("accepted endpoint query leaked into plan/result: %+v", res)
	}
	if len(prober.reqs) != 0 {
		t.Fatal("dry run must not probe")
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
