package campaign

import "testing"

func TestClassifyFullMatrix(t *testing.T) {
	cases := []struct {
		name    string
		control ProbeResult
		authed  ProbeResult
		want    Outcome
	}{
		{"control initialize denied, auth read allowed => verified", initResult(ProbeDenied), readResult(ProbeAllowed), OutcomeCredentialGatedReachVerified},
		{"control read denied, auth read allowed => verified", readResult(ProbeDenied), readResult(ProbeAllowed), OutcomeCredentialGatedReachVerified},
		{"both read allowed => anonymous", readResult(ProbeAllowed), readResult(ProbeAllowed), OutcomeAnonymousAccessObserved},
		{"control read allowed, auth read denied => anonymous+rejected", readResult(ProbeAllowed), readResult(ProbeDenied), OutcomeAnonymousAccessCredentialRejected},
		{"both read denied => not_observed", readResult(ProbeDenied), readResult(ProbeDenied), OutcomeNotObserved},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Classify(tc.control, tc.authed); got != tc.want {
				t.Fatalf("Classify(%+v,%+v) = %q, want %q", tc.control, tc.authed, got, tc.want)
			}
		})
	}
}

func readResult(status ProbeStatus) ProbeResult {
	return ProbeResult{Stage: ProbeStageResourceRead, ResourceAddressed: true, Status: status}
}

func initResult(status ProbeStatus) ProbeResult {
	return ProbeResult{Stage: ProbeStageInitialize, Status: status}
}

// TestClassifyIndeterminate asserts that non-definitive or incomplete
// credential probes cannot produce verified/not_observed. A successful exact
// control read remains an independently reportable anonymous-access fact.
func TestClassifyIndeterminate(t *testing.T) {
	nonDefinitive := []ProbeStatus{
		ProbeNotFound, ProbeMalformedAuth, ProbeProtocolError,
		ProbeAmbiguous, ProbeTimeout, ProbeError,
	}

	for _, nd := range nonDefinitive {
		if got := Classify(readResult(nd), readResult(ProbeDenied)); got != OutcomeIndeterminate {
			t.Errorf("Classify(control=%s, authed=denied) = %q, want indeterminate", nd, got)
		}
		if got := Classify(readResult(ProbeDenied), readResult(nd)); got != OutcomeIndeterminate {
			t.Errorf("Classify(control=denied, authed=%s) = %q, want indeterminate", nd, got)
		}
		if got := Classify(readResult(ProbeAllowed), readResult(nd)); got != OutcomeAnonymousAccessObserved {
			t.Errorf("successful control + authed=%s = %q, want anonymous observation", nd, got)
		}
	}
}

// TestNotFoundNeverNotObserved guards the specific regression the plan calls out:
// a missing resource (404) on a denied control must NOT collapse to not_observed.
func TestNotFoundNeverNotObserved(t *testing.T) {
	if got := Classify(readResult(ProbeDenied), readResult(ProbeNotFound)); got != OutcomeIndeterminate {
		t.Fatalf("denied control + 404 authed = %q, want indeterminate", got)
	}
	if got := Classify(readResult(ProbeNotFound), readResult(ProbeNotFound)); got != OutcomeIndeterminate {
		t.Fatalf("both 404 = %q, want indeterminate", got)
	}
}

func TestNegativeRequiresDualExactResourceReadDenials(t *testing.T) {
	cases := []struct {
		name    string
		control ProbeResult
		authed  ProbeResult
	}{
		{"control initialization denied", initResult(ProbeDenied), readResult(ProbeDenied)},
		{"authed initialization denied", readResult(ProbeDenied), initResult(ProbeDenied)},
		{"control wrong resource", ProbeResult{Stage: ProbeStageResourceRead, Status: ProbeDenied}, readResult(ProbeDenied)},
		{"authed wrong resource", readResult(ProbeDenied), ProbeResult{Stage: ProbeStageResourceRead, Status: ProbeDenied}},
		{"incomplete control", ProbeResult{Status: ProbeDenied}, readResult(ProbeDenied)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Classify(tc.control, tc.authed); got != OutcomeIndeterminate {
				t.Fatalf("Classify = %q, want indeterminate", got)
			}
		})
	}
}

func TestOutcomeDefinitiveAndEdgeKind(t *testing.T) {
	cases := []struct {
		outcome    Outcome
		definitive bool
		edge       string
		emits      bool
	}{
		{OutcomeCredentialGatedReachVerified, true, "CREDENTIAL_REACH_VERIFIED", true},
		{OutcomeAnonymousAccessObserved, false, "PUBLIC_ACCESS_OBSERVED", true},
		{OutcomeAnonymousAccessCredentialRejected, false, "PUBLIC_ACCESS_OBSERVED", true},
		{OutcomeNotObserved, true, "", false},
		{OutcomeIndeterminate, false, "", false},
	}
	for _, tc := range cases {
		t.Run(string(tc.outcome), func(t *testing.T) {
			if got := tc.outcome.Definitive(); got != tc.definitive {
				t.Errorf("Definitive() = %v, want %v", got, tc.definitive)
			}
			edge, emits := tc.outcome.EdgeKind()
			if emits != tc.emits || edge != tc.edge {
				t.Errorf("EdgeKind() = (%q,%v), want (%q,%v)", edge, emits, tc.edge, tc.emits)
			}
		})
	}
}

func TestProbeStatusIsDefinitive(t *testing.T) {
	if !ProbeAllowed.IsDefinitive() || !ProbeDenied.IsDefinitive() {
		t.Fatal("allowed/denied must be definitive")
	}
	for _, s := range []ProbeStatus{ProbeNotFound, ProbeMalformedAuth, ProbeProtocolError, ProbeAmbiguous, ProbeTimeout, ProbeError} {
		if s.IsDefinitive() {
			t.Errorf("%s must not be definitive", s)
		}
	}
}
