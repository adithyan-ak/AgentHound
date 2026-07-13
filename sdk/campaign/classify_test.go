package campaign

import "testing"

func TestClassifyFullMatrix(t *testing.T) {
	cases := []struct {
		name    string
		control ProbeStatus
		authed  ProbeStatus
		want    Outcome
	}{
		{"unauth denied, auth allowed => verified", ProbeDenied, ProbeAllowed, OutcomeCredentialGatedReachVerified},
		{"both allowed => anonymous", ProbeAllowed, ProbeAllowed, OutcomeAnonymousAccessObserved},
		{"unauth allowed, auth denied => anonymous+rejected", ProbeAllowed, ProbeDenied, OutcomeAnonymousAccessCredentialRejected},
		{"both denied => not_observed", ProbeDenied, ProbeDenied, OutcomeNotObserved},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Classify(tc.control, tc.authed); got != tc.want {
				t.Fatalf("Classify(%s,%s) = %q, want %q", tc.control, tc.authed, got, tc.want)
			}
		})
	}
}

// TestClassifyIndeterminate asserts that ANY non-definitive probe on either side
// forces indeterminate and NEVER not_observed. not_observed must require both
// sides to be definitive authz denials.
func TestClassifyIndeterminate(t *testing.T) {
	nonDefinitive := []ProbeStatus{
		ProbeNotFound, ProbeMalformedAuth, ProbeProtocolError,
		ProbeAmbiguous, ProbeTimeout, ProbeError,
	}
	definitive := []ProbeStatus{ProbeAllowed, ProbeDenied}

	for _, nd := range nonDefinitive {
		for _, d := range definitive {
			if got := Classify(nd, d); got != OutcomeIndeterminate {
				t.Errorf("Classify(control=%s, authed=%s) = %q, want indeterminate", nd, d, got)
			}
			if got := Classify(d, nd); got != OutcomeIndeterminate {
				t.Errorf("Classify(control=%s, authed=%s) = %q, want indeterminate", d, nd, got)
			}
		}
		for _, nd2 := range nonDefinitive {
			if got := Classify(nd, nd2); got != OutcomeIndeterminate {
				t.Errorf("Classify(control=%s, authed=%s) = %q, want indeterminate", nd, nd2, got)
			}
		}
	}
}

// TestNotFoundNeverNotObserved guards the specific regression the plan calls out:
// a missing resource (404) on a denied control must NOT collapse to not_observed.
func TestNotFoundNeverNotObserved(t *testing.T) {
	if got := Classify(ProbeDenied, ProbeNotFound); got != OutcomeIndeterminate {
		t.Fatalf("denied control + 404 authed = %q, want indeterminate", got)
	}
	if got := Classify(ProbeNotFound, ProbeNotFound); got != OutcomeIndeterminate {
		t.Fatalf("both 404 = %q, want indeterminate", got)
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
		{OutcomeAnonymousAccessObserved, true, "PUBLIC_ACCESS_OBSERVED", true},
		{OutcomeAnonymousAccessCredentialRejected, true, "PUBLIC_ACCESS_OBSERVED", true},
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
