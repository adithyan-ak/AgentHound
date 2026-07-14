package campaign

// ProbeStatus is the classified result of a single read probe against the exact
// predicted resource. Only Allowed and Denied are DEFINITIVE authorization
// signals; every other status is an incomplete/ambiguous probe that forces an
// indeterminate outcome so prior evidence is preserved rather than overwritten.
type ProbeStatus string

const (
	// ProbeAllowed: the exact predicted resource was read successfully.
	ProbeAllowed ProbeStatus = "allowed"
	// ProbeDenied: a definitive typed, observed HTTP 401/403 authorization
	// denial. No MCP/JSON-RPC authentication codes are currently recognized.
	ProbeDenied ProbeStatus = "denied"
	// ProbeNotFound: the resource is missing (HTTP 404 / MCP resource-not-found).
	// Distinct from an authz denial: we cannot conclude anything about access.
	ProbeNotFound ProbeStatus = "not_found"
	// ProbeMalformedAuth: the server rejected the request as malformed auth
	// (e.g. 400) rather than making an authorization decision.
	ProbeMalformedAuth ProbeStatus = "malformed_auth"
	// ProbeProtocolError: an MCP or transport protocol error.
	ProbeProtocolError ProbeStatus = "protocol_error"
	// ProbeAmbiguous: a response that is neither a clean allow nor a definitive
	// denial (e.g. 2xx with an error body, or an unmapped status).
	ProbeAmbiguous ProbeStatus = "ambiguous"
	// ProbeTimeout: the probe timed out.
	ProbeTimeout ProbeStatus = "timeout"
	// ProbeError: any other incomplete probe (connection refused, TLS, etc.).
	ProbeError ProbeStatus = "error"
)

// IsDefinitive reports whether the probe produced a definitive authorization
// signal (a clean allow or a clean authz denial of an existing resource).
func (s ProbeStatus) IsDefinitive() bool {
	return s == ProbeAllowed || s == ProbeDenied
}

// Outcome is the differential classification of a control (unauth) probe versus
// an authed probe. It is the collector's wire vocabulary and is deliberately
// distinct from server/model.FindingEvidenceState.
type Outcome string

const (
	// OutcomeCredentialGatedReachVerified: unauth denied, auth allowed. The
	// credential is necessary and sufficient for the read — emit
	// CREDENTIAL_REACH_VERIFIED and upgrade the CAN_REACH finding.
	OutcomeCredentialGatedReachVerified Outcome = "credential_gated_reach_verified"
	// OutcomeAnonymousAccessObserved: both allowed. Credential necessity is NOT
	// proven — emit PUBLIC_ACCESS_OBSERVED (a fact, not an auto-finding).
	OutcomeAnonymousAccessObserved Outcome = "anonymous_access_observed"
	// OutcomeAnonymousAccessCredentialRejected: unauth allowed, auth denied.
	// Reach is anonymous and the credential was rejected — emit
	// PUBLIC_ACCESS_OBSERVED; the read is not credential-verified.
	OutcomeAnonymousAccessCredentialRejected Outcome = "anonymous_access_observed_credential_rejected"
	// OutcomeNotObserved: both are definitive authorization denials of the SAME
	// existing resource. A valid negative — retires the prior verification for
	// this coverage domain.
	OutcomeNotObserved Outcome = "not_observed"
	// OutcomeIndeterminate: any incomplete/ambiguous probe (404, malformed auth,
	// protocol error, ambiguous, timeout, ...). Prior evidence is preserved.
	OutcomeIndeterminate Outcome = "indeterminate"
)

// Classify implements the stage-aware differential outcome matrix.
// Credential-gated reach permits the control denial to occur during initialize,
// but requires the authenticated probe to read the exact resource. A negative
// is valid only when both probes reached resource_read, addressed that same
// exact requested resource, and received definitive denials. An independently
// successful control read emits anonymous-access evidence even when the
// credential observation is otherwise indeterminate.
func Classify(control, authed ProbeResult) Outcome {
	controlRead := exactResourceRead(control)
	authedRead := exactResourceRead(authed)

	switch {
	case validControlDenial(control) && authedRead && authed.Status == ProbeAllowed:
		return OutcomeCredentialGatedReachVerified
	case controlRead && control.Status == ProbeAllowed &&
		authedRead && authed.Status == ProbeDenied:
		return OutcomeAnonymousAccessCredentialRejected
	case controlRead && control.Status == ProbeAllowed:
		return OutcomeAnonymousAccessObserved
	case controlRead && authedRead &&
		control.Status == ProbeDenied && authed.Status == ProbeDenied:
		return OutcomeNotObserved
	default:
		return OutcomeIndeterminate
	}
}

func exactResourceRead(result ProbeResult) bool {
	return result.Stage == ProbeStageResourceRead && result.ResourceAddressed
}

func validControlDenial(result ProbeResult) bool {
	return result.Status == ProbeDenied &&
		((result.Stage == ProbeStageInitialize && !result.ResourceAddressed) ||
			exactResourceRead(result))
}

// Definitive reports whether the outcome is a completed observation whose
// credential coverage domain may be promoted (and thus retire prior evidence).
// Only a matching positive or exact dual-denial negative may do so. Anonymous
// observations are still emitted, but remain partial so they cannot retire a
// prior credential verification.
func (o Outcome) Definitive() bool {
	return o == OutcomeCredentialGatedReachVerified || o == OutcomeNotObserved
}

// EdgeKind returns the raw evidence edge kind emitted for the outcome, and
// whether any edge is emitted at all. not_observed and indeterminate emit no
// evidence edge (not_observed relies on the deterministic coverage domain to
// retire prior evidence; indeterminate preserves it).
func (o Outcome) EdgeKind() (string, bool) {
	switch o {
	case OutcomeCredentialGatedReachVerified:
		return "CREDENTIAL_REACH_VERIFIED", true
	case OutcomeAnonymousAccessObserved, OutcomeAnonymousAccessCredentialRejected:
		return "PUBLIC_ACCESS_OBSERVED", true
	default:
		return "", false
	}
}
