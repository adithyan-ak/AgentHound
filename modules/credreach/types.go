package credreach

import (
	"context"
	"strings"
	"time"
)

type ProbeRequest struct {
	Host        string
	ResourceURI string
	Credential  string
	Insecure    bool
	Timeout     time.Duration
}

func (request ProbeRequest) Unauthenticated() bool {
	return strings.TrimSpace(request.Credential) == ""
}

type ProbeStage string

const (
	ProbeStageInitialize   ProbeStage = "initialize"
	ProbeStageResourceRead ProbeStage = "resource_read"
)

type ProbeStatus string

const (
	ProbeAllowed       ProbeStatus = "allowed"
	ProbeDenied        ProbeStatus = "denied"
	ProbeNotFound      ProbeStatus = "not_found"
	ProbeMalformedAuth ProbeStatus = "malformed_auth"
	ProbeProtocolError ProbeStatus = "protocol_error"
	ProbeAmbiguous     ProbeStatus = "ambiguous"
	ProbeTimeout       ProbeStatus = "timeout"
	ProbeError         ProbeStatus = "error"
)

type ProbeResult struct {
	Stage             ProbeStage
	ResourceAddressed bool
	Status            ProbeStatus
	Detail            string
}

type Prober interface {
	Probe(context.Context, ProbeRequest) ProbeResult
}

type Outcome string

const (
	OutcomeCredentialGatedReachVerified      Outcome = "credential_gated_reach_verified"
	OutcomeAnonymousAccessObserved           Outcome = "anonymous_access_observed"
	OutcomeAnonymousAccessCredentialRejected Outcome = "anonymous_access_observed_credential_rejected"
	OutcomeNotObserved                       Outcome = "not_observed"
	OutcomeIndeterminate                     Outcome = "indeterminate"
)

func Classify(control, credential ProbeResult) Outcome {
	controlRead := exactResourceRead(control)
	credentialRead := exactResourceRead(credential)
	switch {
	case validControlDenial(control) && credentialRead && credential.Status == ProbeAllowed:
		return OutcomeCredentialGatedReachVerified
	case controlRead && control.Status == ProbeAllowed && credentialRead && credential.Status == ProbeDenied:
		return OutcomeAnonymousAccessCredentialRejected
	case controlRead && control.Status == ProbeAllowed:
		return OutcomeAnonymousAccessObserved
	case controlRead && credentialRead && control.Status == ProbeDenied && credential.Status == ProbeDenied:
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
		((result.Stage == ProbeStageInitialize && !result.ResourceAddressed) || exactResourceRead(result))
}
