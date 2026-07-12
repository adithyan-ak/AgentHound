package common

// This file centralizes the auth-scheme and assessment (truth) state enums so
// collectors, analysis, and the generated UI registry share one vocabulary.
// The governing rule: absence is not evidence. A field that was never probed
// MUST be AssessmentNotAssessed / AuthUnknown, never silently coerced to a
// benign value.

// AuthScheme is the authentication mechanism observed on a service or agent.
// It is derived from normalized credential/auth evidence, not assumed. In
// particular OIDC does not imply a fixed assurance score without supporting
// evidence — callers must carry assurance separately.
type AuthScheme string

const (
	// AuthNone means the endpoint was probed and confirmed to require no auth.
	AuthNone   AuthScheme = "none"
	AuthBasic  AuthScheme = "basic"
	AuthAPIKey AuthScheme = "api_key"
	AuthBearer AuthScheme = "bearer"
	AuthCustom AuthScheme = "custom"
	AuthOAuth  AuthScheme = "oauth"
	AuthOIDC   AuthScheme = "oidc"
	// AuthSignature covers request-signing schemes (HTTP message signatures,
	// A2A agent-card signatures, etc.).
	AuthSignature AuthScheme = "signature"
	// AuthUnknown means the auth posture was not determined. Distinct from
	// AuthNone (probed, confirmed open).
	AuthUnknown AuthScheme = "unknown"
)

// AllAuthSchemes is the canonical ordered set of auth schemes.
var AllAuthSchemes = []AuthScheme{
	AuthNone, AuthBasic, AuthAPIKey, AuthBearer, AuthCustom,
	AuthOAuth, AuthOIDC, AuthSignature, AuthUnknown,
}

// Valid reports whether s is one of the defined auth schemes.
func (s AuthScheme) Valid() bool {
	switch s {
	case AuthNone, AuthBasic, AuthAPIKey, AuthBearer, AuthCustom,
		AuthOAuth, AuthOIDC, AuthSignature, AuthUnknown:
		return true
	default:
		return false
	}
}

// AssessmentState is the truth state of any property whose absence must not be
// read as a benign value (host scope, resource sensitivity, pinning, backend
// verification, credential masking, etc.).
type AssessmentState string

const (
	// AssessmentAssessed means the property was actively determined; its value
	// is trustworthy.
	AssessmentAssessed AssessmentState = "assessed"
	// AssessmentNotAssessed means the property was never probed in this scan.
	AssessmentNotAssessed AssessmentState = "not_assessed"
	// AssessmentUnknown means the property was probed but could not be
	// determined (ambiguous/inconclusive evidence).
	AssessmentUnknown AssessmentState = "unknown"
)

// AllAssessmentStates is the canonical ordered set of assessment states.
var AllAssessmentStates = []AssessmentState{
	AssessmentAssessed, AssessmentNotAssessed, AssessmentUnknown,
}

// Valid reports whether s is one of the defined assessment states.
func (s AssessmentState) Valid() bool {
	switch s {
	case AssessmentAssessed, AssessmentNotAssessed, AssessmentUnknown:
		return true
	default:
		return false
	}
}
