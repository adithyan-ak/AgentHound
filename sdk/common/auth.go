package common

import "strings"

// AuthMethod is the canonical authentication vocabulary emitted by collectors.
// Empty or unassessed evidence is unknown; it is never equivalent to none.
type AuthMethod string

const (
	AuthUnknown AuthMethod = "unknown"
	AuthNone    AuthMethod = "none"
	AuthBasic   AuthMethod = "basic"
	AuthAPIKey  AuthMethod = "apiKey"
	AuthBearer  AuthMethod = "bearer"
	AuthOAuth   AuthMethod = "oauth"
	AuthOIDC    AuthMethod = "oidc"
	AuthMTLS    AuthMethod = "mtls"
	AuthCustom  AuthMethod = "custom"
)

// AuthAssurance is deliberately categorical. Unknown and custom schemes have
// no invented numeric weakness and therefore cannot satisfy weak/strong
// detector predicates.
type AuthAssurance string

const (
	AuthAssuranceUnknown         AuthAssurance = "unknown"
	AuthAssuranceUnauthenticated AuthAssurance = "unauthenticated"
	AuthAssuranceWeak            AuthAssurance = "weak"
	AuthAssuranceModerate        AuthAssurance = "moderate"
	AuthAssuranceStrong          AuthAssurance = "strong"
)

const (
	AuthEvidenceUnknown                 = "unknown"
	AuthEvidenceDeclaredScheme          = "declared_security_scheme"
	AuthEvidenceConfiguredCredential    = "configured_credential"
	AuthEvidenceAnonymousProbeSucceeded = "anonymous_probe_succeeded"
	AuthEvidenceLocalProcess            = "local_process"
)

// AuthAssessment carries the normalized method and its supported assurance
// semantics. Weakness is nil for unknown/custom methods.
type AuthAssessment struct {
	Method    AuthMethod
	Assurance AuthAssurance
	Weakness  *float64
}

var authWeakness = map[AuthMethod]float64{
	AuthNone:   100,
	AuthBasic:  85,
	AuthAPIKey: 70,
	AuthBearer: 50,
	AuthOAuth:  25,
	AuthOIDC:   20,
	AuthMTLS:   10,
}

// RecognizeAuthMethod normalizes a known spelling. The boolean is false for an
// empty or unsupported value so callers can distinguish unknown evidence from
// an explicitly configured custom scheme.
func RecognizeAuthMethod(raw string) (AuthMethod, bool) {
	normalized := strings.ToLower(strings.TrimSpace(raw))
	normalized = strings.NewReplacer("-", "", "_", "", " ", "").Replace(normalized)
	switch normalized {
	case "none", "anonymous", "unauthenticated", "noauth":
		return AuthNone, true
	case "basic", "httpbasic":
		return AuthBasic, true
	case "apikey", "xapikey":
		return AuthAPIKey, true
	case "bearer", "httpbearer":
		return AuthBearer, true
	case "oauth", "oauth2":
		return AuthOAuth, true
	case "oidc", "openid", "openidconnect":
		return AuthOIDC, true
	case "mtls", "mutualtls":
		return AuthMTLS, true
	case "custom":
		return AuthCustom, true
	case "unknown", "":
		return AuthUnknown, normalized == "unknown"
	default:
		return AuthUnknown, false
	}
}

// NormalizeAuthMethod maps unsupported non-empty values to custom while
// preserving missing values as unknown.
func NormalizeAuthMethod(raw string) AuthMethod {
	if method, ok := RecognizeAuthMethod(raw); ok {
		return method
	}
	if strings.TrimSpace(raw) == "" {
		return AuthUnknown
	}
	return AuthCustom
}

// IsConfirmedAnonymousAccess requires affirmative runtime evidence in addition
// to an explicit no-auth method. Local-process access and unverified
// declarations are not anonymous network access.
func IsConfirmedAnonymousAccess(rawMethod, evidence string) bool {
	return NormalizeAuthMethod(rawMethod) == AuthNone &&
		evidence == AuthEvidenceAnonymousProbeSucceeded
}

func AssessAuth(raw string) AuthAssessment {
	method := NormalizeAuthMethod(raw)
	assessment := AuthAssessment{Method: method, Assurance: AuthAssuranceUnknown}
	switch method {
	case AuthNone:
		assessment.Assurance = AuthAssuranceUnauthenticated
	case AuthBasic, AuthAPIKey:
		assessment.Assurance = AuthAssuranceWeak
	case AuthBearer:
		assessment.Assurance = AuthAssuranceModerate
	case AuthOAuth, AuthOIDC, AuthMTLS:
		assessment.Assurance = AuthAssuranceStrong
	}
	if score, ok := authWeakness[method]; ok {
		scoreCopy := score
		assessment.Weakness = &scoreCopy
	}
	return assessment
}

// AuthWeaknessScores returns a copy so consumers cannot mutate the canonical
// policy. Higher values mean weaker authentication.
func AuthWeaknessScores() map[string]float64 {
	out := make(map[string]float64, len(authWeakness))
	for method, score := range authWeakness {
		out[string(method)] = score
	}
	return out
}

// AuthTrustWeight preserves the existing edge-ranking scale while avoiding a
// no-auth score for unknown/custom methods.
func AuthTrustWeight(raw string) float64 {
	switch NormalizeAuthMethod(raw) {
	case AuthNone:
		return 0.1
	case AuthBasic:
		return 0.25
	case AuthAPIKey:
		return 0.3
	case AuthBearer:
		return 0.5
	case AuthOAuth:
		return 0.7
	case AuthOIDC:
		return 0.75
	case AuthMTLS:
		return 0.9
	default:
		return 0.5
	}
}

func IsExplicitlyAuthenticated(raw string) bool {
	method := NormalizeAuthMethod(raw)
	return method != AuthUnknown && method != AuthNone
}
