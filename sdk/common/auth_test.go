package common

import "testing"

func TestAssessAuthCanonicalMethods(t *testing.T) {
	tests := []struct {
		raw       string
		method    AuthMethod
		assurance AuthAssurance
		weakness  *float64
	}{
		{"", AuthUnknown, AuthAssuranceUnknown, nil},
		{"none", AuthNone, AuthAssuranceUnauthenticated, floatPtr(100)},
		{"Basic", AuthBasic, AuthAssuranceWeak, floatPtr(85)},
		{"api_key", AuthAPIKey, AuthAssuranceWeak, floatPtr(70)},
		{"Bearer", AuthBearer, AuthAssuranceModerate, floatPtr(50)},
		{"oauth2", AuthOAuth, AuthAssuranceStrong, floatPtr(25)},
		{"openIdConnect", AuthOIDC, AuthAssuranceStrong, floatPtr(20)},
		{"mutualTLS", AuthMTLS, AuthAssuranceStrong, floatPtr(10)},
		{"proprietary", AuthCustom, AuthAssuranceUnknown, nil},
	}

	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			got := AssessAuth(tt.raw)
			if got.Method != tt.method || got.Assurance != tt.assurance {
				t.Fatalf("AssessAuth(%q) = %+v, want method=%q assurance=%q",
					tt.raw, got, tt.method, tt.assurance)
			}
			if tt.weakness == nil {
				if got.Weakness != nil {
					t.Fatalf("AssessAuth(%q).Weakness = %v, want nil", tt.raw, *got.Weakness)
				}
				return
			}
			if got.Weakness == nil || *got.Weakness != *tt.weakness {
				t.Fatalf("AssessAuth(%q).Weakness = %v, want %v", tt.raw, got.Weakness, *tt.weakness)
			}
		})
	}
}

func TestAuthWeaknessScoresReturnsCopy(t *testing.T) {
	first := AuthWeaknessScores()
	first["oidc"] = 999
	second := AuthWeaknessScores()
	if second["oidc"] != 20 {
		t.Fatalf("caller mutated canonical auth policy: oidc=%v", second["oidc"])
	}
	if _, ok := second["unknown"]; ok {
		t.Fatal("unknown must not have a numeric weakness")
	}
	if _, ok := second["custom"]; ok {
		t.Fatal("custom must not have a numeric weakness")
	}
}

func TestIsConfirmedAnonymousAccessRequiresAffirmativeEvidence(t *testing.T) {
	tests := []struct {
		name     string
		method   string
		evidence string
		want     bool
	}{
		{
			name:     "successful anonymous network probe",
			method:   "none",
			evidence: AuthEvidenceAnonymousProbeSucceeded,
			want:     true,
		},
		{
			name:     "legacy local stdio process",
			method:   "none",
			evidence: AuthEvidenceLocalProcess,
		},
		{
			name:     "unverified no-auth declaration",
			method:   "none",
			evidence: AuthEvidenceUnknown,
		},
		{
			name:     "authenticated scheme",
			method:   "bearer",
			evidence: AuthEvidenceConfiguredCredential,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsConfirmedAnonymousAccess(tt.method, tt.evidence); got != tt.want {
				t.Fatalf(
					"IsConfirmedAnonymousAccess(%q, %q) = %v, want %v",
					tt.method,
					tt.evidence,
					got,
					tt.want,
				)
			}
		})
	}
}

func floatPtr(v float64) *float64 { return &v }
