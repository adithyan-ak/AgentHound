package common

import "testing"

func TestApplyCredentialEvidenceClearsUnsupportedExposureClaims(t *testing.T) {
	props := map[string]any{
		"is_exposed":   true,
		"high_entropy": true,
	}
	ApplyCredentialEvidence(
		props,
		CredentialIdentityProviderName,
		CredentialMaterialMasked,
		CredentialExposureNotObserved,
	)

	if props["is_exposed"] != false || props["high_entropy"] != false {
		t.Fatalf("masked identity retained exposure claims: %+v", props)
	}
	if props["identity_basis"] != "provider_name" ||
		props["material_status"] != "masked" ||
		props["exposure_status"] != "not_observed" {
		t.Fatalf("canonical evidence properties missing: %+v", props)
	}
}
