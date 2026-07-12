package common

import "testing"

func TestApplyCredentialEvidenceUsesCanonicalExposureStatus(t *testing.T) {
	props := map[string]any{
		"high_entropy": true,
	}
	ApplyCredentialEvidence(
		props,
		CredentialIdentityProviderName,
		CredentialMaterialMasked,
		CredentialExposureNotObserved,
	)

	if props["high_entropy"] != false {
		t.Fatalf("masked identity retained exposure claims: %+v", props)
	}
	if _, legacy := props["is_exposed"]; legacy {
		t.Fatalf("legacy is_exposed alias was emitted: %+v", props)
	}
	if props["identity_basis"] != "provider_name" ||
		props["material_status"] != "masked" ||
		props["exposure_status"] != "not_observed" {
		t.Fatalf("canonical evidence properties missing: %+v", props)
	}
}
