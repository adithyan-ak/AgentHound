package common

// CredentialIdentityBasis states what makes a Credential node stable across
// observations. provider_name and metadata identities are not secret-value
// hashes and must not participate in value-hash joins.
type CredentialIdentityBasis string

const (
	CredentialIdentityUnknown      CredentialIdentityBasis = "unknown"
	CredentialIdentityValueHash    CredentialIdentityBasis = "value_hash"
	CredentialIdentityProviderName CredentialIdentityBasis = "provider_name"
	CredentialIdentityMetadata     CredentialIdentityBasis = "metadata"
)

// CredentialMaterialStatus describes what credential material the producer
// actually observed. A hash or masked reference is not usable secret material.
type CredentialMaterialStatus string

const (
	CredentialMaterialUnknown    CredentialMaterialStatus = "unknown"
	CredentialMaterialObserved   CredentialMaterialStatus = "observed"
	CredentialMaterialMasked     CredentialMaterialStatus = "masked"
	CredentialMaterialHashed     CredentialMaterialStatus = "hashed"
	CredentialMaterialUnobserved CredentialMaterialStatus = "unobserved"
)

type CredentialExposureStatus string

const (
	CredentialExposureUnknown     CredentialExposureStatus = "unknown"
	CredentialExposureExposed     CredentialExposureStatus = "exposed"
	CredentialExposureNotObserved CredentialExposureStatus = "not_observed"
)

type PinningStatus string

const (
	PinningUnknown       PinningStatus = "unknown"
	PinningPinned        PinningStatus = "pinned"
	PinningUnpinned      PinningStatus = "unpinned"
	PinningNotApplicable PinningStatus = "not_applicable"
)

type VerificationStatus string

const (
	VerificationUnknown              VerificationStatus = "unknown"
	VerificationConfiguredUnverified VerificationStatus = "configured_unverified"
	VerificationVerified             VerificationStatus = "verified"
	VerificationFailed               VerificationStatus = "failed"
)

// ApplyCredentialEvidence writes canonical evidence properties and maintains
// the legacy booleans conservatively. In particular, masked/hashed/unobserved
// material explicitly clears stale is_exposed/high_entropy values on MERGE.
func ApplyCredentialEvidence(
	props map[string]any,
	identity CredentialIdentityBasis,
	material CredentialMaterialStatus,
	exposure CredentialExposureStatus,
) {
	props["identity_basis"] = string(identity)
	props["material_status"] = string(material)
	props["exposure_status"] = string(exposure)

	switch exposure {
	case CredentialExposureExposed:
		props["is_exposed"] = true
	case CredentialExposureNotObserved:
		props["is_exposed"] = false
	}
	if material != CredentialMaterialObserved {
		props["high_entropy"] = false
	}
}

func HasObservedCredentialMaterial(material CredentialMaterialStatus) bool {
	return material == CredentialMaterialObserved
}
