package ingest

// ExposesCredentialEdge builds the standard EXPOSES_CREDENTIAL edge from
// an AIService node to a Credential node. Looters that enumerate exposed
// upstream/provider secrets (litellmloot, openwebuiloot, ...) share this
// constructor so the edge's confidence, risk_weight, and evidence shape
// stay identical across collectors. SourceKind is AIService to satisfy
// the kinds registry's EXPOSES_CREDENTIAL constraint (source must be an
// AIService — see sdk/ingest/kinds.go).
func ExposesCredentialEdge(sourceID, credID, engagementID, source, endpoint string) Edge {
	return CredentialEvidenceEdge(
		sourceID,
		credID,
		engagementID,
		source,
		endpoint,
		"exposed",
	)
}

// CredentialEvidenceEdge builds the EXPOSES_CREDENTIAL topology from an
// AIService source to a Credential target while making the evidence claim
// explicit. A credential reference with exposure_status=not_observed is not
// usable secret exposure.
func CredentialEvidenceEdge(
	sourceID, credID, engagementID, source, endpoint, exposureStatus string,
) Edge {
	riskWeight := 0.0
	assertionType := "credential_reference"
	if exposureStatus == "exposed" {
		riskWeight = 0.1
		assertionType = "observed_credential_exposure"
	}
	return Edge{
		Source:     sourceID,
		Target:     credID,
		Kind:       "EXPOSES_CREDENTIAL",
		SourceKind: "AIService",
		TargetKind: "Credential",
		Properties: map[string]any{
			"confidence":      1.0,
			"risk_weight":     riskWeight,
			"exposure_status": exposureStatus,
			"assertion_type":  assertionType,
			"evidence": map[string]any{
				"endpoint":      endpoint,
				"source":        source,
				"engagement_id": engagementID,
			},
		},
	}
}
