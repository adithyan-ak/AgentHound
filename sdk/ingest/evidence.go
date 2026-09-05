package ingest

type EvidenceState string

const (
	EvidenceConfigured EvidenceState = "configured"
	EvidenceObserved   EvidenceState = "observed"
	EvidenceVerified   EvidenceState = "verified"
)

func ValidEvidenceState(value string) bool {
	switch EvidenceState(value) {
	case EvidenceConfigured, EvidenceObserved, EvidenceVerified:
		return true
	default:
		return false
	}
}

// RequiresEvidenceState preserves historical V1 raw relationships while
// requiring the explicit evidence contract for the new topology vocabulary.
func RequiresEvidenceState(edgeKind, sourceKind, targetKind string) bool {
	if edgeKind == "USES_BACKEND" || edgeKind == "STORED_IN" {
		return true
	}
	return edgeKind == "PROVIDES_RESOURCE" && targetKind != "MCPResource"
}
