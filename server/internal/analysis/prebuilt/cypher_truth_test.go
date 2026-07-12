package prebuilt

import (
	"strings"
	"testing"
)

func TestUnknownAuthAndSignatureDoNotMatchAbsenceQueries(t *testing.T) {
	for name, query := range map[string]string{
		"mcp": CypherNoAuthServers,
		"a2a": CypherNoAuthA2A,
	} {
		if strings.Contains(query, "auth_method IS NULL") {
			t.Errorf("%s no-auth query treats unknown as none:\n%s", name, query)
		}
		if !strings.Contains(query, "auth_method = 'none'") {
			t.Errorf("%s no-auth query lacks explicit-none predicate", name)
		}
		if !strings.Contains(query, "auth_evidence = 'anonymous_probe_succeeded'") {
			t.Errorf("%s no-auth query lacks explicit anonymous-probe evidence", name)
		}
	}
	if strings.Contains(CypherUnsignedCards, "is_signed IS NULL") {
		t.Fatalf("unsigned query treats unknown signature as unsigned:\n%s", CypherUnsignedCards)
	}
	if !strings.Contains(CypherUnsignedCards, "signature_verification_status = 'unsigned'") {
		t.Fatal("unsigned query lacks explicit rich-status predicate")
	}
}

func TestChokepointQueryReturnsAnonymousEvidence(t *testing.T) {
	if !strings.Contains(
		CypherChokepointServers,
		"s.auth_evidence AS auth_evidence",
	) {
		t.Fatalf(
			"chokepoint query cannot distinguish confirmed anonymous access:\n%s",
			CypherChokepointServers,
		)
	}
}

func TestHighEntropyQueryRequiresObservedMaterial(t *testing.T) {
	for _, clause := range []string{
		"c.material_status = 'observed'",
		"c.exposure_status = 'exposed'",
		"c.merge_key = 'value_hash'",
	} {
		if !strings.Contains(CypherHighEntropySecrets, clause) {
			t.Errorf("high-entropy query missing explicit evidence gate %q", clause)
		}
	}
	if strings.Contains(CypherHighEntropySecrets, "material_status IS NULL") ||
		strings.Contains(CypherHighEntropySecrets, "exposure_status IS NULL") {
		t.Fatal("high-entropy query accepts legacy missing evidence as observed exposure")
	}
}

func TestLiteLLMMasterExposureQueryKeepsReferencesNonUsable(t *testing.T) {
	for _, clause := range []string{
		"master.material_status = 'observed'",
		"master.exposure_status = 'exposed'",
		"master_evidence.assertion_type = 'observed_credential_exposure'",
		"reference.material_status = 'masked'",
		"reference.material_status = 'hashed'",
		"reference.exposure_status = 'not_observed'",
		"false AS reference_contains_usable_material",
	} {
		if !strings.Contains(CypherLitellmCredentialLeak, clause) {
			t.Errorf("LiteLLM exposure query missing evidence gate %q", clause)
		}
	}
	if strings.Contains(CypherLitellmCredentialLeak, "reference.material_status = 'observed'") ||
		strings.Contains(CypherLitellmCredentialLeak, "reference.exposure_status = 'exposed'") {
		t.Fatal("LiteLLM exposure query promotes masked/hashed references to usable material")
	}
}

func TestCrossProtocolQueryLabelsHostCorrelationHypothesis(t *testing.T) {
	if !strings.Contains(CypherCrossProtocolPaths, "'hypothesis' AS evidence_state") ||
		!strings.Contains(CypherCrossProtocolPaths, "'shared_host' AS correlation") {
		t.Fatalf("cross-protocol query lacks hypothesis metadata:\n%s", CypherCrossProtocolPaths)
	}
	query, ok := Get("cross-protocol-paths")
	if !ok {
		t.Fatal("cross-protocol query missing")
	}
	if query.Severity == "critical" ||
		!strings.Contains(query.Description, "50%-confidence") ||
		!strings.Contains(query.Description, "not proven") {
		t.Fatalf("cross-protocol query metadata overstates correlation: %+v", query)
	}
}
