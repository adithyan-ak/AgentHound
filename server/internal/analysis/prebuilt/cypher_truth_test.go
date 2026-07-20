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
		if strings.Contains(query, "effective_auth_method IS NULL") {
			t.Errorf("%s no-auth query treats unknown as none:\n%s", name, query)
		}
		if !strings.Contains(query, "effective_auth_method = 'none'") {
			t.Errorf("%s no-auth query lacks explicit-none predicate", name)
		}
		if !strings.Contains(query, "effective_auth_assurance = 'unauthenticated'") ||
			!strings.Contains(query, "effective_auth_evidence = 'anonymous_probe_succeeded'") {
			t.Errorf("%s no-auth query lacks explicit anonymous-probe evidence", name)
		}
	}
	for name, query := range map[string]string{
		"MCP": CypherNoAuthServers,
		"A2A": CypherNoAuthA2A,
	} {
		if !strings.Contains(query, "effective_auth_source = 'observed'") {
			t.Fatalf("%s no-auth query must require runtime observation:\n%s", name, query)
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
		"s.effective_auth_evidence AS auth_evidence",
	) {
		t.Fatalf(
			"chokepoint query cannot distinguish confirmed anonymous access:\n%s",
			CypherChokepointServers,
		)
	}
}

func TestAuthDisplayingPrebuiltQueriesUseEffectiveTuple(t *testing.T) {
	for name, query := range map[string]string{
		"agents shell": CypherAgentsShellAccess,
		"chokepoints":  CypherChokepointServers,
	} {
		if !strings.Contains(query, "s.effective_auth_method AS auth_method") {
			t.Errorf("%s query displays configured auth instead of effective auth:\n%s", name, query)
		}
		if strings.Contains(query, "s.auth_method AS auth_method") {
			t.Errorf("%s query still displays stale configured auth:\n%s", name, query)
		}
	}
	if !strings.Contains(CypherChokepointServers, "s.effective_auth_evidence AS auth_evidence") {
		t.Fatalf("chokepoint query omits effective evidence:\n%s", CypherChokepointServers)
	}
	for name, query := range map[string]string{
		"agents shell": CypherAgentsShellAccess,
		"MCP no auth":  CypherNoAuthServers,
		"A2A no auth":  CypherNoAuthA2A,
		"chokepoints":  CypherChokepointServers,
	} {
		if !strings.Contains(query, "effective_auth_source AS auth_source") {
			t.Errorf("%s query omits effective auth source:\n%s", name, query)
		}
	}
}

func TestHighEntropyQueryRequiresObservedMaterial(t *testing.T) {
	for _, clause := range []string{
		"c.material_status = 'observed'",
		"c.exposure_status = 'exposed'",
		"c.merge_key = 'value_hash'",
		"-[:AUTHENTICATES_WITH]->(:Identity)-[:USES_CREDENTIAL]->(c)",
		"RETURN DISTINCT",
	} {
		if !strings.Contains(CypherHighEntropySecrets, clause) {
			t.Errorf("high-entropy query missing explicit evidence gate %q", clause)
		}
	}
	if strings.Contains(CypherHighEntropySecrets, "material_status IS NULL") ||
		strings.Contains(CypherHighEntropySecrets, "exposure_status IS NULL") {
		t.Fatal("high-entropy query accepts legacy missing evidence as observed exposure")
	}
	if strings.Contains(CypherHighEntropySecrets, "HAS_ENV_VAR") ||
		strings.Contains(CypherHighEntropySecrets, "location") {
		t.Fatalf("high-entropy query attributes credentials by config location instead of canonical authentication topology:\n%s", CypherHighEntropySecrets)
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
