package processors

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

func TestCanReach_Name(t *testing.T) {
	p := &CanReach{}
	if p.Name() != "can_reach" {
		t.Errorf("Name() = %q, want can_reach", p.Name())
	}
}

func TestCanReach_Dependencies(t *testing.T) {
	p := &CanReach{}
	deps := p.Dependencies()
	if len(deps) != 2 || deps[0] != "auth_strength" || deps[1] != "has_access_to" {
		t.Errorf("Dependencies() = %v, want [auth_strength has_access_to]", deps)
	}
}

func TestCanReach_ProcessSuccess(t *testing.T) {
	mock := &graph.MockGraphDB{ExecuteWriteResult: 4}

	p := &CanReach{}
	stats, err := p.Process(context.Background(), mock, "scan-1")
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if stats.ProcessorName != "can_reach" {
		t.Errorf("ProcessorName = %q", stats.ProcessorName)
	}
	// 3 queries x 4 each = 12
	if stats.EdgesCreated != 12 {
		t.Errorf("EdgesCreated = %d, want 12", stats.EdgesCreated)
	}

	calls := mock.CallsTo("ExecuteWrite")
	if len(calls) != 3 {
		t.Errorf("ExecuteWrite called %d times, want 3 (direct + credential chain + verified upgrade)", len(calls))
	}
	direct, _ := calls[0].Args[0].(string)
	if strings.Contains(direct, "WHERE NOT EXISTS((a)-[:CAN_REACH]->(r))") {
		t.Fatalf("direct CAN_REACH must refresh an existing inferred edge:\n%s", direct)
	}
	if !strings.Contains(direct, "ts.effective_risk_weight <= 0.1") ||
		strings.Contains(direct, "ts.risk_weight <=") {
		t.Fatalf("direct confidence must use the derived effective trust weight:\n%s", direct)
	}
	credential, _ := calls[1].Args[0].(string)
	if !strings.Contains(credential, "current.scan_id = $scan_id") {
		t.Fatalf("credential pass must preserve a direct path refreshed this scan:\n%s", credential)
	}
	if !strings.Contains(credential, "NOT EXISTS {") ||
		!strings.Contains(credential, "MATCH (a)-[current:CAN_REACH]->(r)") {
		t.Fatalf("credential pass must use Neo4j-4.4-compatible EXISTS subquery:\n%s", credential)
	}
	if strings.Contains(credential, "coalesce(s1.observed_auth_assurance, s1.auth_assurance)") ||
		strings.Contains(credential, "s1.effective_auth_assurance IN ['unauthenticated', 'weak']") ||
		!strings.Contains(credential, "s1.effective_auth_assurance = 'unauthenticated'") ||
		!strings.Contains(credential, "s1.effective_auth_source = 'observed'") ||
		!strings.Contains(credential, "OR s1.effective_auth_assurance = 'weak'") {
		t.Fatalf("unknown auth must not satisfy credential delegation:\n%s", credential)
	}
	if strings.Contains(credential, "HAS_ENV_VAR") ||
		!strings.Contains(credential, "MATCH (s2:MCPServer)-[authenticates:AUTHENTICATES_WITH]->(i:Identity)-[uses:USES_CREDENTIAL]->(c:Credential)") {
		t.Fatalf("credential pass must use the canonical auth/uses topology, independent of credential location:\n%s", credential)
	}
	for _, predicate := range []string{
		"c.value_hash IS NOT NULL AND c.value_hash <> ''",
		"c.merge_key = 'value_hash'",
		"c.identity_basis = 'value_hash'",
		"c.material_status = 'observed'",
		"c.exposure_status = 'exposed'",
	} {
		if !strings.Contains(credential, predicate) {
			t.Fatalf("credential pass accepts a non-runnable credential; missing %q:\n%s", predicate, credential)
		}
	}
	if !strings.Contains(
		credential,
		"ORDER BY a.objectid, s1.objectid, t1.objectid, s2.objectid,\n"+
			"         i.objectid, c.objectid, t2.objectid, r.objectid",
	) || !strings.Contains(credential, "})[0] AS winner") {
		t.Fatalf("credential paths must reduce by the complete stable object-ID tuple:\n%s", credential)
	}
	orderStart := strings.Index(credential, "ORDER BY")
	winnerStart := strings.Index(credential, "})[0] AS winner")
	if orderStart < 0 || winnerStart < orderStart ||
		strings.Contains(credential[orderStart:winnerStart], "id(") {
		t.Fatalf("relationship IDs must not participate in credential-path selection:\n%s", credential)
	}
	compactCredential := strings.Join(strings.Fields(credential), " ")
	for _, orderedEvidence := range []string{
		"a.objectid, winner.s1.objectid, winner.t1.objectid, winner.s2.objectid, winner.i.objectid, winner.c.objectid, winner.t2.objectid, r.objectid",
		"id(winner.trust1), id(winner.provides1), id(winner.authenticates), id(winner.uses), id(winner.provides2), id(winner.access)",
	} {
		if !strings.Contains(compactCredential, orderedEvidence) {
			t.Fatalf("credential pass must persist canonical ordered evidence %q:\n%s", orderedEvidence, credential)
		}
	}
}

// The third query correlates same-scan proof directly through its Credential
// endpoint and upgrades the existing prediction without creating another edge.
func TestCanReach_ProofUpgradeQuery(t *testing.T) {
	mock := &graph.MockGraphDB{ExecuteWriteResult: 1}
	p := &CanReach{}
	if _, err := p.Process(context.Background(), mock, "scan-1"); err != nil {
		t.Fatalf("Process: %v", err)
	}
	calls := mock.CallsTo("ExecuteWrite")
	if len(calls) != 3 {
		t.Fatalf("ExecuteWrite called %d times, want 3", len(calls))
	}
	upgrade, _ := calls[2].Args[0].(string)
	for _, needle := range []string{
		"CREDENTIAL_ACCESS_OBSERVED",
		"v.scan_id = $scan_id",
		"c.objectid IN coalesce(e.evidence_node_ids, [])",
		"reach_evidence_state = 'verified'",
		"e.proof_action_id = v.action_id",
		"e.proof_credential_status = v.credential_status",
		"e.proof_cleanup_status = v.cleanup_status",
	} {
		if !strings.Contains(upgrade, needle) {
			t.Fatalf("verified-upgrade query missing %q:\n%s", needle, upgrade)
		}
	}
	// The upgrade must NOT MERGE/CREATE a new edge (no duplicate finding).
	if strings.Contains(upgrade, "MERGE (a)-[e:CAN_REACH]") || strings.Contains(upgrade, "CREATE (") {
		t.Fatalf("verified-upgrade must not create a second CAN_REACH edge:\n%s", upgrade)
	}
	if !strings.Contains(upgrade, "e.confidence = 1.0") {
		t.Fatalf("verified-upgrade must raise confidence:\n%s", upgrade)
	}
	if strings.Contains(upgrade, "witness") || strings.Contains(upgrade, "campaign") {
		t.Fatalf("same-scan proof upgrade retained campaign/witness coupling:\n%s", upgrade)
	}
}

func TestCanReach_ProcessFirstQueryError(t *testing.T) {
	mock := &graph.MockGraphDB{ExecuteWriteError: errors.New("query failed")}

	p := &CanReach{}
	_, err := p.Process(context.Background(), mock, "scan-1")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCanReach_ProcessSecondQueryError(t *testing.T) {
	callCount := 0
	mock := &graph.MockGraphDB{
		ExecuteWriteFunc: func(_ context.Context, _ string, _ map[string]any) (int, error) {
			callCount++
			if callCount == 2 {
				return 0, errors.New("credential chain query failed")
			}
			return 3, nil
		},
	}

	p := &CanReach{}
	_, err := p.Process(context.Background(), mock, "scan-1")
	if err == nil {
		t.Fatal("expected error on second query")
	}
}
