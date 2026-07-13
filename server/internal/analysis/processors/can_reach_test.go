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
	if len(deps) != 1 || deps[0] != "has_access_to" {
		t.Errorf("Dependencies() = %v, want [has_access_to]", deps)
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
	credential, _ := calls[1].Args[0].(string)
	if !strings.Contains(credential, "current.scan_id = $scan_id") {
		t.Fatalf("credential pass must preserve a direct path refreshed this scan:\n%s", credential)
	}
	if !strings.Contains(credential, "NOT EXISTS {") ||
		!strings.Contains(credential, "MATCH (a)-[current:CAN_REACH]->(r)") {
		t.Fatalf("credential pass must use Neo4j-4.4-compatible EXISTS subquery:\n%s", credential)
	}
	if strings.Contains(credential, "s1.auth_method IS NULL OR") ||
		!strings.Contains(credential, "s1.auth_assurance IN ['unauthenticated', 'weak']") {
		t.Fatalf("unknown auth must not satisfy credential delegation:\n%s", credential)
	}
}

// TestCanReach_VerifiedUpgradeQuery asserts the third query re-correlates a raw
// CREDENTIAL_REACH_VERIFIED edge against the live credential identity + topology
// and upgrades the CAN_REACH edge in place (no new edge, no double-count).
func TestCanReach_VerifiedUpgradeQuery(t *testing.T) {
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
	// Re-correlation must bind the LIVE credential identity to the witness echo.
	for _, needle := range []string{
		"CREDENTIAL_REACH_VERIFIED",
		"c.value_hash = v.credential_value_hash",
		"c.merge_key = v.credential_merge_key",
		"r.objectid = v.resource_id",
		"PROVIDES_RESOURCE",
		"reach_evidence_state = 'verified'",
		"c.objectid IN e.evidence_node_ids",
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
