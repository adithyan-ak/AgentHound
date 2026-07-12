package processors

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

func TestCrossServiceCredentialChain_Name(t *testing.T) {
	p := &CrossServiceCredentialChain{}
	if p.Name() != "cross_service_credential_chain" {
		t.Errorf("Name() = %q, want cross_service_credential_chain", p.Name())
	}
}

// TestCrossServiceCredentialChain_Dependencies guards the v0.2 design
// decision (resolved during the architect-review pass) that this
// processor depends on BOTH has_access_to AND can_reach. A future
// refactor that drops can_reach from the dependency list re-introduces
// a race where the runner could schedule cross_service before
// can_reach and the credential-chain demo would silently miss findings.
func TestCrossServiceCredentialChain_Dependencies(t *testing.T) {
	p := &CrossServiceCredentialChain{}
	deps := p.Dependencies()
	if len(deps) != 2 {
		t.Fatalf("Dependencies() = %v, want 2 entries", deps)
	}
	wantSet := map[string]bool{"has_access_to": true, "can_reach": true}
	for _, d := range deps {
		if !wantSet[d] {
			t.Errorf("unexpected dependency %q", d)
		}
		delete(wantSet, d)
	}
	if len(wantSet) > 0 {
		t.Errorf("missing dependencies: %v", wantSet)
	}
}

func TestCrossServiceCredentialChain_ProcessSuccess(t *testing.T) {
	mock := &graph.MockGraphDB{ExecuteWriteResult: 3}
	p := &CrossServiceCredentialChain{}
	stats, err := p.Process(context.Background(), mock, "scan-1")
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if stats.ProcessorName != "cross_service_credential_chain" {
		t.Errorf("ProcessorName = %q", stats.ProcessorName)
	}
	if stats.EdgesCreated != 3 {
		t.Errorf("EdgesCreated = %d, want 3", stats.EdgesCreated)
	}
	calls := mock.CallsTo("ExecuteWrite")
	if len(calls) != 1 {
		t.Errorf("ExecuteWrite called %d times, want 1", len(calls))
	}
}

func TestCrossServiceCredentialChain_ProcessError(t *testing.T) {
	mock := &graph.MockGraphDB{ExecuteWriteError: errors.New("cypher boom")}
	p := &CrossServiceCredentialChain{}
	_, err := p.Process(context.Background(), mock, "scan-1")
	if err == nil {
		t.Fatal("expected error")
	}
}

// TestCrossServiceCredentialChain_CypherJoinsOnValueHash guards the
// load-bearing claim of the v0.2 design: the join predicate is
// c1master.value_hash = c1.value_hash. If a future refactor changes
// the join to objectid (which would only fire on hand-loaded test
// fixtures) the credential-chain demo silently breaks. We assert the
// emitted Cypher contains the value_hash join predicate.
func TestCrossServiceCredentialChain_CypherJoinsOnValueHash(t *testing.T) {
	var captured string
	mock := &graph.MockGraphDB{
		ExecuteWriteFunc: func(_ context.Context, cypher string, _ map[string]any) (int, error) {
			captured = cypher
			return 0, nil
		},
	}
	p := &CrossServiceCredentialChain{}
	_, err := p.Process(context.Background(), mock, "scan-1")
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if !strings.Contains(captured, "value_hash") {
		t.Errorf("Cypher missing value_hash predicate; query:\n%s", captured)
	}
	// Specifically: the join is "c1master.value_hash = c1.value_hash".
	// Either ordering is fine.
	if !strings.Contains(captured, "c1master.value_hash = c1.value_hash") &&
		!strings.Contains(captured, "c1.value_hash = c1master.value_hash") {
		t.Errorf("Cypher missing the explicit c1master.value_hash = c1.value_hash join; query:\n%s", captured)
	}
	// source_collector remains required detector provenance even though
	// composite lifecycle is managed as one global epoch.
	if !strings.Contains(captured, "MERGE (a)-[e:CAN_REACH]->(c2)") {
		t.Errorf("Cypher missing CAN_REACH MERGE; query:\n%s", captured)
	}
	if !strings.Contains(captured, "source_collector") {
		t.Errorf("Cypher missing source_collector provenance; query:\n%s", captured)
	}
	if strings.Contains(captured, "NOT EXISTS((a)-[:CAN_REACH]->(c2))") {
		t.Errorf("Cypher must refresh existing CAN_REACH scan_id instead of skipping matches; query:\n%s", captured)
	}
}

// TestCrossServiceCredentialChain_MergeKeyFilter guards the U-MED-4
// filter clause: only canonical merge_key='value_hash' credentials may
// participate on either side of the value_hash join.
func TestCrossServiceCredentialChain_MergeKeyFilter(t *testing.T) {
	var captured string
	mock := &graph.MockGraphDB{
		ExecuteWriteFunc: func(_ context.Context, cypher string, _ map[string]any) (int, error) {
			captured = cypher
			return 0, nil
		},
	}
	p := &CrossServiceCredentialChain{}
	_, err := p.Process(context.Background(), mock, "scan-1")
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	// Both sides of the join must be filtered.
	for _, side := range []string{
		"c1.merge_key = 'value_hash'",
		"c1master.merge_key = 'value_hash'",
		"c1.material_status = 'observed'",
		"c1master.material_status = 'observed'",
		"c1.exposure_status = 'exposed'",
		"c1master.exposure_status = 'exposed'",
	} {
		if !strings.Contains(captured, side) {
			t.Errorf("Cypher missing merge_key filter %q; query:\n%s", side, captured)
		}
	}
	if strings.Contains(captured, "material_status IS NULL") ||
		strings.Contains(captured, "exposure_status IS NULL") ||
		strings.Contains(captured, "merge_key IS NULL") {
		t.Fatalf("detector accepts missing credential evidence as observed:\n%s", captured)
	}
	// The clause must NOT accidentally accept identity-marked nodes.
	if strings.Contains(captured, "merge_key = 'identity'") {
		t.Errorf("Cypher accidentally selects identity-marked nodes; query:\n%s", captured)
	}
}

func TestCrossServiceCredentialChain_PreservesPerAgentWitnesses(t *testing.T) {
	var captured string
	mock := &graph.MockGraphDB{
		ExecuteWriteFunc: func(_ context.Context, cypher string, _ map[string]any) (int, error) {
			captured = cypher
			return 0, nil
		},
	}
	if _, err := (&CrossServiceCredentialChain{}).Process(
		context.Background(),
		mock,
		"scan-1",
	); err != nil {
		t.Fatalf("Process: %v", err)
	}
	for _, witness := range []string{
		"id(trust)", "id(environment)", "id(exposes_master)",
		"id(exposes_upstream)", "witness.relationship_ids",
		"e.evidence_relationship_ids = witness_relationship_ids",
		"collect({\n  agent: a,\n  relationship_ids: agent_paths[0]\n}) AS agent_witnesses",
		"size(agent_witnesses) AS reachable_agents",
	} {
		if !strings.Contains(captured, witness) {
			t.Errorf("Cypher missing per-agent witness %q; query:\n%s", witness, captured)
		}
	}
	if strings.Contains(captured, "collect(DISTINCT {\n  agent: a,") {
		t.Errorf("blast radius must not count distinct agent/path tuples; query:\n%s", captured)
	}
}
