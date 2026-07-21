package processors

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/adithyan-ak/agenthound/server/internal/analysis/riskscore"
	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

func TestAuthStrength_Name(t *testing.T) {
	p := &AuthStrength{}
	if p.Name() != "auth_strength" {
		t.Errorf("Name() = %q, want auth_strength", p.Name())
	}
}

func TestAuthStrength_Dependencies(t *testing.T) {
	p := &AuthStrength{}
	if deps := p.Dependencies(); deps != nil {
		t.Errorf("Dependencies() = %v, want nil", deps)
	}
}

func TestAuthStrength_ProcessSuccess(t *testing.T) {
	// auth_strength is a pre-pass that SETs a numeric node property; the
	// ExecuteWrite return is the node-update count, so it lands in
	// NodesUpdated (not EdgesCreated).
	mock := &graph.MockGraphDB{ExecuteWriteResult: 3}

	p := &AuthStrength{}
	stats, err := p.Process(context.Background(), mock, "scan-1")
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if stats.ProcessorName != "auth_strength" {
		t.Errorf("ProcessorName = %q", stats.ProcessorName)
	}
	if stats.NodesUpdated != 3 {
		t.Errorf("NodesUpdated = %d, want 3", stats.NodesUpdated)
	}
	if stats.EdgesCreated != 0 {
		t.Errorf("EdgesCreated = %d, want 0 (pre-pass writes no edges)", stats.EdgesCreated)
	}

	calls := mock.CallsTo("ExecuteWrite")
	if len(calls) != 2 {
		t.Fatalf("ExecuteWrite called %d times, want 2", len(calls))
	}

	cypher, _ := calls[0].Args[0].(string)
	if !contains(cypher, "n.auth_strength =") {
		t.Errorf("Cypher should SET the auth_strength property; query:\n%s", cypher)
	}
	for _, property := range []string{
		"n.effective_auth_method = effective_method",
		"n.effective_auth_assurance =",
		"n.effective_auth_evidence = effective_evidence",
		"n.effective_auth_source = effective_source",
	} {
		if !contains(cypher, property) {
			t.Errorf("Cypher should SET %s; query:\n%s", property, cypher)
		}
	}
	if contains(cypher, "SET n.auth_assurance =") ||
		contains(cypher, ", n.auth_assurance =") {
		t.Errorf("configured auth_assurance must remain immutable; query:\n%s", cypher)
	}
	if !contains(cypher, "effective_evidence") ||
		!contains(cypher, "anonymous_probe_succeeded") ||
		!contains(cypher, "coalesce(effective_source, 'configured') <> 'observed'") {
		t.Errorf("explicit none must require observed anonymous-probe evidence; query:\n%s", cypher)
	}
	for _, guard := range []string{
		"n.status = 'reachable'",
		"n.transport = 'http'",
		"n.observed_auth_method = 'none'",
		"n.observed_auth_assurance = 'unauthenticated'",
		"n.observed_auth_evidence = 'anonymous_probe_succeeded'",
		"n:A2AAgent",
		"n.auth_probe_method = 'get_task_nonexistent'",
		"n.auth_probe_status = 'anonymous_protocol_access'",
		"n.auth_probe_detail IN ['task_not_found_v1', 'task_not_found_v0_3']",
		"CASE WHEN use_observed THEN n.observed_auth_method ELSE n.auth_method END",
		"CASE WHEN use_observed THEN n.observed_auth_evidence ELSE n.auth_evidence END",
	} {
		if !contains(cypher, guard) {
			t.Errorf("effective tuple query missing %q; query:\n%s", guard, cypher)
		}
	}

	trustCypher, _ := calls[1].Args[0].(string)
	for _, guard := range []string{
		"MATCH ()-[t:TRUSTS_SERVER]->(s:MCPServer)",
		"s.effective_auth_source = 'observed'",
		"s.effective_auth_method = 'none'",
		"s.effective_auth_assurance = 'unauthenticated'",
		"s.effective_auth_evidence = 'anonymous_probe_succeeded'",
		"WHEN observed_anonymous THEN 0.1",
		"ELSE t.risk_weight",
		"WHEN observed_anonymous THEN true",
		"ELSE t.auth_assessment_complete",
		"t.effective_auth_source = CASE",
		"WHEN observed_anonymous THEN 'observed'",
		"ELSE 'configured'",
	} {
		if !contains(trustCypher, guard) {
			t.Errorf("effective trust query missing %q; query:\n%s", guard, trustCypher)
		}
	}

	// Drift guard: the CASE expression is built at runtime from
	// riskscore.AuthStrengthScores (authStrengthCase uses %g formatting).
	// If a future edit hard-codes the Cypher or the map drifts from the
	// rendered query, this loop catches it — every key→value pair the map
	// declares must appear verbatim in the emitted Cypher.
	for k, v := range riskscore.AuthStrengthScores {
		want := fmt.Sprintf("WHEN '%s' THEN %g", k, v)
		if !contains(cypher, want) {
			t.Errorf("Cypher missing CASE branch %q (AuthStrengthScores drift); query:\n%s", want, cypher)
		}
	}

	// Unknown/custom methods have no numeric weakness. Setting null also
	// removes a stale numeric property if richer evidence becomes unavailable.
	if !contains(cypher, "ELSE null END") {
		t.Errorf("Cypher must render unknown numeric auth as null; query:\n%s", cypher)
	}
}

func TestAuthStrengthScores_OIDCIsStrong(t *testing.T) {
	// AH-UI-15: OIDC (emitted by the A2A collector) is an OAuth2-based strong
	// scheme. It must be present and score no weaker than oauth.
	oidc, ok := riskscore.AuthStrengthScores["oidc"]
	if !ok {
		t.Fatal("AuthStrengthScores must include oidc")
	}
	if oidc > riskscore.AuthStrengthScores["oauth"] {
		t.Errorf("oidc weakness %g should be <= oauth %g", oidc, riskscore.AuthStrengthScores["oauth"])
	}
	if oidc >= 80 {
		t.Errorf("oidc weakness %g should be well below the confused_deputy weak threshold (80)", oidc)
	}
}

func TestAuthStrength_ProcessError(t *testing.T) {
	mock := &graph.MockGraphDB{ExecuteWriteError: errors.New("db error")}

	p := &AuthStrength{}
	_, err := p.Process(context.Background(), mock, "scan-1")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestAuthStrength_TrustMaterializationError(t *testing.T) {
	calls := 0
	mock := &graph.MockGraphDB{
		ExecuteWriteFunc: func(_ context.Context, _ string, _ map[string]any) (int, error) {
			calls++
			if calls == 2 {
				return 0, errors.New("trust materialization failed")
			}
			return 4, nil
		},
	}

	stats, err := (&AuthStrength{}).Process(context.Background(), mock, "scan-1")
	if err == nil {
		t.Fatal("expected trust materialization error")
	}
	if stats.NodesUpdated != 0 || stats.EdgesCreated != 0 {
		t.Fatalf("failed pre-pass reported partial success: %+v", stats)
	}
}
