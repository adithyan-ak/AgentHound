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
	if len(calls) != 1 {
		t.Fatalf("ExecuteWrite called %d times, want 1", len(calls))
	}

	cypher, _ := calls[0].Args[0].(string)
	if !contains(cypher, "SET n.auth_strength =") {
		t.Errorf("Cypher should SET the auth_strength property; query:\n%s", cypher)
	}
	if !contains(cypher, "n.auth_assurance =") {
		t.Errorf("Cypher should SET categorical auth_assurance; query:\n%s", cypher)
	}
	if !contains(cypher, "n.auth_evidence") ||
		!contains(cypher, "anonymous_probe_succeeded") {
		t.Errorf("explicit none must require anonymous-probe evidence; query:\n%s", cypher)
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
