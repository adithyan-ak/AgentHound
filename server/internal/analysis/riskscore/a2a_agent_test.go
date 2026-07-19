package riskscore

import (
	"context"
	"testing"

	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

func TestA2AAgentRiskAssessmentUnknownAuth(t *testing.T) {
	mock := &graph.MockGraphDB{
		QueryFunc: func(_ context.Context, cypher string, _ map[string]any) ([]map[string]any, error) {
			if containsSubstring(cypher, "auth_method") {
				return []map[string]any{{"am": "unknown"}}, nil
			}
			return nil, nil
		},
	}
	assessment, err := A2AAgentRiskAssessment(context.Background(), mock, "a2a-1")
	if err != nil {
		t.Fatalf("A2AAgentRiskAssessment: %v", err)
	}
	if assessment.Complete || assessment.Min != 0 || assessment.Max != 30 ||
		len(assessment.UnknownFactors) != 1 ||
		assessment.UnknownFactors[0] != "auth_method" {
		t.Fatalf("unknown auth assessment = %+v", assessment)
	}
}

func TestA2AAuthAssessmentRequiresExplicitAnonymousEvidence(t *testing.T) {
	for _, test := range []struct {
		name       string
		evidence   string
		complete   bool
		unknownKey string
	}{
		{
			name:       "missing evidence remains bounded unknown",
			unknownKey: "auth_evidence",
		},
		{
			name:       "unknown evidence remains bounded unknown",
			evidence:   "unknown",
			unknownKey: "auth_evidence",
		},
		{
			name:     "successful anonymous probe is exact",
			evidence: "anonymous_probe_succeeded",
			complete: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			db := &graph.MockGraphDB{QueryResult: []map[string]any{{
				"am": "none", "auth_assurance": "unauthenticated",
				"auth_evidence": test.evidence, "auth_source": "observed",
			}}}
			assessment, err := a2aAuthAssessment(context.Background(), db, "a2a")
			if err != nil {
				t.Fatal(err)
			}
			if assessment.Complete != test.complete {
				t.Fatalf("assessment = %+v, want complete=%v", assessment, test.complete)
			}
			if test.complete {
				if assessment.Score != 100 ||
					assessment.Min != 100 ||
					assessment.Max != 100 {
					t.Fatalf("confirmed anonymous assessment = %+v", assessment)
				}
				return
			}
			if assessment.Score != 100 ||
				assessment.Min != 0 ||
				assessment.Max != 100 ||
				len(assessment.UnknownFactors) != 1 ||
				assessment.UnknownFactors[0] != test.unknownKey {
				t.Fatalf("unconfirmed anonymous assessment = %+v", assessment)
			}
		})
	}
}

func TestA2AAuthAssessmentUsesMaterializedEffectiveFields(t *testing.T) {
	var captured string
	db := &graph.MockGraphDB{
		QueryFunc: func(_ context.Context, cypher string, _ map[string]any) ([]map[string]any, error) {
			captured = cypher
			return []map[string]any{{
				"am": "mtls", "auth_evidence": "declared_security_scheme",
			}}, nil
		},
	}
	assessment, err := a2aAuthAssessment(context.Background(), db, "a2a")
	if err != nil {
		t.Fatal(err)
	}
	if !assessment.Complete || assessment.Score != 10 {
		t.Fatalf("A2A effective configured assessment = %+v", assessment)
	}
	if !containsSubstring(captured, "a.effective_auth_method AS am") ||
		!containsSubstring(captured, "a.effective_auth_assurance AS auth_assurance") ||
		!containsSubstring(captured, "a.effective_auth_evidence AS auth_evidence") ||
		!containsSubstring(captured, "a.effective_auth_source AS auth_source") ||
		containsSubstring(captured, "a.observed_auth_") {
		t.Fatalf("A2A risk did not use its materialized effective tuple:\n%s", captured)
	}
}

func TestA2AAuthAssessmentRejectsConfiguredAnonymousClaim(t *testing.T) {
	db := &graph.MockGraphDB{QueryResult: []map[string]any{{
		"am": "none", "auth_assurance": "unknown",
		"auth_evidence": "anonymous_probe_succeeded", "auth_source": "configured",
	}}}
	assessment, err := a2aAuthAssessment(context.Background(), db, "a2a")
	if err != nil {
		t.Fatal(err)
	}
	if assessment.Complete || len(assessment.UnknownFactors) != 1 ||
		assessment.UnknownFactors[0] != "auth_source" {
		t.Fatalf("configured anonymous claim was treated as observed: %+v", assessment)
	}
}
