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
				"am": "none", "auth_evidence": test.evidence,
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
