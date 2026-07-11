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
