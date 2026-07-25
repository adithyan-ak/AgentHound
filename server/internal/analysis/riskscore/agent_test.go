package riskscore

import (
	"context"
	"testing"

	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

func TestAgentRiskScore_AllZero(t *testing.T) {
	mock := &graph.MockGraphDB{QueryResult: nil}
	score, err := AgentRiskScore(context.Background(), mock, "agent-1")
	if err != nil {
		t.Fatalf("AgentRiskScore() error = %v", err)
	}
	if score != 10 {
		t.Errorf("score = %f, want 10 (unknown instruction loading bound)", score)
	}
}

func TestAgentRiskScore_HighEntropyCreds(t *testing.T) {
	mock := &graph.MockGraphDB{
		QueryFunc: func(_ context.Context, cypher string, _ map[string]any) ([]map[string]any, error) {
			if containsSubstring(cypher, "USES_CREDENTIAL") {
				return []map[string]any{
					{
						"high_entropy": true, "cred_type": "envVar",
						"merge_key": "value_hash", "material_status": "observed",
						"exposure_status": "exposed",
					},
				}, nil
			}
			return nil, nil
		},
	}

	score, err := AgentRiskScore(context.Background(), mock, "agent-1")
	if err != nil {
		t.Fatalf("AgentRiskScore() error = %v", err)
	}
	// cred=100 and unknown instruction loading. score = 30 + 10.
	if score != 40 {
		t.Errorf("score = %f, want 40", score)
	}
}

func TestAgentRiskScore_HardcodedCreds(t *testing.T) {
	mock := &graph.MockGraphDB{
		QueryFunc: func(_ context.Context, cypher string, _ map[string]any) ([]map[string]any, error) {
			if containsSubstring(cypher, "USES_CREDENTIAL") {
				return []map[string]any{
					{
						"high_entropy": false, "cred_type": "hardcoded",
						"merge_key": "value_hash", "material_status": "observed",
						"exposure_status": "exposed",
					},
				}, nil
			}
			return nil, nil
		},
	}

	score, err := AgentRiskScore(context.Background(), mock, "agent-1")
	if err != nil {
		t.Fatalf("AgentRiskScore() error = %v", err)
	}
	if score != 40 {
		t.Errorf("score = %f, want 40", score)
	}
}

func TestAgentRiskScore_NormalCreds(t *testing.T) {
	mock := &graph.MockGraphDB{
		QueryFunc: func(_ context.Context, cypher string, _ map[string]any) ([]map[string]any, error) {
			if containsSubstring(cypher, "USES_CREDENTIAL") {
				return []map[string]any{
					{
						"high_entropy": false, "cred_type": "envVar",
						"merge_key": "value_hash", "material_status": "observed",
						"exposure_status": "exposed",
					},
				}, nil
			}
			return nil, nil
		},
	}

	score, err := AgentRiskScore(context.Background(), mock, "agent-1")
	if err != nil {
		t.Fatalf("AgentRiskScore() error = %v", err)
	}
	// cred=60 and unknown instruction loading. score = 18 + 10.
	if score != 28 {
		t.Errorf("score = %f, want 28", score)
	}
}

func TestAgentCredentialRiskUsesCanonicalTopologyForEveryConfigLocation(t *testing.T) {
	for _, location := range []string{"header", "arg:1", "url_query:token"} {
		t.Run(location, func(t *testing.T) {
			var captured string
			mock := &graph.MockGraphDB{
				QueryFunc: func(_ context.Context, cypher string, _ map[string]any) ([]map[string]any, error) {
					captured = cypher
					return []map[string]any{{
						"location": location, "high_entropy": true, "cred_type": "hardcoded",
						"merge_key": "value_hash", "material_status": "observed",
						"exposure_status": "exposed",
					}}, nil
				},
			}

			risk, err := agentCredentialRisk(context.Background(), mock, "agent-1")
			if err != nil {
				t.Fatalf("agentCredentialRisk: %v", err)
			}
			if risk != 100 {
				t.Fatalf("risk = %v, want 100 for %s credential", risk, location)
			}
			assertCanonicalCredentialRiskQuery(t, captured)
		})
	}
}

func assertCanonicalCredentialRiskQuery(t *testing.T, cypher string) {
	t.Helper()
	for _, clause := range []string{
		"TRUSTS_SERVER",
		"-[:AUTHENTICATES_WITH]->(:Identity)-[:USES_CREDENTIAL]->(c:Credential)",
		"WITH DISTINCT c",
		"c.value_hash IS NOT NULL",
		"c.value_hash <> ''",
		"c.merge_key = 'value_hash'",
		"c.identity_basis = 'value_hash'",
		"c.material_status = 'observed'",
		"c.exposure_status = 'exposed'",
	} {
		if !containsSubstring(cypher, clause) {
			t.Errorf("credential risk query missing %q:\n%s", clause, cypher)
		}
	}
	if containsSubstring(cypher, "HAS_ENV_VAR") || containsSubstring(cypher, "location") {
		t.Fatalf("credential risk query still depends on config location:\n%s", cypher)
	}
}

func TestAgentRiskScore_BlastRadius(t *testing.T) {
	mock := &graph.MockGraphDB{
		QueryFunc: func(_ context.Context, cypher string, _ map[string]any) ([]map[string]any, error) {
			if containsSubstring(cypher, "CAN_REACH") {
				return []map[string]any{{"cnt": int64(5)}}, nil
			}
			return nil, nil
		},
	}

	score, err := AgentRiskScore(context.Background(), mock, "agent-1")
	if err != nil {
		t.Fatalf("AgentRiskScore() error = %v", err)
	}
	// blast=50 and unknown instruction loading. score = 12.5 + 10.
	if score != 22.5 {
		t.Errorf("score = %f, want 22.5", score)
	}
}

func TestAgentRiskScore_BlastRadiusCapped(t *testing.T) {
	mock := &graph.MockGraphDB{
		QueryFunc: func(_ context.Context, cypher string, _ map[string]any) ([]map[string]any, error) {
			if containsSubstring(cypher, "CAN_REACH") {
				return []map[string]any{{"cnt": int64(20)}}, nil
			}
			return nil, nil
		},
	}

	score, err := AgentRiskScore(context.Background(), mock, "agent-1")
	if err != nil {
		t.Fatalf("AgentRiskScore() error = %v", err)
	}
	// blast=100 and unknown instruction loading. score = 25 + 10.
	if score != 35 {
		t.Errorf("score = %f, want 35", score)
	}
}

func TestAgentRiskScore_AuthPosture(t *testing.T) {
	var authQuery string
	mock := &graph.MockGraphDB{
		QueryFunc: func(_ context.Context, cypher string, _ map[string]any) ([]map[string]any, error) {
			if containsSubstring(cypher, "risk_weight") {
				authQuery = cypher
				return []map[string]any{{
					"rw":                       0.1,
					"auth_assessment_complete": true,
				}}, nil
			}
			return nil, nil
		},
	}

	assessment, err := AgentRiskAssessment(context.Background(), mock, "agent-1")
	if err != nil {
		t.Fatalf("AgentRiskAssessment() error = %v", err)
	}
	// auth=90 plus the unknown instruction-loading upper bound.
	if assessment.Complete ||
		assessment.Score != 28 ||
		assessment.Min != 18 ||
		assessment.Max != 28 ||
		len(assessment.UnknownFactors) != 1 ||
		assessment.UnknownFactors[0] != "agent_instruction_loading" {
		t.Errorf("assessment = %+v, want bounded score [18,28]", assessment)
	}
	if !containsSubstring(authQuery, "t.effective_risk_weight AS rw") ||
		!containsSubstring(authQuery, "t.effective_auth_assessment_complete AS auth_assessment_complete") ||
		containsSubstring(authQuery, "RETURN t.risk_weight AS rw") {
		t.Fatalf("agent risk did not consume the effective trust assessment:\n%s", authQuery)
	}
}

func TestAgentRiskAssessment_UnknownAuthIsBounded(t *testing.T) {
	mock := &graph.MockGraphDB{
		QueryFunc: func(_ context.Context, cypher string, _ map[string]any) ([]map[string]any, error) {
			if containsSubstring(cypher, "risk_weight") {
				return []map[string]any{{
					"rw":                       0.5,
					"auth_assessment_complete": false,
				}}, nil
			}
			return nil, nil
		},
	}

	assessment, err := AgentRiskAssessment(context.Background(), mock, "agent-1")
	if err != nil {
		t.Fatalf("AgentRiskAssessment() error = %v", err)
	}
	if assessment.Complete ||
		assessment.Score != 30 ||
		assessment.Min != 0 ||
		assessment.Max != 30 {
		t.Fatalf("assessment = %+v, want conservative combined bound [0,30]", assessment)
	}
	if len(assessment.UnknownFactors) != 2 ||
		assessment.UnknownFactors[0] != "agent_auth" ||
		assessment.UnknownFactors[1] != "agent_instruction_loading" {
		t.Fatalf(
			"unknown factors = %v, want [agent_auth agent_instruction_loading]",
			assessment.UnknownFactors,
		)
	}
}

func TestAgentRiskAssessment_MixedAuthCompletenessBoundsOnlyUnknownEdges(t *testing.T) {
	mock := &graph.MockGraphDB{
		QueryFunc: func(_ context.Context, cypher string, _ map[string]any) ([]map[string]any, error) {
			if containsSubstring(cypher, "risk_weight") {
				return []map[string]any{
					{
						"rw":                       0.9,
						"auth_assessment_complete": true,
					},
					{
						"rw":                       0.5,
						"auth_assessment_complete": false,
					},
				}, nil
			}
			return nil, nil
		},
	}

	assessment, err := AgentRiskAssessment(context.Background(), mock, "agent-1")
	if err != nil {
		t.Fatalf("AgentRiskAssessment() error = %v", err)
	}
	if assessment.Complete ||
		assessment.Score != 21 ||
		assessment.Min != 1 ||
		assessment.Max != 21 {
		t.Fatalf("assessment = %+v, want mixed combined bound [1,21]", assessment)
	}
	if len(assessment.UnknownFactors) != 2 ||
		assessment.UnknownFactors[0] != "agent_auth" ||
		assessment.UnknownFactors[1] != "agent_instruction_loading" {
		t.Fatalf(
			"unknown factors = %v, want [agent_auth agent_instruction_loading]",
			assessment.UnknownFactors,
		)
	}
}

func TestAgentRiskScore_ToolSurface(t *testing.T) {
	mock := &graph.MockGraphDB{
		QueryFunc: func(_ context.Context, cypher string, _ map[string]any) ([]map[string]any, error) {
			if containsSubstring(cypher, "PROVIDES_TOOL") {
				return []map[string]any{{"cnt": int64(10)}}, nil
			}
			return nil, nil
		},
	}

	score, err := AgentRiskScore(context.Background(), mock, "agent-1")
	if err != nil {
		t.Fatalf("AgentRiskScore() error = %v", err)
	}
	// tools=50 and unknown instruction loading. score = 7.5 + 10.
	if score != 17.5 {
		t.Errorf("score = %f, want 17.5", score)
	}
}

func TestAgentRiskScore_Poisoning(t *testing.T) {
	mock := &graph.MockGraphDB{
		QueryFunc: func(_ context.Context, cypher string, _ map[string]any) ([]map[string]any, error) {
			if containsSubstring(cypher, "LOADS_INSTRUCTIONS") {
				return []map[string]any{{"cnt": int64(1)}}, nil
			}
			return nil, nil
		},
	}

	score, err := AgentRiskScore(context.Background(), mock, "agent-1")
	if err != nil {
		t.Fatalf("AgentRiskScore() error = %v", err)
	}
	// poison = 100. score = 0.10*100 = 10
	if score != 10 {
		t.Errorf("score = %f, want 10", score)
	}
}

// Static discovery does not prove what an agent loads. With no suspicious
// evidence-backed LOADS_INSTRUCTIONS edge, poisoning exposure stays unknown.
func TestAgentRiskAssessment_PoisoningUnknownWithoutLoadEvidence(t *testing.T) {
	mock := &graph.MockGraphDB{
		QueryFunc: func(_ context.Context, cypher string, _ map[string]any) ([]map[string]any, error) {
			if containsSubstring(cypher, "LOADS_INSTRUCTIONS") {
				return []map[string]any{{"cnt": int64(0)}}, nil
			}
			return nil, nil
		},
	}

	assessment, err := AgentRiskAssessment(context.Background(), mock, "agent-1")
	if err != nil {
		t.Fatalf("AgentRiskAssessment() error = %v", err)
	}
	if assessment.Complete {
		t.Fatalf("assessment must be incomplete without load evidence: %+v", assessment)
	}
	if len(assessment.UnknownFactors) != 1 ||
		assessment.UnknownFactors[0] != "agent_instruction_loading" {
		t.Fatalf(
			"unknown factors = %v, want [agent_instruction_loading]",
			assessment.UnknownFactors,
		)
	}
	// poison Max=100 weighted 0.10 contributes up to 10 to the conservative bound.
	if assessment.Max < 10 {
		t.Fatalf("assessment max = %v, want >= 10 (poison upper bound included)", assessment.Max)
	}
}

func TestAgentRiskAssessment_PoisoningIgnoresInventoryCompletenessProperty(t *testing.T) {
	mock := &graph.MockGraphDB{
		QueryFunc: func(_ context.Context, cypher string, _ map[string]any) ([]map[string]any, error) {
			if containsSubstring(cypher, "LOADS_INSTRUCTIONS") {
				if containsSubstring(cypher, "instruction_coverage_complete") {
					t.Fatal("risk query conflates inventory coverage with load evidence")
				}
				return []map[string]any{{"cnt": int64(0)}}, nil
			}
			return nil, nil
		},
	}

	assessment, err := AgentRiskAssessment(context.Background(), mock, "agent-1")
	if err != nil {
		t.Fatalf("AgentRiskAssessment() error = %v", err)
	}
	if assessment.Complete ||
		len(assessment.UnknownFactors) != 1 ||
		assessment.UnknownFactors[0] != "agent_instruction_loading" {
		t.Fatalf("assessment = %+v, want unknown load relationship", assessment)
	}
}

func TestAgentRiskScore_QueryError(t *testing.T) {
	mock := &graph.MockGraphDB{QueryError: context.Canceled}

	_, err := AgentRiskScore(context.Background(), mock, "agent-1")
	if err == nil {
		t.Fatal("expected error")
	}
}

func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && contains(s, substr)
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
