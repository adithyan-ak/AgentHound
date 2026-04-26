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
	if score != 0 {
		t.Errorf("score = %f, want 0 (no data)", score)
	}
}

func TestAgentRiskScore_HighEntropyCreds(t *testing.T) {
	mock := &graph.MockGraphDB{
		QueryFunc: func(_ context.Context, cypher string, _ map[string]any) ([]map[string]any, error) {
			if containsSubstring(cypher, "HAS_ENV_VAR") {
				return []map[string]any{
					{"high_entropy": true, "cred_type": "envVar"},
				}, nil
			}
			return nil, nil
		},
	}

	score, err := AgentRiskScore(context.Background(), mock, "agent-1")
	if err != nil {
		t.Fatalf("AgentRiskScore() error = %v", err)
	}
	// cred=100, rest=0. score = 0.30*100 = 30
	if score != 30 {
		t.Errorf("score = %f, want 30", score)
	}
}

func TestAgentRiskScore_HardcodedCreds(t *testing.T) {
	mock := &graph.MockGraphDB{
		QueryFunc: func(_ context.Context, cypher string, _ map[string]any) ([]map[string]any, error) {
			if containsSubstring(cypher, "HAS_ENV_VAR") {
				return []map[string]any{
					{"high_entropy": false, "cred_type": "hardcoded"},
				}, nil
			}
			return nil, nil
		},
	}

	score, err := AgentRiskScore(context.Background(), mock, "agent-1")
	if err != nil {
		t.Fatalf("AgentRiskScore() error = %v", err)
	}
	if score != 30 {
		t.Errorf("score = %f, want 30", score)
	}
}

func TestAgentRiskScore_NormalCreds(t *testing.T) {
	mock := &graph.MockGraphDB{
		QueryFunc: func(_ context.Context, cypher string, _ map[string]any) ([]map[string]any, error) {
			if containsSubstring(cypher, "HAS_ENV_VAR") {
				return []map[string]any{
					{"high_entropy": false, "cred_type": "envVar"},
				}, nil
			}
			return nil, nil
		},
	}

	score, err := AgentRiskScore(context.Background(), mock, "agent-1")
	if err != nil {
		t.Fatalf("AgentRiskScore() error = %v", err)
	}
	// cred=60, rest=0. score = 0.30*60 = 18
	if score != 18 {
		t.Errorf("score = %f, want 18", score)
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
	// blast = min(5*10, 100) = 50. score = 0.25*50 = 12.5
	if score != 12.5 {
		t.Errorf("score = %f, want 12.5", score)
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
	// blast = min(200, 100) = 100. score = 0.25*100 = 25
	if score != 25 {
		t.Errorf("score = %f, want 25", score)
	}
}

func TestAgentRiskScore_AuthPosture(t *testing.T) {
	mock := &graph.MockGraphDB{
		QueryFunc: func(_ context.Context, cypher string, _ map[string]any) ([]map[string]any, error) {
			if containsSubstring(cypher, "risk_weight") {
				return []map[string]any{{"rw": 0.1}}, nil
			}
			return nil, nil
		},
	}

	score, err := AgentRiskScore(context.Background(), mock, "agent-1")
	if err != nil {
		t.Fatalf("AgentRiskScore() error = %v", err)
	}
	// auth = (1 - 0.1) * 100 = 90. score = 0.20*90 = 18
	if score != 18 {
		t.Errorf("score = %f, want 18", score)
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
	// tools = min(10*5, 100) = 50. score = 0.15*50 = 7.5
	if score != 7.5 {
		t.Errorf("score = %f, want 7.5", score)
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
