package riskscore

import (
	"context"
	"testing"

	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

func TestServerRiskScore_AllZero(t *testing.T) {
	mock := &graph.MockGraphDB{QueryResult: nil}
	score, err := ServerRiskScore(context.Background(), mock, "server-1")
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	// No data for tool/exposure/cred, but auth defaults to 100 for missing node
	// auth=100 (no rows means 100). score = 0.35*100 = 35
	if score != 35 {
		t.Errorf("score = %f, want 35", score)
	}
}

func TestServerRiskScore_AuthStrength(t *testing.T) {
	tests := []struct {
		name     string
		method   string
		expected float64
	}{
		{"no auth", "none", 100},
		{"apiKey", "apiKey", 70},
		{"bearer", "bearer", 50},
		{"oauth", "oauth", 25},
		{"mtls", "mtls", 10},
		{"unknown defaults to 100", "magic", 100},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &graph.MockGraphDB{
				QueryFunc: func(_ context.Context, cypher string, _ map[string]any) ([]map[string]any, error) {
					if containsSubstring(cypher, "auth_method") {
						return []map[string]any{{"am": tt.method}}, nil
					}
					return nil, nil
				},
			}

			score, err := ServerRiskScore(context.Background(), mock, "server-1")
			if err != nil {
				t.Fatalf("error = %v", err)
			}
			// score = 0.35*auth + 0 + 0 + 0
			want := 0.35 * tt.expected
			want = roundTo2(want)
			if score != want {
				t.Errorf("score = %f, want %f", score, want)
			}
		})
	}
}

func TestServerRiskScore_ToolRisk(t *testing.T) {
	mock := &graph.MockGraphDB{
		QueryFunc: func(_ context.Context, cypher string, _ map[string]any) ([]map[string]any, error) {
			if containsSubstring(cypher, "auth_method") {
				return []map[string]any{{"am": "oauth"}}, nil
			}
			if containsSubstring(cypher, "capability_surface") {
				return []map[string]any{
					{"caps": []any{"shell_access", "file_read"}},
				}, nil
			}
			return nil, nil
		},
	}

	score, err := ServerRiskScore(context.Background(), mock, "server-1")
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	// auth=25, tool=100 (shell_access), exp=0, cred=0
	// score = 0.35*25 + 0.25*100 = 8.75 + 25 = 33.75
	if score != 33.75 {
		t.Errorf("score = %f, want 33.75", score)
	}
}

func TestServerRiskScore_Exposure(t *testing.T) {
	tests := []struct {
		name     string
		row      map[string]any
		expected float64
	}{
		{"public", map[string]any{"pub": true, "priv": false, "loc": false}, 100},
		{"private", map[string]any{"pub": false, "priv": true, "loc": false}, 50},
		{"local", map[string]any{"pub": false, "priv": false, "loc": true}, 20},
		{"none", map[string]any{"pub": false, "priv": false, "loc": false}, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &graph.MockGraphDB{
				QueryFunc: func(_ context.Context, cypher string, _ map[string]any) ([]map[string]any, error) {
					if containsSubstring(cypher, "auth_method") {
						return []map[string]any{{"am": "mtls"}}, nil
					}
					if containsSubstring(cypher, "RUNS_ON") {
						return []map[string]any{tt.row}, nil
					}
					return nil, nil
				},
			}

			score, err := ServerRiskScore(context.Background(), mock, "server-1")
			if err != nil {
				t.Fatalf("error = %v", err)
			}
			// auth=10, tool=0, exp=tt.expected, cred=0
			want := roundTo2(0.35*10 + 0.20*tt.expected)
			if score != want {
				t.Errorf("score = %f, want %f", score, want)
			}
		})
	}
}

func TestServerRiskScore_CredentialHandling(t *testing.T) {
	tests := []struct {
		name     string
		row      map[string]any
		expected float64
	}{
		{"high entropy", map[string]any{"high_entropy": true, "cred_type": "envVar"}, 100},
		{"hardcoded", map[string]any{"high_entropy": false, "cred_type": "hardcoded"}, 100},
		{"normal", map[string]any{"high_entropy": false, "cred_type": "envVar"}, 50},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &graph.MockGraphDB{
				QueryFunc: func(_ context.Context, cypher string, _ map[string]any) ([]map[string]any, error) {
					if containsSubstring(cypher, "auth_method") {
						return []map[string]any{{"am": "mtls"}}, nil
					}
					if containsSubstring(cypher, "HAS_ENV_VAR") {
						return []map[string]any{tt.row}, nil
					}
					return nil, nil
				},
			}

			score, err := ServerRiskScore(context.Background(), mock, "server-1")
			if err != nil {
				t.Fatalf("error = %v", err)
			}
			// auth=10, tool=0, exp=0, cred=tt.expected
			want := roundTo2(0.35*10 + 0.20*tt.expected)
			if score != want {
				t.Errorf("score = %f, want %f", score, want)
			}
		})
	}
}

func TestServerRiskScore_QueryError(t *testing.T) {
	mock := &graph.MockGraphDB{QueryError: context.Canceled}

	_, err := ServerRiskScore(context.Background(), mock, "server-1")
	if err == nil {
		t.Fatal("expected error")
	}
}

func roundTo2(v float64) float64 {
	return float64(int(v*100+0.5)) / 100
}
