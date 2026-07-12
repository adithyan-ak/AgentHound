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
	// Missing auth and host scope retain a conservative rankable score while
	// the assessment records both unknown factors.
	if score != 55 {
		t.Errorf("score = %f, want 55", score)
	}
}

func TestServerRiskScore_AuthStrength(t *testing.T) {
	tests := []struct {
		name     string
		method   string
		expected float64
	}{
		{"no auth", "none", 100},
		{"basic", "basic", 85},
		{"apiKey", "apiKey", 70},
		{"bearer", "bearer", 50},
		{"oauth", "oauth", 25},
		{"oidc", "oidc", 20},
		{"mtls", "mtls", 10},
		{"unknown uses conservative risk bound", "magic", 100},
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
			// Missing host scope contributes its conservative 100 upper bound.
			want := 0.35*tt.expected + 0.20*100
			want = roundTo2(want)
			if score != want {
				t.Errorf("score = %f, want %f", score, want)
			}
		})
	}
}

func TestServerAuthAssessmentRequiresExplicitAnonymousEvidence(t *testing.T) {
	for _, tt := range []struct {
		name     string
		evidence string
		complete bool
	}{
		{name: "missing evidence remains unknown"},
		{name: "unknown evidence remains unknown", evidence: "unknown"},
		{name: "successful anonymous probe is explicit", evidence: "anonymous_probe_succeeded", complete: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			db := &graph.MockGraphDB{QueryResult: []map[string]any{{
				"am": "none", "auth_evidence": tt.evidence,
			}}}
			assessment, err := serverAuthAssessment(context.Background(), db, "server")
			if err != nil {
				t.Fatal(err)
			}
			if assessment.Complete != tt.complete {
				t.Fatalf("assessment = %+v, want complete=%v", assessment, tt.complete)
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
	if score != 53.75 {
		t.Errorf("score = %f, want 53.75", score)
	}
}

func TestServerRiskScore_Exposure(t *testing.T) {
	tests := []struct {
		name     string
		row      map[string]any
		expected float64
	}{
		{"public", map[string]any{"scope": "public"}, 100},
		{"private", map[string]any{"scope": "private"}, 50},
		{"local", map[string]any{"scope": "local"}, 20},
		{"unknown", map[string]any{"scope": "unknown"}, 100},
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
		{"high entropy", map[string]any{
			"high_entropy": true, "cred_type": "envVar",
			"material_status": "observed", "exposure_status": "exposed", "merge_key": "value_hash",
		}, 100},
		{"hardcoded", map[string]any{
			"high_entropy": false, "cred_type": "hardcoded",
			"material_status": "observed", "exposure_status": "exposed", "merge_key": "value_hash",
		}, 100},
		{"normal", map[string]any{
			"high_entropy": false, "cred_type": "envVar",
			"material_status": "observed", "exposure_status": "exposed", "merge_key": "value_hash",
		}, 50},
		{"legacy missing evidence", map[string]any{
			"high_entropy": true, "cred_type": "hardcoded",
		}, 0},
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
			// Missing host scope contributes its conservative upper bound.
			want := roundTo2(0.35*10 + 0.20*100 + 0.20*tt.expected)
			if score != want {
				t.Errorf("score = %f, want %f", score, want)
			}
		})
	}
}

func TestServerRiskAssessmentDisclosesUnknownFactors(t *testing.T) {
	mock := &graph.MockGraphDB{QueryResult: nil}
	assessment, err := ServerRiskAssessment(context.Background(), mock, "server-1")
	if err != nil {
		t.Fatalf("ServerRiskAssessment: %v", err)
	}
	if assessment.Complete {
		t.Fatal("missing auth and host scope reported complete")
	}
	if assessment.Min != 0 || assessment.Max != 55 || assessment.Score != 55 {
		t.Fatalf("assessment bounds = %+v, want score/max 55 and min 0", assessment)
	}
	if len(assessment.UnknownFactors) != 2 ||
		assessment.UnknownFactors[0] != "auth_method" ||
		assessment.UnknownFactors[1] != "host_scope" {
		t.Fatalf("unknown factors = %v", assessment.UnknownFactors)
	}
}

func TestServerRiskScoreIgnoresUnobservedCredentialMaterial(t *testing.T) {
	mock := &graph.MockGraphDB{
		QueryFunc: func(_ context.Context, cypher string, _ map[string]any) ([]map[string]any, error) {
			switch {
			case containsSubstring(cypher, "auth_method"):
				return []map[string]any{{"am": "mtls"}}, nil
			case containsSubstring(cypher, "RUNS_ON"):
				return []map[string]any{{"scope": "local"}}, nil
			case containsSubstring(cypher, "HAS_ENV_VAR"):
				return []map[string]any{{
					"material_status": "masked",
					"exposure_status": "not_observed",
					"merge_key":       "identity",
					"high_entropy":    true,
					"cred_type":       "hardcoded",
				}}, nil
			default:
				return nil, nil
			}
		},
	}
	score, err := ServerRiskScore(context.Background(), mock, "server-1")
	if err != nil {
		t.Fatalf("ServerRiskScore: %v", err)
	}
	if score != 7.5 { // 0.35*10 auth + 0.20*20 local exposure
		t.Fatalf("masked identity affected credential risk: score=%v, want 7.5", score)
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
