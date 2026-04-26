package riskscore

import (
	"context"
	"testing"

	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

func TestToolRiskScore_AllZero(t *testing.T) {
	mock := &graph.MockGraphDB{QueryResult: nil}
	score, err := ToolRiskScore(context.Background(), mock, "tool-1")
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	// No rows for caps/poison/sensitivity. inputValidation returns 100 for no rows.
	// score = 0.20*100 = 20
	if score != 20 {
		t.Errorf("score = %f, want 20", score)
	}
}

func TestToolRiskScore_CapabilityClass(t *testing.T) {
	tests := []struct {
		name string
		caps []any
		want float64
	}{
		{"shell_access", []any{"shell_access"}, 100},
		{"code_execution", []any{"code_execution"}, 100},
		{"credential_access", []any{"credential_access"}, 90},
		{"database_access", []any{"database_access"}, 80},
		{"file_write", []any{"file_write"}, 70},
		{"network_outbound", []any{"network_outbound"}, 60},
		{"email_send", []any{"email_send"}, 50},
		{"file_read", []any{"file_read"}, 40},
		{"unknown", []any{"custom"}, 20},
		{"multiple picks max", []any{"file_read", "shell_access"}, 100},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &graph.MockGraphDB{
				QueryFunc: func(_ context.Context, cypher string, _ map[string]any) ([]map[string]any, error) {
					if containsSubstring(cypher, "capability_surface") && !containsSubstring(cypher, "PROVIDES_TOOL") {
						return []map[string]any{{"caps": tt.caps}}, nil
					}
					if containsSubstring(cypher, "input_schema") {
						return []map[string]any{{"schema": `{"type":"object"}`}}, nil
					}
					return nil, nil
				},
			}

			score, err := ToolRiskScore(context.Background(), mock, "tool-1")
			if err != nil {
				t.Fatalf("error = %v", err)
			}
			// cap=tt.want, poison=0, sensitivity=0, input=0 (has schema)
			want := roundTo2(0.30 * tt.want)
			if score != want {
				t.Errorf("score = %f, want %f", score, want)
			}
		})
	}
}

func TestToolRiskScore_Poisoning(t *testing.T) {
	tests := []struct {
		name string
		row  map[string]any
		want float64
	}{
		{"injection patterns", map[string]any{"injected": true, "xref": false}, 100},
		{"cross references", map[string]any{"injected": false, "xref": true}, 50},
		{"clean", map[string]any{"injected": false, "xref": false}, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &graph.MockGraphDB{
				QueryFunc: func(_ context.Context, cypher string, _ map[string]any) ([]map[string]any, error) {
					if containsSubstring(cypher, "injection_patterns") {
						return []map[string]any{tt.row}, nil
					}
					if containsSubstring(cypher, "input_schema") {
						return []map[string]any{{"schema": `{"type":"object"}`}}, nil
					}
					return nil, nil
				},
			}

			score, err := ToolRiskScore(context.Background(), mock, "tool-1")
			if err != nil {
				t.Fatalf("error = %v", err)
			}
			want := roundTo2(0.25 * tt.want)
			if score != want {
				t.Errorf("score = %f, want %f", score, want)
			}
		})
	}
}

func TestToolRiskScore_AccessSensitivity(t *testing.T) {
	tests := []struct {
		name        string
		sensitivity string
		want        float64
	}{
		{"critical", "critical", 100},
		{"high", "high", 75},
		{"medium", "medium", 50},
		{"low", "low", 25},
		{"none", "none", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &graph.MockGraphDB{
				QueryFunc: func(_ context.Context, cypher string, _ map[string]any) ([]map[string]any, error) {
					if containsSubstring(cypher, "HAS_ACCESS_TO") {
						return []map[string]any{{"sensitivity": tt.sensitivity}}, nil
					}
					if containsSubstring(cypher, "input_schema") {
						return []map[string]any{{"schema": `{"type":"object"}`}}, nil
					}
					return nil, nil
				},
			}

			score, err := ToolRiskScore(context.Background(), mock, "tool-1")
			if err != nil {
				t.Fatalf("error = %v", err)
			}
			want := roundTo2(0.25 * tt.want)
			if score != want {
				t.Errorf("score = %f, want %f", score, want)
			}
		})
	}
}

func TestToolRiskScore_InputValidation(t *testing.T) {
	tests := []struct {
		name   string
		schema any
		want   float64
	}{
		{"no schema", nil, 100},
		{"empty schema", "", 100},
		{"has schema", `{"type":"object"}`, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &graph.MockGraphDB{
				QueryFunc: func(_ context.Context, cypher string, _ map[string]any) ([]map[string]any, error) {
					if containsSubstring(cypher, "input_schema") {
						return []map[string]any{{"schema": tt.schema}}, nil
					}
					return nil, nil
				},
			}

			score, err := ToolRiskScore(context.Background(), mock, "tool-1")
			if err != nil {
				t.Fatalf("error = %v", err)
			}
			want := roundTo2(0.20 * tt.want)
			if score != want {
				t.Errorf("score = %f, want %f", score, want)
			}
		})
	}
}

func TestToolRiskScore_QueryError(t *testing.T) {
	mock := &graph.MockGraphDB{QueryError: context.Canceled}

	_, err := ToolRiskScore(context.Background(), mock, "tool-1")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCapabilityRisk(t *testing.T) {
	tests := []struct {
		cap  string
		want float64
	}{
		{"shell_access", 100},
		{"code_execution", 100},
		{"credential_access", 90},
		{"database_access", 80},
		{"file_write", 70},
		{"network_outbound", 60},
		{"email_send", 50},
		{"file_read", 40},
		{"unknown", 20},
	}
	for _, tt := range tests {
		if got := capabilityRisk(tt.cap); got != tt.want {
			t.Errorf("capabilityRisk(%q) = %f, want %f", tt.cap, got, tt.want)
		}
	}
}

func TestEdgeRiskWeight(t *testing.T) {
	tests := []struct {
		kind string
		auth string
		want float64
	}{
		{"TRUSTS_SERVER", "none", 0.1},
		{"TRUSTS_SERVER", "apiKey", 0.3},
		{"TRUSTS_SERVER", "oauth", 0.7},
		{"TRUSTS_SERVER", "mtls", 0.9},
		{"TRUSTS_SERVER", "unknown", 0.1},
		{"DELEGATES_TO", "oauth", 0.5},
		{"DELEGATES_TO", "none", 0.1},
		{"DELEGATES_TO", "", 0.1},
		{"PROVIDES_TOOL", "", 0.1},
		{"HAS_ACCESS_TO", "", 0.2},
		{"CAN_EXECUTE", "", 0.1},
		{"SHADOWS", "", 0.4},
		{"UNKNOWN_EDGE", "", 0.5},
	}

	for _, tt := range tests {
		got := EdgeRiskWeight(tt.kind, tt.auth)
		if got != tt.want {
			t.Errorf("EdgeRiskWeight(%q, %q) = %f, want %f", tt.kind, tt.auth, got, tt.want)
		}
	}
}

func TestToFloat64(t *testing.T) {
	tests := []struct {
		input any
		want  float64
	}{
		{float64(3.14), 3.14},
		{int64(42), 42},
		{int(7), 7},
		{"string", 0},
		{nil, 0},
	}
	for _, tt := range tests {
		if got := toFloat64(tt.input); got != tt.want {
			t.Errorf("toFloat64(%v) = %f, want %f", tt.input, got, tt.want)
		}
	}
}

func TestToInt64(t *testing.T) {
	tests := []struct {
		input any
		want  int64
	}{
		{int64(42), 42},
		{float64(3.14), 3},
		{int(7), 7},
		{"string", 0},
		{nil, 0},
	}
	for _, tt := range tests {
		if got := toInt64(tt.input); got != tt.want {
			t.Errorf("toInt64(%v) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestToStringSlice(t *testing.T) {
	tests := []struct {
		name  string
		input any
		want  int
	}{
		{"nil", nil, 0},
		{"string slice", []string{"a", "b"}, 2},
		{"any slice", []any{"a", "b", "c"}, 3},
		{"mixed any slice", []any{"a", 42, "b"}, 2},
		{"int", 42, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := toStringSlice(tt.input)
			if len(got) != tt.want {
				t.Errorf("toStringSlice() len = %d, want %d", len(got), tt.want)
			}
		})
	}
}
