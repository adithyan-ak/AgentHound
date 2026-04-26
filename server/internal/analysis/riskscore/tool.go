package riskscore

import (
	"context"
	"math"

	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

var sensitivityScores = map[string]float64{
	"critical": 100,
	"high":     75,
	"medium":   50,
	"low":      25,
	"none":     0,
}

func ToolRiskScore(ctx context.Context, db graph.GraphDB, objectID string) (float64, error) {
	capClass, err := toolCapabilityClass(ctx, db, objectID)
	if err != nil {
		return 0, err
	}
	poison, err := toolPoisoning(ctx, db, objectID)
	if err != nil {
		return 0, err
	}
	sens, err := toolAccessSensitivity(ctx, db, objectID)
	if err != nil {
		return 0, err
	}
	input, err := toolInputValidation(ctx, db, objectID)
	if err != nil {
		return 0, err
	}

	score := 0.30*capClass + 0.25*poison + 0.25*sens + 0.20*input
	return math.Round(score*100) / 100, nil
}

func toolCapabilityClass(ctx context.Context, db graph.GraphDB, objectID string) (float64, error) {
	cypher := `MATCH (t {objectid: $id}) RETURN t.capability_surface AS caps`
	rows, err := db.Query(ctx, cypher, map[string]any{"id": objectID})
	if err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 0, nil
	}

	var maxRisk float64
	caps := toStringSlice(rows[0]["caps"])
	for _, cap := range caps {
		r := capabilityRisk(cap)
		if r > maxRisk {
			maxRisk = r
		}
	}
	return maxRisk, nil
}

func toolPoisoning(ctx context.Context, db graph.GraphDB, objectID string) (float64, error) {
	cypher := `
MATCH (t {objectid: $id})
RETURN t.has_injection_patterns AS injected, t.has_cross_references AS xref`

	rows, err := db.Query(ctx, cypher, map[string]any{"id": objectID})
	if err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 0, nil
	}
	if inj, ok := rows[0]["injected"].(bool); ok && inj {
		return 100, nil
	}
	if xref, ok := rows[0]["xref"].(bool); ok && xref {
		return 50, nil
	}
	return 0, nil
}

func toolAccessSensitivity(ctx context.Context, db graph.GraphDB, objectID string) (float64, error) {
	cypher := `
MATCH (t {objectid: $id})-[:HAS_ACCESS_TO]->(r:MCPResource)
RETURN r.sensitivity AS sensitivity`

	rows, err := db.Query(ctx, cypher, map[string]any{"id": objectID})
	if err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 0, nil
	}

	var maxSens float64
	for _, row := range rows {
		s, _ := row["sensitivity"].(string)
		if v, ok := sensitivityScores[s]; ok && v > maxSens {
			maxSens = v
		}
	}
	return maxSens, nil
}

func toolInputValidation(ctx context.Context, db graph.GraphDB, objectID string) (float64, error) {
	cypher := `MATCH (t {objectid: $id}) RETURN t.input_schema AS schema`
	rows, err := db.Query(ctx, cypher, map[string]any{"id": objectID})
	if err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 100, nil
	}
	schema := rows[0]["schema"]
	if schema == nil {
		return 100, nil
	}
	if s, ok := schema.(string); ok && s == "" {
		return 100, nil
	}
	return 0, nil
}

var capabilityRiskMap = map[string]float64{
	"shell_access":      100,
	"code_execution":    100,
	"credential_access": 90,
	"database_access":   80,
	"file_write":        70,
	"network_outbound":  60,
	"email_send":        50,
	"file_read":         40,
}

func capabilityRisk(cap string) float64 {
	if r, ok := capabilityRiskMap[cap]; ok {
		return r
	}
	return 20
}

func toFloat64(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int64:
		return float64(n)
	case int:
		return float64(n)
	default:
		return 0
	}
}

func toInt64(v any) int64 {
	switch n := v.(type) {
	case int64:
		return n
	case float64:
		return int64(n)
	case int:
		return int64(n)
	default:
		return 0
	}
}

func toStringSlice(v any) []string {
	if v == nil {
		return nil
	}
	switch s := v.(type) {
	case []string:
		return s
	case []any:
		out := make([]string, 0, len(s))
		for _, item := range s {
			if str, ok := item.(string); ok {
				out = append(out, str)
			}
		}
		return out
	default:
		return nil
	}
}
