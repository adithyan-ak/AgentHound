package riskscore

import (
	"context"
	"math"

	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

var authStrengthScores = map[string]float64{
	"none":   100,
	"apiKey": 70,
	"bearer": 50,
	"oauth":  25,
	"mtls":   10,
}

func ServerRiskScore(ctx context.Context, db graph.GraphDB, objectID string) (float64, error) {
	auth, err := serverAuthStrength(ctx, db, objectID)
	if err != nil {
		return 0, err
	}
	tool, err := serverToolRisk(ctx, db, objectID)
	if err != nil {
		return 0, err
	}
	exp, err := serverExposure(ctx, db, objectID)
	if err != nil {
		return 0, err
	}
	cred, err := serverCredentialHandling(ctx, db, objectID)
	if err != nil {
		return 0, err
	}

	score := 0.35*auth + 0.25*tool + 0.20*exp + 0.20*cred
	return math.Round(score*100) / 100, nil
}

func serverAuthStrength(ctx context.Context, db graph.GraphDB, objectID string) (float64, error) {
	cypher := `MATCH (s {objectid: $id}) RETURN s.auth_method AS am`
	rows, err := db.Query(ctx, cypher, map[string]any{"id": objectID})
	if err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 100, nil
	}
	am, _ := rows[0]["am"].(string)
	if s, ok := authStrengthScores[am]; ok {
		return s, nil
	}
	return 100, nil
}

func serverToolRisk(ctx context.Context, db graph.GraphDB, objectID string) (float64, error) {
	cypher := `
MATCH (s {objectid: $id})-[:PROVIDES_TOOL]->(t:MCPTool)
RETURN t.capability_surface AS caps`

	rows, err := db.Query(ctx, cypher, map[string]any{"id": objectID})
	if err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 0, nil
	}

	var maxRisk float64
	for _, row := range rows {
		caps := toStringSlice(row["caps"])
		for _, cap := range caps {
			r := capabilityRisk(cap)
			if r > maxRisk {
				maxRisk = r
			}
		}
	}
	return maxRisk, nil
}

func serverExposure(ctx context.Context, db graph.GraphDB, objectID string) (float64, error) {
	cypher := `
MATCH (s {objectid: $id})-[:RUNS_ON]->(h:Host)
RETURN h.is_public AS pub, h.is_private AS priv, h.is_local AS loc`

	rows, err := db.Query(ctx, cypher, map[string]any{"id": objectID})
	if err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 0, nil
	}

	var maxExposure float64
	for _, row := range rows {
		if pub, ok := row["pub"].(bool); ok && pub {
			return 100, nil
		}
		if priv, ok := row["priv"].(bool); ok && priv && maxExposure < 50 {
			maxExposure = 50
		}
		if loc, ok := row["loc"].(bool); ok && loc && maxExposure < 20 {
			maxExposure = 20
		}
	}
	return maxExposure, nil
}

func serverCredentialHandling(ctx context.Context, db graph.GraphDB, objectID string) (float64, error) {
	cypher := `
MATCH (s {objectid: $id})-[:HAS_ENV_VAR]->(c:Credential)
RETURN c.high_entropy AS high_entropy, c.type AS cred_type`

	rows, err := db.Query(ctx, cypher, map[string]any{"id": objectID})
	if err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 0, nil
	}

	for _, row := range rows {
		if he, ok := row["high_entropy"].(bool); ok && he {
			return 100, nil
		}
		if ct, ok := row["cred_type"].(string); ok && ct == "hardcoded" {
			return 100, nil
		}
	}
	return 50, nil
}
