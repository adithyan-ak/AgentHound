package riskscore

import (
	"context"
	"math"

	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

func AgentRiskScore(ctx context.Context, db graph.GraphDB, objectID string) (float64, error) {
	cred, err := agentCredentialRisk(ctx, db, objectID)
	if err != nil {
		return 0, err
	}
	blast, err := agentBlastRadius(ctx, db, objectID)
	if err != nil {
		return 0, err
	}
	auth, err := agentAuthPosture(ctx, db, objectID)
	if err != nil {
		return 0, err
	}
	tools, err := agentToolSurface(ctx, db, objectID)
	if err != nil {
		return 0, err
	}
	poison, err := agentPoisoning(ctx, db, objectID)
	if err != nil {
		return 0, err
	}

	score := 0.30*cred + 0.25*blast + 0.20*auth + 0.15*tools + 0.10*poison
	return math.Round(score*100) / 100, nil
}

func agentCredentialRisk(ctx context.Context, db graph.GraphDB, objectID string) (float64, error) {
	cypher := `
MATCH (a {objectid: $id})-[:TRUSTS_SERVER]->(s:MCPServer)-[:HAS_ENV_VAR]->(c:Credential)
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
	return 60, nil
}

func agentBlastRadius(ctx context.Context, db graph.GraphDB, objectID string) (float64, error) {
	cypher := `
MATCH (a {objectid: $id})-[:CAN_REACH]->(r:MCPResource)
RETURN count(DISTINCT r) AS cnt`

	rows, err := db.Query(ctx, cypher, map[string]any{"id": objectID})
	if err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 0, nil
	}
	cnt := toInt64(rows[0]["cnt"])
	return math.Min(float64(cnt)*10, 100), nil
}

func agentAuthPosture(ctx context.Context, db graph.GraphDB, objectID string) (float64, error) {
	cypher := `
MATCH (a {objectid: $id})-[t:TRUSTS_SERVER]->(s:MCPServer)
RETURN t.risk_weight AS rw`

	rows, err := db.Query(ctx, cypher, map[string]any{"id": objectID})
	if err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 0, nil
	}

	var sum float64
	for _, row := range rows {
		sum += toFloat64(row["rw"])
	}
	avg := sum / float64(len(rows))
	return (1 - avg) * 100, nil
}

func agentToolSurface(ctx context.Context, db graph.GraphDB, objectID string) (float64, error) {
	cypher := `
MATCH (a {objectid: $id})-[:TRUSTS_SERVER]->(s:MCPServer)-[:PROVIDES_TOOL]->(t:MCPTool)
RETURN count(DISTINCT t) AS cnt`

	rows, err := db.Query(ctx, cypher, map[string]any{"id": objectID})
	if err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 0, nil
	}
	cnt := toInt64(rows[0]["cnt"])
	return math.Min(float64(cnt)*5, 100), nil
}

func agentPoisoning(ctx context.Context, db graph.GraphDB, objectID string) (float64, error) {
	cypher := `
MATCH (a {objectid: $id})-[:LOADS_INSTRUCTIONS]->(i:InstructionFile)
WHERE i.is_suspicious = true
RETURN count(i) AS cnt`

	rows, err := db.Query(ctx, cypher, map[string]any{"id": objectID})
	if err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 0, nil
	}
	if toInt64(rows[0]["cnt"]) > 0 {
		return 100, nil
	}
	return 0, nil
}
