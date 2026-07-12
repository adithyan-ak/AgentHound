package riskscore

import (
	"context"
	"math"

	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

func A2AAgentRiskScore(ctx context.Context, db graph.GraphDB, objectID string) (float64, error) {
	auth, err := a2aAuthStrength(ctx, db, objectID)
	if err != nil {
		return 0, err
	}
	blast, err := a2aBlastRadius(ctx, db, objectID)
	if err != nil {
		return 0, err
	}
	delegation, err := a2aDelegationSurface(ctx, db, objectID)
	if err != nil {
		return 0, err
	}
	impersonation, err := a2aImpersonationRisk(ctx, db, objectID)
	if err != nil {
		return 0, err
	}

	score := 0.30*auth + 0.30*blast + 0.25*delegation + 0.15*impersonation
	return math.Round(score*100) / 100, nil
}

func a2aAuthStrength(ctx context.Context, db graph.GraphDB, objectID string) (float64, error) {
	cypher := `MATCH (a {objectid: $id}) WHERE ($scan_id = '' OR a.scan_id = $scan_id) RETURN a.auth_method AS am`
	rows, err := db.Query(ctx, cypher, riskParams(ctx, objectID))
	if err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 100, nil
	}
	am, _ := rows[0]["am"].(string)
	if s, ok := AuthStrengthScores[am]; ok {
		return s, nil
	}
	return 100, nil
}

func a2aBlastRadius(ctx context.Context, db graph.GraphDB, objectID string) (float64, error) {
	// Count both proven reach and the dedicated cross-protocol pivot: an
	// A2A agent's blast radius includes resources it can reach heuristically
	// across the A2A→MCP boundary, or the risk score would understate an
	// externally-reachable agent that has no proven CAN_REACH edge.
	cypher := `
MATCH (a {objectid: $id})-[:CAN_REACH|CAN_REACH_CROSS_PROTOCOL]->(r:MCPResource)
WHERE ($scan_id = '' OR a.scan_id = $scan_id)
RETURN count(DISTINCT r) AS cnt`
	rows, err := db.Query(ctx, cypher, riskParams(ctx, objectID))
	if err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 0, nil
	}
	cnt := toInt64(rows[0]["cnt"])
	return math.Min(float64(cnt)*10, 100), nil
}

func a2aDelegationSurface(ctx context.Context, db graph.GraphDB, objectID string) (float64, error) {
	cypher := `
MATCH (a {objectid: $id})-[:DELEGATES_TO]->(peer:A2AAgent)
WHERE ($scan_id = '' OR a.scan_id = $scan_id)
RETURN count(DISTINCT peer) AS cnt`
	rows, err := db.Query(ctx, cypher, riskParams(ctx, objectID))
	if err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 0, nil
	}
	cnt := toInt64(rows[0]["cnt"])
	return math.Min(float64(cnt)*20, 100), nil
}

func a2aImpersonationRisk(ctx context.Context, db graph.GraphDB, objectID string) (float64, error) {
	cypher := `
MATCH (a {objectid: $id})-[:CAN_IMPERSONATE]-(peer:A2AAgent)
WHERE ($scan_id = '' OR a.scan_id = $scan_id)
RETURN count(DISTINCT peer) AS cnt`
	rows, err := db.Query(ctx, cypher, riskParams(ctx, objectID))
	if err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 0, nil
	}
	cnt := toInt64(rows[0]["cnt"])
	return math.Min(float64(cnt)*25, 100), nil
}
