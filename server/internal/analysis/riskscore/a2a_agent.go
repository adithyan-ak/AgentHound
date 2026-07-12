package riskscore

import (
	"context"
	"math"

	"github.com/adithyan-ak/agenthound/sdk/common"
	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

func A2AAgentRiskScore(ctx context.Context, db graph.GraphDB, objectID string) (float64, error) {
	assessment, err := A2AAgentRiskAssessment(ctx, db, objectID)
	if err != nil {
		return 0, err
	}
	return assessment.Score, nil
}

func A2AAgentRiskAssessment(ctx context.Context, db graph.GraphDB, objectID string) (Assessment, error) {
	auth, err := a2aAuthAssessment(ctx, db, objectID)
	if err != nil {
		return Assessment{}, err
	}
	blast, err := a2aBlastRadius(ctx, db, objectID)
	if err != nil {
		return Assessment{}, err
	}
	delegation, err := a2aDelegationSurface(ctx, db, objectID)
	if err != nil {
		return Assessment{}, err
	}
	impersonation, err := a2aImpersonationRisk(ctx, db, objectID)
	if err != nil {
		return Assessment{}, err
	}

	return combineAssessments(
		weightedAssessment{weight: 0.30, value: auth},
		weightedAssessment{weight: 0.30, value: exactAssessment(blast)},
		weightedAssessment{weight: 0.25, value: exactAssessment(delegation)},
		weightedAssessment{weight: 0.15, value: exactAssessment(impersonation)},
	), nil
}

func a2aAuthAssessment(ctx context.Context, db graph.GraphDB, objectID string) (Assessment, error) {
	cypher := `MATCH (a {objectid: $id})
RETURN a.auth_method AS am, a.auth_evidence AS auth_evidence`
	rows, err := db.Query(ctx, cypher, map[string]any{"id": objectID})
	if err != nil {
		return Assessment{}, err
	}
	if len(rows) == 0 {
		return unknownAssessment("auth_method", 0, 100), nil
	}
	am, _ := rows[0]["am"].(string)
	authEvidence, _ := rows[0]["auth_evidence"].(string)
	if common.NormalizeAuthMethod(am) == common.AuthNone &&
		!common.IsConfirmedAnonymousAccess(am, authEvidence) {
		return unknownAssessment("auth_evidence", 0, 100), nil
	}
	auth := common.AssessAuth(am)
	if auth.Weakness == nil {
		return unknownAssessment("auth_method", 0, 100), nil
	}
	return exactAssessment(*auth.Weakness), nil
}

func a2aBlastRadius(ctx context.Context, db graph.GraphDB, objectID string) (float64, error) {
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

func a2aDelegationSurface(ctx context.Context, db graph.GraphDB, objectID string) (float64, error) {
	cypher := `
MATCH (a {objectid: $id})-[:DELEGATES_TO]->(peer:A2AAgent)
RETURN count(DISTINCT peer) AS cnt`
	rows, err := db.Query(ctx, cypher, map[string]any{"id": objectID})
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
RETURN count(DISTINCT peer) AS cnt`
	rows, err := db.Query(ctx, cypher, map[string]any{"id": objectID})
	if err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 0, nil
	}
	cnt := toInt64(rows[0]["cnt"])
	return math.Min(float64(cnt)*25, 100), nil
}
