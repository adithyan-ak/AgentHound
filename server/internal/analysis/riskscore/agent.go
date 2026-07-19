package riskscore

import (
	"context"
	"math"

	"github.com/adithyan-ak/agenthound/sdk/common"
	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

func AgentRiskScore(ctx context.Context, db graph.GraphDB, objectID string) (float64, error) {
	assessment, err := AgentRiskAssessment(ctx, db, objectID)
	if err != nil {
		return 0, err
	}
	return assessment.Score, nil
}

func AgentRiskAssessment(ctx context.Context, db graph.GraphDB, objectID string) (Assessment, error) {
	cred, err := agentCredentialRisk(ctx, db, objectID)
	if err != nil {
		return Assessment{}, err
	}
	blast, err := agentBlastRadius(ctx, db, objectID)
	if err != nil {
		return Assessment{}, err
	}
	auth, err := agentAuthPosture(ctx, db, objectID)
	if err != nil {
		return Assessment{}, err
	}
	tools, err := agentToolSurface(ctx, db, objectID)
	if err != nil {
		return Assessment{}, err
	}
	poison, err := agentPoisoning(ctx, db, objectID)
	if err != nil {
		return Assessment{}, err
	}

	return combineAssessments(
		weightedAssessment{weight: 0.30, value: exactAssessment(cred)},
		weightedAssessment{weight: 0.25, value: exactAssessment(blast)},
		weightedAssessment{weight: 0.20, value: auth},
		weightedAssessment{weight: 0.15, value: exactAssessment(tools)},
		weightedAssessment{weight: 0.10, value: exactAssessment(poison)},
	), nil
}

func agentCredentialRisk(ctx context.Context, db graph.GraphDB, objectID string) (float64, error) {
	cypher := `
MATCH (a {objectid: $id})-[:TRUSTS_SERVER]->(s:MCPServer)
      -[:AUTHENTICATES_WITH]->(:Identity)-[:USES_CREDENTIAL]->(c:Credential)
WHERE c.value_hash IS NOT NULL AND c.value_hash <> ''
  AND c.merge_key = 'value_hash'
  AND c.identity_basis = 'value_hash'
  AND c.material_status = 'observed'
  AND c.exposure_status = 'exposed'
WITH DISTINCT c
RETURN c.high_entropy AS high_entropy, c.type AS cred_type,
       c.material_status AS material_status, c.exposure_status AS exposure_status,
       c.merge_key AS merge_key`

	rows, err := db.Query(ctx, cypher, map[string]any{"id": objectID})
	if err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 0, nil
	}

	eligible := false
	for _, row := range rows {
		if mergeKey, _ := row["merge_key"].(string); mergeKey != "value_hash" {
			continue
		}
		material, _ := row["material_status"].(string)
		exposure, _ := row["exposure_status"].(string)
		if material != string(common.CredentialMaterialObserved) ||
			exposure != string(common.CredentialExposureExposed) {
			continue
		}
		eligible = true
		if he, ok := row["high_entropy"].(bool); ok && he {
			return 100, nil
		}
		if ct, ok := row["cred_type"].(string); ok && ct == "hardcoded" {
			return 100, nil
		}
	}
	if !eligible {
		return 0, nil
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

func agentAuthPosture(ctx context.Context, db graph.GraphDB, objectID string) (Assessment, error) {
	cypher := `
MATCH (a {objectid: $id})-[t:TRUSTS_SERVER]->(s:MCPServer)
RETURN t.effective_risk_weight AS rw,
       t.effective_auth_assessment_complete AS auth_assessment_complete`

	rows, err := db.Query(ctx, cypher, map[string]any{"id": objectID})
	if err != nil {
		return Assessment{}, err
	}
	if len(rows) == 0 {
		return exactAssessment(0), nil
	}

	var knownRisk float64
	var unknown int
	for _, row := range rows {
		complete, _ := row["auth_assessment_complete"].(bool)
		weight, valid := boundedTrustWeight(row["rw"])
		if !complete || !valid {
			unknown++
			continue
		}
		knownRisk += (1 - weight) * 100
	}
	count := float64(len(rows))
	if unknown > 0 {
		return unknownAssessment(
			"agent_auth",
			knownRisk/count,
			(knownRisk+float64(unknown)*100)/count,
		), nil
	}
	return exactAssessment(knownRisk / count), nil
}

func boundedTrustWeight(value any) (float64, bool) {
	var weight float64
	switch typed := value.(type) {
	case float64:
		weight = typed
	case int64:
		weight = float64(typed)
	case int:
		weight = float64(typed)
	default:
		return 0, false
	}
	if math.IsNaN(weight) || math.IsInf(weight, 0) || weight < 0 || weight > 1 {
		return 0, false
	}
	return weight, true
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
