package riskscore

import (
	"context"
	"math"

	"github.com/adithyan-ak/agenthound/sdk/common"
	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

// AuthStrengthScores maps a categorical auth_method to a numeric weakness
// score (higher = weaker). Exported so the auth_strength post-processor can
// materialize the same scores onto :MCPServer / :A2AAgent nodes as a Cypher
// CASE without the two definitions drifting.
var AuthStrengthScores = common.AuthWeaknessScores()

func ServerRiskScore(ctx context.Context, db graph.GraphDB, objectID string) (float64, error) {
	assessment, err := ServerRiskAssessment(ctx, db, objectID)
	if err != nil {
		return 0, err
	}
	return assessment.Score, nil
}

func ServerRiskAssessment(ctx context.Context, db graph.GraphDB, objectID string) (Assessment, error) {
	auth, err := serverAuthAssessment(ctx, db, objectID)
	if err != nil {
		return Assessment{}, err
	}
	tool, err := serverToolRisk(ctx, db, objectID)
	if err != nil {
		return Assessment{}, err
	}
	exp, err := serverExposureAssessment(ctx, db, objectID)
	if err != nil {
		return Assessment{}, err
	}
	cred, err := serverCredentialHandlingAssessment(ctx, db, objectID)
	if err != nil {
		return Assessment{}, err
	}

	return combineAssessments(
		weightedAssessment{weight: 0.35, value: auth},
		weightedAssessment{weight: 0.25, value: exactAssessment(tool)},
		weightedAssessment{weight: 0.20, value: exp},
		weightedAssessment{weight: 0.20, value: cred},
	), nil
}

func serverAuthAssessment(ctx context.Context, db graph.GraphDB, objectID string) (Assessment, error) {
	cypher := `MATCH (s {objectid: $id})
RETURN s.auth_method AS am, s.auth_evidence AS auth_evidence`
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

func serverExposureAssessment(ctx context.Context, db graph.GraphDB, objectID string) (Assessment, error) {
	cypher := `
MATCH (s {objectid: $id})-[:RUNS_ON]->(h:Host)
RETURN h.scope AS scope, h.is_public AS pub, h.is_private AS priv, h.is_local AS loc`

	rows, err := db.Query(ctx, cypher, map[string]any{"id": objectID})
	if err != nil {
		return Assessment{}, err
	}
	if len(rows) == 0 {
		return unknownAssessment("host_scope", 0, 100), nil
	}

	var maxExposure float64
	hasUnknown := false
	for _, row := range rows {
		scope, _ := row["scope"].(string)
		switch scope {
		case string(common.HostScopePublic):
			return exactAssessment(100), nil
		case string(common.HostScopePrivate):
			if maxExposure < 50 {
				maxExposure = 50
			}
			continue
		case string(common.HostScopeLocal):
			if maxExposure < 20 {
				maxExposure = 20
			}
			continue
		case string(common.HostScopeUnknown):
			hasUnknown = true
			continue
		}
		if pub, ok := row["pub"].(bool); ok && pub {
			return exactAssessment(100), nil
		}
		if priv, ok := row["priv"].(bool); ok && priv && maxExposure < 50 {
			maxExposure = 50
			continue
		}
		if loc, ok := row["loc"].(bool); ok && loc && maxExposure < 20 {
			maxExposure = 20
			continue
		}
		hasUnknown = true
	}
	if hasUnknown {
		return unknownAssessment("host_scope", maxExposure, 100), nil
	}
	return exactAssessment(maxExposure), nil
}

func serverCredentialHandlingAssessment(ctx context.Context, db graph.GraphDB, objectID string) (Assessment, error) {
	cypher := `
MATCH (s {objectid: $id})-[:HAS_ENV_VAR]->(c:Credential)
RETURN c.high_entropy AS high_entropy, c.type AS cred_type,
       c.blast_radius AS blast_radius, c.material_status AS material_status,
       c.exposure_status AS exposure_status, c.merge_key AS merge_key`

	rows, err := db.Query(ctx, cypher, map[string]any{"id": objectID})
	if err != nil {
		return Assessment{}, err
	}
	if len(rows) == 0 {
		return exactAssessment(0), nil
	}

	// base captures intrinsic handling risk (high-entropy / hardcoded
	// secrets max it out). blast amplifies it by how many distinct agents
	// can reach the secret (materialized as Credential.blast_radius by the
	// cross_service_credential_chain processor), mirroring a2aBlastRadius.
	base := 0.0
	var blast float64
	for _, row := range rows {
		material, _ := row["material_status"].(string)
		exposure, _ := row["exposure_status"].(string)
		mergeKey, _ := row["merge_key"].(string)
		if mergeKey == "identity" {
			continue
		}
		if material != string(common.CredentialMaterialObserved) ||
			exposure != string(common.CredentialExposureExposed) {
			continue
		}
		if base < 50 {
			base = 50
		}
		if he, ok := row["high_entropy"].(bool); ok && he {
			base = 100
		}
		if ct, ok := row["cred_type"].(string); ok && ct == "hardcoded" {
			base = 100
		}
		if br := toInt64(row["blast_radius"]); br > 0 {
			if b := math.Min(float64(br)*10, 100); b > blast {
				blast = b
			}
		}
	}
	return exactAssessment(math.Max(base, blast)), nil
}
