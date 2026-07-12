package processors

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/adithyan-ak/agenthound/sdk/common"
	"github.com/adithyan-ak/agenthound/server/internal/analysis/riskscore"
	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

// AuthStrength materializes a numeric auth_strength property on every node
// that carries a categorical auth_method (MCPServer, A2AAgent). Downstream
// processors (notably confused_deputy) can then compare auth gradients
// directly in Cypher instead of re-deriving the score map.
//
// Pre-pass: no dependencies, and it only updates node properties — it
// writes no composite edges, so it needs no source_collector and is not
// touched by composite edge retirement.
type AuthStrength struct{}

func (p *AuthStrength) Name() string           { return "auth_strength" }
func (p *AuthStrength) Dependencies() []string { return nil }

func (p *AuthStrength) Process(ctx context.Context, db graph.GraphDB, _ string) (graph.ProcessingStats, error) {
	start := time.Now()

	cypher := fmt.Sprintf(`MATCH (n) WHERE n.auth_method IS NOT NULL
SET n.auth_strength = %s,
    n.auth_assurance = %s
RETURN count(n) AS updated`,
		authStrengthCase("n.auth_method", "n.auth_evidence"),
		authAssuranceCase("n.auth_method", "n.auth_evidence"))

	updated, err := db.ExecuteWrite(ctx, cypher, map[string]any{})
	if err != nil {
		return graph.ProcessingStats{ProcessorName: p.Name(), Duration: time.Since(start)}, err
	}
	return graph.ProcessingStats{
		ProcessorName: p.Name(),
		NodesUpdated:  updated,
		Duration:      time.Since(start),
	}, nil
}

// authStrengthCase renders a Cypher CASE expression that maps the given
// auth_method property to its numeric strength, sourced from
// riskscore.AuthStrengthScores so the runtime risk model and the
// materialized node property never drift. Unknown/custom methods yield null,
// which removes any stale numeric property instead of inventing weakness.
func authStrengthCase(prop, evidenceProp string) string {
	keys := make([]string, 0, len(riskscore.AuthStrengthScores))
	for k := range riskscore.AuthStrengthScores {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var sb strings.Builder
	fmt.Fprintf(
		&sb,
		"CASE WHEN %s = '%s' AND coalesce(%s, '%s') <> '%s' THEN null ELSE CASE %s",
		prop,
		common.AuthNone,
		evidenceProp,
		common.AuthEvidenceUnknown,
		common.AuthEvidenceAnonymousProbeSucceeded,
		prop,
	)
	for _, k := range keys {
		fmt.Fprintf(&sb, " WHEN '%s' THEN %g", k, riskscore.AuthStrengthScores[k])
	}
	sb.WriteString(" ELSE null END END")
	return sb.String()
}

func authAssuranceCase(prop, evidenceProp string) string {
	return fmt.Sprintf(
		"CASE WHEN %s = '%s' AND coalesce(%s, '%s') <> '%s' THEN '%s' ELSE "+
			"CASE %s WHEN '%s' THEN '%s' WHEN '%s' THEN '%s' WHEN '%s' THEN '%s' "+
			"WHEN '%s' THEN '%s' WHEN '%s' THEN '%s' WHEN '%s' THEN '%s' "+
			"WHEN '%s' THEN '%s' ELSE '%s' END END",
		prop,
		common.AuthNone,
		evidenceProp,
		common.AuthEvidenceUnknown,
		common.AuthEvidenceAnonymousProbeSucceeded,
		common.AuthAssuranceUnknown,
		prop,
		common.AuthNone, common.AuthAssuranceUnauthenticated,
		common.AuthBasic, common.AuthAssuranceWeak,
		common.AuthAPIKey, common.AuthAssuranceWeak,
		common.AuthBearer, common.AuthAssuranceModerate,
		common.AuthOAuth, common.AuthAssuranceStrong,
		common.AuthOIDC, common.AuthAssuranceStrong,
		common.AuthMTLS, common.AuthAssuranceStrong,
		common.AuthAssuranceUnknown,
	)
}
