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

// AuthStrength materializes one paired effective authentication tuple and a
// numeric auth_strength property on MCPServer and A2AAgent nodes. Configured
// auth_* properties remain immutable collection provenance. A valid, known
// MCP or A2A runtime observation wins for node posture only under its strict
// protocol-specific evidence contract; unknown/unavailable runtime
// observations fall back to the complete configured tuple.
//
// The pre-pass also materializes derived effective_* properties on incoming
// TRUSTS_SERVER relationships. Only confirmed observed anonymous access can
// override every incoming relationship. For every other posture, each edge's
// configured risk and completeness are retained independently; one observed
// authenticated path must not rewrite unrelated configured access paths.
type AuthStrength struct{}

func (p *AuthStrength) Name() string           { return "auth_strength" }
func (p *AuthStrength) Dependencies() []string { return nil }

func (p *AuthStrength) Process(ctx context.Context, db graph.GraphDB, _ string) (graph.ProcessingStats, error) {
	start := time.Now()

	// This predicate intentionally duplicates the strict ingest contract at the
	// analysis boundary. It makes upgrades safe for an existing database that
	// predates tuple validation: malformed legacy observed fields cannot become
	// effective merely because observed_auth_method is non-empty.
	validKnownObserved := `(
  (n:MCPServer AND n.transport = 'http' AND n.status = 'reachable' AND (
    (n.observed_auth_method = 'none' AND
     n.observed_auth_assurance = 'unauthenticated' AND
     n.observed_auth_evidence = 'anonymous_probe_succeeded') OR
    (n.observed_auth_method IN ['basic', 'apiKey'] AND
     n.observed_auth_assurance = 'weak' AND
     n.observed_auth_evidence = 'configured_credential') OR
    (n.observed_auth_method = 'bearer' AND
     n.observed_auth_assurance = 'moderate' AND
     n.observed_auth_evidence = 'configured_credential') OR
    (n.observed_auth_method IN ['oauth', 'oidc', 'mtls'] AND
     n.observed_auth_assurance = 'strong' AND
     n.observed_auth_evidence = 'configured_credential') OR
    (n.observed_auth_method = 'custom' AND
     n.observed_auth_assurance = 'unknown' AND
     n.observed_auth_evidence = 'configured_credential')
  )) OR
  (n:A2AAgent AND
   n.auth_probe_method = 'get_task_nonexistent' AND
   n.auth_probe_status = 'anonymous_protocol_access' AND
   n.auth_probe_detail IN ['task_not_found_v1', 'task_not_found_v0_3'] AND
   n.observed_auth_method = 'none' AND
   n.observed_auth_assurance = 'unauthenticated' AND
   n.observed_auth_evidence = 'anonymous_probe_succeeded')
)`

	nodeCypher := fmt.Sprintf(`MATCH (n)
WHERE (n:MCPServer OR n:A2AAgent) AND n.auth_method IS NOT NULL
WITH n, %s AS use_observed
WITH n,
     CASE WHEN use_observed THEN n.observed_auth_method ELSE n.auth_method END AS effective_method,
     CASE WHEN use_observed THEN n.observed_auth_evidence ELSE n.auth_evidence END AS effective_evidence,
     CASE WHEN use_observed THEN 'observed' ELSE 'configured' END AS effective_source
SET n.effective_auth_method = effective_method,
    n.effective_auth_assurance = %s,
    n.effective_auth_evidence = effective_evidence,
    n.effective_auth_source = effective_source,
    n.auth_strength = %s
RETURN count(n) AS updated`,
		validKnownObserved,
		authAssuranceCase("effective_method", "effective_evidence", "effective_source"),
		authStrengthCase("effective_method", "effective_evidence", "effective_source"))

	updated, err := db.ExecuteWrite(ctx, nodeCypher, map[string]any{})
	if err != nil {
		return graph.ProcessingStats{ProcessorName: p.Name(), Duration: time.Since(start)}, err
	}

	trustCypher := `MATCH ()-[t:TRUSTS_SERVER]->(s:MCPServer)
WITH t, s,
     s.effective_auth_source = 'observed' AND
     s.effective_auth_method = 'none' AND
     s.effective_auth_assurance = 'unauthenticated' AND
     s.effective_auth_evidence = 'anonymous_probe_succeeded' AS observed_anonymous
SET t.effective_risk_weight = CASE
      WHEN observed_anonymous THEN 0.1
      ELSE t.risk_weight
    END,
    t.effective_auth_assessment_complete = CASE
      WHEN observed_anonymous THEN true
      ELSE t.auth_assessment_complete
    END,
    t.effective_auth_source = CASE
      WHEN observed_anonymous THEN 'observed'
      ELSE 'configured'
    END
RETURN count(t) AS updated`
	if _, err := db.ExecuteWrite(ctx, trustCypher, map[string]any{}); err != nil {
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
// materialized node property never drift. None requires affirmative observed
// provenance in addition to anonymous-probe evidence. Unknown/custom methods
// yield null, which removes any stale numeric property instead of inventing
// weakness.
func authStrengthCase(prop, evidenceProp, sourceProp string) string {
	keys := make([]string, 0, len(riskscore.AuthStrengthScores))
	for k := range riskscore.AuthStrengthScores {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var sb strings.Builder
	fmt.Fprintf(
		&sb,
		"CASE WHEN %s = '%s' AND (coalesce(%s, '%s') <> '%s' OR coalesce(%s, 'configured') <> 'observed') THEN null ELSE CASE %s",
		prop,
		common.AuthNone,
		evidenceProp,
		common.AuthEvidenceUnknown,
		common.AuthEvidenceAnonymousProbeSucceeded,
		sourceProp,
		prop,
	)
	for _, k := range keys {
		fmt.Fprintf(&sb, " WHEN '%s' THEN %g", k, riskscore.AuthStrengthScores[k])
	}
	sb.WriteString(" ELSE null END END")
	return sb.String()
}

func authAssuranceCase(prop, evidenceProp, sourceProp string) string {
	return fmt.Sprintf(
		"CASE WHEN %s = '%s' AND (coalesce(%s, '%s') <> '%s' OR coalesce(%s, 'configured') <> 'observed') THEN '%s' ELSE "+
			"CASE %s WHEN '%s' THEN '%s' WHEN '%s' THEN '%s' WHEN '%s' THEN '%s' "+
			"WHEN '%s' THEN '%s' WHEN '%s' THEN '%s' WHEN '%s' THEN '%s' "+
			"WHEN '%s' THEN '%s' ELSE '%s' END END",
		prop,
		common.AuthNone,
		evidenceProp,
		common.AuthEvidenceUnknown,
		common.AuthEvidenceAnonymousProbeSucceeded,
		sourceProp,
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
