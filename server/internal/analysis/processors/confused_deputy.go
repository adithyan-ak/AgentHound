package processors

import (
	"context"
	"time"

	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

// ConfusedDeputy flags A2A delegation where a weakly-authenticated agent
// can drive a strongly-authenticated one — a classic confused-deputy
// escalation: the anonymous/low-trust caller borrows the high-trust agent's
// privileges through the DELEGATES_TO edge.
//
// auth_assurance is materialized by the auth_strength pre-pass. Unknown and
// custom methods are deliberately excluded rather than treated as weak.
type ConfusedDeputy struct{}

func (p *ConfusedDeputy) Name() string { return "confused_deputy" }

// Depends on auth_strength (provides the numeric scores this query
// compares) and can_reach (so it runs in the late reachability phase
// alongside the other escalation detectors).
func (p *ConfusedDeputy) Dependencies() []string {
	return []string{"auth_strength", "can_reach"}
}

func (p *ConfusedDeputy) Process(ctx context.Context, db graph.GraphDB, scanID string) (graph.ProcessingStats, error) {
	start := time.Now()

	// source_collector='a2a': a real collector in AllowedCollectors, so the
	// edge participates in stale-edge cleanup directly (no expand mapping).
	cypher := `
MATCH (low:A2AAgent)-[delegation:DELEGATES_TO]->(high:A2AAgent)
WHERE low.auth_assurance IN ['unauthenticated', 'weak']
  AND high.auth_assurance = 'strong'
MERGE (low)-[e:CONFUSED_DEPUTY]->(high)
SET e.scan_id = $scan_id, e.last_seen = datetime(), e.is_composite = true,
    e.source_collector = 'a2a',
    e.low_auth_method = low.auth_method,
    e.high_auth_method = high.auth_method,
    e.confidence = 0.8, e.risk_weight = 0.3,
    e.evidence_version = 1,
    e.evidence_node_ids = [low.objectid, high.objectid],
    e.evidence_relationship_ids = [id(delegation)]
RETURN count(*) AS written`

	n, err := db.ExecuteWrite(ctx, cypher, map[string]any{"scan_id": scanID})
	if err != nil {
		return graph.ProcessingStats{
			ProcessorName: p.Name(),
			Duration:      time.Since(start),
		}, err
	}
	return graph.ProcessingStats{
		ProcessorName: p.Name(),
		EdgesCreated:  n,
		Duration:      time.Since(start),
	}, nil
}
