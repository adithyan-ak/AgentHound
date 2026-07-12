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
// auth_strength is the numeric weakness score materialized by the
// auth_strength pre-pass (higher = weaker). low.auth_strength >= 80 picks
// out none/apiKey-class callers; high.auth_strength <= 30 picks out
// oauth/mtls-class callees.
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
MATCH (low:A2AAgent)-[:DELEGATES_TO]->(high:A2AAgent)
WHERE low.scan_id = $scan_id AND high.scan_id = $scan_id
  AND low.auth_strength >= 80 AND high.auth_strength <= 30
MERGE (low)-[e:CONFUSED_DEPUTY]->(high)
SET e.scan_id = $scan_id, e.last_seen = datetime(), e.is_composite = true,
    e.source_collector = 'a2a',
    e.low_auth_method = low.auth_method,
    e.high_auth_method = high.auth_method,
    e.confidence = 0.8, e.risk_weight = 0.3
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
