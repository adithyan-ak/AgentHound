package processors

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

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
// touched by the stale-edge cleanup.
type AuthStrength struct{}

func (p *AuthStrength) Name() string           { return "auth_strength" }
func (p *AuthStrength) Dependencies() []string { return nil }

func (p *AuthStrength) Process(ctx context.Context, db graph.GraphDB, scanID string) (graph.ProcessingStats, error) {
	start := time.Now()

	cypher := fmt.Sprintf(`MATCH (n) WHERE n.scan_id = $scan_id AND n.auth_method IS NOT NULL
SET n.auth_strength = %s
RETURN count(n) AS updated`, authStrengthCase("n.auth_method"))

	updated, err := db.ExecuteWrite(ctx, cypher, map[string]any{"scan_id": scanID})
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
// materialized node property never drift. Unknown / absent methods default
// to 100 (treated as weakest, matching serverAuthStrength's fallback).
func authStrengthCase(prop string) string {
	keys := make([]string, 0, len(riskscore.AuthStrengthScores))
	for k := range riskscore.AuthStrengthScores {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var sb strings.Builder
	sb.WriteString("CASE " + prop)
	for _, k := range keys {
		fmt.Fprintf(&sb, " WHEN '%s' THEN %g", k, riskscore.AuthStrengthScores[k])
	}
	sb.WriteString(" ELSE 100 END")
	return sb.String()
}
