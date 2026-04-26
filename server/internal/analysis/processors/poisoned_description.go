package processors

import (
	"context"
	"time"

	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

type PoisonedDescription struct{}

func (p *PoisonedDescription) Name() string           { return "poisoned_description" }
func (p *PoisonedDescription) Dependencies() []string { return nil }

func (p *PoisonedDescription) Process(ctx context.Context, db graph.GraphDB, scanID string) (graph.ProcessingStats, error) {
	start := time.Now()

	cypher := `
MATCH (t:MCPTool)
WHERE t.has_injection_patterns = true
MERGE (t)-[e:POISONED_DESCRIPTION]->(t)
ON CREATE SET e.confidence = 1.0,
              e.is_composite = true,
              e.source_collector = 'mcp',
              e.scan_id = $scan_id,
              e.risk_weight = 0.8,
              e.last_seen = datetime()
ON MATCH SET  e.scan_id = $scan_id,
              e.last_seen = datetime()
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
