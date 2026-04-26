package processors

import (
	"context"
	"time"

	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

type PoisonedInstructions struct{}

func (p *PoisonedInstructions) Name() string           { return "poisoned_instructions" }
func (p *PoisonedInstructions) Dependencies() []string { return nil }

func (p *PoisonedInstructions) Process(ctx context.Context, db graph.GraphDB, scanID string) (graph.ProcessingStats, error) {
	start := time.Now()

	cypher := `
MATCH (f:InstructionFile)
WHERE f.is_suspicious = true
MERGE (f)-[e:POISONED_INSTRUCTIONS]->(f)
ON CREATE SET e.confidence = 1.0,
              e.is_composite = true,
              e.source_collector = 'config',
              e.scan_id = $scan_id,
              e.risk_weight = 0.7,
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
