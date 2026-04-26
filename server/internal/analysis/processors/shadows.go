package processors

import (
	"context"
	"time"

	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

type Shadows struct{}

func (p *Shadows) Name() string           { return "shadows" }
func (p *Shadows) Dependencies() []string { return nil }

func (p *Shadows) Process(ctx context.Context, db graph.GraphDB, scanID string) (graph.ProcessingStats, error) {
	start := time.Now()

	cypher := `
MATCH (s1:MCPServer)-[:PROVIDES_TOOL]->(t1:MCPTool),
      (s2:MCPServer)-[:PROVIDES_TOOL]->(t2:MCPTool)
WHERE s1 <> s2
  AND t1 <> t2
  AND (
    (t1.description IS NOT NULL AND t2.name IS NOT NULL
     AND toLower(t1.description) CONTAINS toLower(t2.name))
    OR t1.has_cross_references = true
  )
MERGE (t1)-[e:SHADOWS]->(t2)
ON CREATE SET e.confidence = CASE WHEN t1.has_injection_patterns = true THEN 0.9 ELSE 0.6 END,
              e.is_composite = true,
              e.source_collector = 'mcp',
              e.scan_id = $scan_id,
              e.risk_weight = 0.4,
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
