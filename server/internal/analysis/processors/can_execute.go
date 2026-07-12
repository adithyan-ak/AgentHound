package processors

import (
	"context"
	"time"

	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

type CanExecute struct{}

func (p *CanExecute) Name() string           { return "can_execute" }
func (p *CanExecute) Dependencies() []string { return nil }

func (p *CanExecute) Process(ctx context.Context, db graph.GraphDB, scanID string) (graph.ProcessingStats, error) {
	start := time.Now()

	cypher := `
MATCH (s:MCPServer)-[provides:PROVIDES_TOOL]->(t:MCPTool),
      (s)-[runs:RUNS_ON]->(h:Host)
WHERE ANY(cap IN t.capability_surface WHERE cap = 'shell_access')
   OR ANY(cap IN t.capability_surface WHERE cap = 'code_execution')
MERGE (t)-[e:CAN_EXECUTE]->(h)
SET e.confidence = 0.8,
    e.is_composite = true,
    e.source_collector = 'mcp',
    e.scan_id = $scan_id,
    e.risk_weight = 0.1,
    e.last_seen = datetime(),
    e.evidence_version = 1,
    e.evidence_node_ids = [s.objectid, t.objectid, h.objectid],
    e.evidence_relationship_ids = [id(provides), id(runs)]
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
