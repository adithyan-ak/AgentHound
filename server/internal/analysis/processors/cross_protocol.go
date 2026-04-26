package processors

import (
	"context"
	"time"

	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

type CrossProtocol struct{}

func (p *CrossProtocol) Name() string           { return "cross_protocol" }
func (p *CrossProtocol) Dependencies() []string { return []string{"has_access_to"} }

func (p *CrossProtocol) Process(ctx context.Context, db graph.GraphDB, scanID string) (graph.ProcessingStats, error) {
	start := time.Now()

	cypher := `
MATCH (ext:A2AAgent)-[:DELEGATES_TO*1..3]->(int:A2AAgent)
MATCH (int)-[:RUNS_ON]->(h:Host)<-[:RUNS_ON]-(s:MCPServer)
MATCH (a:AgentInstance)-[:TRUSTS_SERVER]->(s)
      -[:PROVIDES_TOOL]->(t:MCPTool)-[:HAS_ACCESS_TO]->(r:MCPResource)
WHERE (ext.auth_method = 'none' OR ext.auth_method IS NULL)
      AND NOT EXISTS((ext)-[:CAN_REACH]->(r))
MERGE (ext)-[e:CAN_REACH]->(r)
SET e.scan_id = $scan_id, e.last_seen = datetime(), e.is_composite = true,
    e.cross_protocol = true, e.source_collector = 'a2a',
    e.via_mcp_server = s.name, e.via_mcp_tool = t.name,
    e.confidence = 0.5, e.risk_weight = 0.1
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
