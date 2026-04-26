package processors

import (
	"context"
	"time"

	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

type CanReach struct{}

func (p *CanReach) Name() string           { return "can_reach" }
func (p *CanReach) Dependencies() []string { return []string{"has_access_to"} }

func (p *CanReach) Process(ctx context.Context, db graph.GraphDB, scanID string) (graph.ProcessingStats, error) {
	start := time.Now()

	directCypher := `
MATCH (a:AgentInstance)-[ts:TRUSTS_SERVER]->(s:MCPServer)
      -[:PROVIDES_TOOL]->(t:MCPTool)-[:HAS_ACCESS_TO]->(r:MCPResource)
WHERE NOT EXISTS((a)-[:CAN_REACH]->(r))
MERGE (a)-[e:CAN_REACH]->(r)
SET e.scan_id = $scan_id, e.last_seen = datetime(), e.is_composite = true, e.source_collector = 'mcp',
    e.via_server = s.name, e.via_tool = t.name, e.hops = 3, e.risk_weight = 0.1,
    e.confidence = CASE WHEN ts.risk_weight <= 0.1 THEN 1.0
                        WHEN ts.risk_weight <= 0.3 THEN 0.8
                        ELSE 0.5 END
RETURN count(*) AS written`

	credChainCypher := `
MATCH (a:AgentInstance)-[:TRUSTS_SERVER]->(s1:MCPServer)-[:PROVIDES_TOOL]->(t1:MCPTool)
WHERE ANY(cap IN t1.capability_surface WHERE cap IN ['file_read', 'credential_access'])
MATCH (s2:MCPServer)-[:HAS_ENV_VAR]->(c:Credential)
MATCH (c)<-[:USES_CREDENTIAL]-(i:Identity)<-[:AUTHENTICATES_WITH]-(s2)
MATCH (s2)-[:PROVIDES_TOOL]->(t2:MCPTool)-[:HAS_ACCESS_TO]->(r:MCPResource)
WHERE s1 <> s2 AND (s1.auth_method IS NULL OR s1.auth_method IN ['none', 'apiKey'])
      AND NOT EXISTS((a)-[:CAN_REACH]->(r))
MERGE (a)-[e:CAN_REACH]->(r)
SET e.scan_id = $scan_id, e.last_seen = datetime(), e.is_composite = true, e.source_collector = 'mcp',
    e.via_credential = c.name, e.hops = 6, e.confidence = 0.6, e.risk_weight = 0.1
RETURN count(*) AS written`

	params := map[string]any{"scan_id": scanID}
	var total int

	for _, cypher := range []string{directCypher, credChainCypher} {
		n, err := db.ExecuteWrite(ctx, cypher, params)
		if err != nil {
			return graph.ProcessingStats{
				ProcessorName: p.Name(),
				Duration:      time.Since(start),
			}, err
		}
		total += n
	}

	return graph.ProcessingStats{
		ProcessorName: p.Name(),
		EdgesCreated:  total,
		Duration:      time.Since(start),
	}, nil
}
