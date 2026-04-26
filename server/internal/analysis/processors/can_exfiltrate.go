package processors

import (
	"context"
	"time"

	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

type CanExfiltrate struct{}

func (p *CanExfiltrate) Name() string           { return "can_exfiltrate" }
func (p *CanExfiltrate) Dependencies() []string { return []string{"can_reach"} }

func (p *CanExfiltrate) Process(ctx context.Context, db graph.GraphDB, scanID string) (graph.ProcessingStats, error) {
	start := time.Now()

	cypher := `
MATCH (a:AgentInstance)-[:CAN_REACH]->(r:MCPResource)
WHERE r.sensitivity IN ['critical', 'high']
MATCH (a)-[:TRUSTS_SERVER]->(s:MCPServer)-[:PROVIDES_TOOL]->(outbound:MCPTool)
WHERE ANY(cap IN outbound.capability_surface WHERE cap IN ['email_send', 'network_outbound', 'file_write'])
      AND NOT EXISTS((a)-[:CAN_EXFILTRATE_VIA]->(outbound))
MERGE (a)-[e:CAN_EXFILTRATE_VIA]->(outbound)
SET e.scan_id = $scan_id, e.last_seen = datetime(), e.is_composite = true, e.source_collector = 'mcp',
    e.sensitive_resource = r.uri, e.resource_sensitivity = r.sensitivity,
    e.confidence = 0.8, e.risk_weight = 0.1
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
