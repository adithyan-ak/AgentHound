package processors

import (
	"context"
	"time"

	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

type CrossProtocol struct{}

func (p *CrossProtocol) Name() string { return "cross_protocol" }
func (p *CrossProtocol) Dependencies() []string {
	return []string{"auth_strength", "has_access_to"}
}

func (p *CrossProtocol) Process(ctx context.Context, db graph.GraphDB, scanID string) (graph.ProcessingStats, error) {
	start := time.Now()

	cypher := `
MATCH delegation = (ext:A2AAgent)-[:DELEGATES_TO*1..3]->(int:A2AAgent)
MATCH (int)-[agent_host:RUNS_ON]->(h:Host)<-[server_host:RUNS_ON]-(s:MCPServer)
MATCH (a:AgentInstance)-[trust:TRUSTS_SERVER]->(s)
      -[provides:PROVIDES_TOOL]->(t:MCPTool)-[access:HAS_ACCESS_TO]->(r:MCPResource)
WHERE ext.effective_auth_assurance = 'unauthenticated'
  AND ext.effective_auth_source = 'observed'
  AND ext.effective_auth_evidence = 'anonymous_probe_succeeded'
MERGE (ext)-[e:CAN_REACH]->(r)
SET e.scan_id = $scan_id, e.last_seen = datetime(), e.is_composite = true,
    e.cross_protocol = true, e.source_collector = 'a2a',
    e.via_mcp_server = s.name, e.via_mcp_tool = t.name,
    e.via_host = h.hostname,
    e.confidence = 0.5, e.risk_weight = 0.1,
    e.evidence_version = 1,
    e.evidence_node_ids =
      [node IN nodes(delegation) | node.objectid] +
      [h.objectid, s.objectid, a.objectid, t.objectid, r.objectid],
    e.evidence_relationship_ids =
      [relationship IN relationships(delegation) | id(relationship)] +
      [id(agent_host), id(server_host), id(trust), id(provides), id(access)]
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
