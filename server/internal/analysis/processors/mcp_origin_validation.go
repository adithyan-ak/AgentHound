package processors

import (
	"context"
	"time"

	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

type MCPOriginValidation struct{}

func (p *MCPOriginValidation) Name() string { return "mcp_origin_validation" }
func (p *MCPOriginValidation) Dependencies() []string {
	return nil
}

func (p *MCPOriginValidation) Process(
	ctx context.Context,
	db graph.GraphDB,
	scanID string,
) (graph.ProcessingStats, error) {
	start := time.Now()
	const cypher = `
MATCH (s:MCPServer)
WHERE s.origin_validation_status = 'accepted'
  AND s.origin_validation_evidence IN ['matching_jsonrpc_response', 'session_allocated']
MERGE (s)-[e:MCP_ORIGIN_VALIDATION_FAILED]->(s)
SET e.confidence = 1.0,
    e.is_composite = true,
    e.source_collector = 'scan',
    e.scan_id = $scan_id,
    e.risk_weight = 0.3,
    e.last_seen = datetime(),
    e.http_status = s.origin_validation_http_status,
    e.response_evidence = s.origin_validation_evidence,
    e.probe_origin = s.origin_validation_probe_origin,
    e.cleanup_status = s.origin_validation_cleanup_status,
    e.evidence_version = 1,
    e.evidence_node_ids = [s.objectid],
    e.evidence_relationship_ids = []
RETURN count(*) AS written`

	written, err := db.ExecuteWrite(ctx, cypher, map[string]any{"scan_id": scanID})
	if err != nil {
		return graph.ProcessingStats{
			ProcessorName: p.Name(),
			Duration:      time.Since(start),
		}, err
	}
	return graph.ProcessingStats{
		ProcessorName: p.Name(),
		EdgesCreated:  written,
		Duration:      time.Since(start),
	}, nil
}
