package processors

import (
	"context"
	"time"

	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

type HasAccessTo struct{}

func (p *HasAccessTo) Name() string           { return "has_access_to" }
func (p *HasAccessTo) Dependencies() []string { return nil }

func (p *HasAccessTo) Process(ctx context.Context, db graph.GraphDB, scanID string) (graph.ProcessingStats, error) {
	start := time.Now()

	// Capability match: database_access capability + DB resource URI schemes
	capDBCypher := `
MATCH (s:MCPServer)-[provides_tool:PROVIDES_TOOL]->(t:MCPTool),
      (s)-[provides_resource:PROVIDES_RESOURCE]->(r:MCPResource)
WHERE ANY(cap IN t.capability_surface WHERE cap = 'database_access')
  AND r.uri_scheme IN ['postgres', 'mysql', 'mongodb', 'redis']
MERGE (t)-[e:HAS_ACCESS_TO]->(r)
SET e.confidence = 0.7,
    e.is_composite = true,
    e.source_collector = 'mcp',
    e.scan_id = $scan_id,
    e.risk_weight = 0.2,
    e.match_type = 'capability_db',
    e.last_seen = datetime(),
    e.evidence_version = 1,
    e.evidence_node_ids = [s.objectid, t.objectid, r.objectid],
    e.evidence_relationship_ids = [id(provides_tool), id(provides_resource)]
RETURN count(*) AS written`

	capFileCypher := `
MATCH (s:MCPServer)-[provides_tool:PROVIDES_TOOL]->(t:MCPTool),
      (s)-[provides_resource:PROVIDES_RESOURCE]->(r:MCPResource)
WHERE (ANY(cap IN t.capability_surface WHERE cap = 'file_read')
       OR ANY(cap IN t.capability_surface WHERE cap = 'file_write'))
  AND r.uri_scheme = 'file'
MERGE (t)-[e:HAS_ACCESS_TO]->(r)
SET e.confidence = 0.7,
    e.is_composite = true,
    e.source_collector = 'mcp',
    e.scan_id = $scan_id,
    e.risk_weight = 0.2,
    e.match_type = 'capability_file',
    e.last_seen = datetime(),
    e.evidence_version = 1,
    e.evidence_node_ids = [s.objectid, t.objectid, r.objectid],
    e.evidence_relationship_ids = [id(provides_tool), id(provides_resource)]
RETURN count(*) AS written`

	descCypher := `
MATCH (s:MCPServer)-[provides_tool:PROVIDES_TOOL]->(t:MCPTool),
      (s)-[provides_resource:PROVIDES_RESOURCE]->(r:MCPResource)
WHERE t.description IS NOT NULL
  AND r.name IS NOT NULL
  AND toLower(t.description) CONTAINS toLower(r.name)
MERGE (t)-[e:HAS_ACCESS_TO]->(r)
SET e.confidence = 0.9,
    e.is_composite = true,
    e.source_collector = 'mcp',
    e.scan_id = $scan_id,
    e.risk_weight = 0.2,
    e.match_type = 'description',
    e.last_seen = datetime(),
    e.evidence_version = 1,
    e.evidence_node_ids = [s.objectid, t.objectid, r.objectid],
    e.evidence_relationship_ids = [id(provides_tool), id(provides_resource)]
RETURN count(*) AS written`

	params := map[string]any{"scan_id": scanID}
	var total int

	for _, cypher := range []string{capDBCypher, capFileCypher, descCypher} {
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
