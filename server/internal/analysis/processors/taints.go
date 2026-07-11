package processors

import (
	"context"
	"time"

	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

// Taints emits a TAINTS edge (MCPTool -> MCPTool) when a tool that ingests
// untrusted input shares enough of its input schema with a tool on another
// server that attacker-controlled data could flow from the first into the
// second. The schema_keys node property (emitted collector-side) lets the
// overlap be computed in pure Cypher with no APOC dependency.
//
// The >= 2 shared-key threshold avoids matching every {type, name} pair —
// a single common key like "id" is not signal.
type Taints struct{}

func (p *Taints) Name() string { return "taints" }

// No processor dependencies: it reads only raw INGESTS_UNTRUSTED edges and
// the schema_keys / source_trust node properties, all present from ingest.
func (p *Taints) Dependencies() []string { return nil }

func (p *Taints) Process(ctx context.Context, db graph.GraphDB, scanID string) (graph.ProcessingStats, error) {
	start := time.Now()

	cypher := `
MATCH (s1:MCPServer)-[provides1:PROVIDES_TOOL]->(src:MCPTool)
MATCH (s2:MCPServer)-[provides2:PROVIDES_TOOL]->(snk:MCPTool)
WHERE s1 <> s2
  AND src <> snk
  AND src.schema_keys IS NOT NULL
  AND snk.schema_keys IS NOT NULL
  AND size([k IN src.schema_keys WHERE k IN snk.schema_keys]) >= 2
OPTIONAL MATCH (src)-[untrusted:INGESTS_UNTRUSTED]->(untrusted_resource:MCPResource)
WITH s1, provides1, src, s2, provides2, snk,
     head(collect({relationship: untrusted, resource: untrusted_resource})) AS input_evidence
WHERE input_evidence.relationship IS NOT NULL OR src.source_trust = 'private'
MERGE (src)-[e:TAINTS]->(snk)
SET e.scan_id = $scan_id, e.last_seen = datetime(), e.is_composite = true,
    e.source_collector = 'mcp', e.confidence = 0.7, e.risk_weight = 0.3,
    e.evidence_version = 1,
    e.evidence_node_ids =
      [s1.objectid, src.objectid, s2.objectid, snk.objectid] +
      CASE
        WHEN input_evidence.resource IS NULL THEN []
        ELSE [input_evidence.resource.objectid]
      END,
    e.evidence_relationship_ids =
      [id(provides1), id(provides2)] +
      CASE
        WHEN input_evidence.relationship IS NULL THEN []
        ELSE [id(input_evidence.relationship)]
      END
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
