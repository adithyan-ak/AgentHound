package processors

import (
	"context"
	"time"

	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

// IfcViolation flags an information-flow-control violation: a tool that
// ingests untrusted input shares a resource (within 3 HAS_ACCESS_TO hops)
// with a tool wielding a high-impact capability (credential access, file
// write, email send). Untrusted data can thus flow into a sensitive sink.
//
// The 1..3 hop cap is the false-positive / performance guard — without it
// the resource-sharing join explodes on dense graphs.
type IfcViolation struct{}

func (p *IfcViolation) Name() string { return "ifc_violation" }

// Depends on has_access_to (the tool→resource accessibility edges this
// query traverses). INGESTS_UNTRUSTED is a raw collector edge, present
// from ingest, so it needs no processor dependency.
func (p *IfcViolation) Dependencies() []string { return []string{"has_access_to"} }

func (p *IfcViolation) Process(ctx context.Context, db graph.GraphDB, scanID string) (graph.ProcessingStats, error) {
	start := time.Now()

	// source_collector='mcp' (a real collector): the edge participates in
	// stale-edge cleanup whenever the mcp collector re-runs. See
	// docs/architecture/post-processors.md for the cleanup-only-on-mcp note.
	cypher := `
MATCH witness = (untrusted:MCPTool)-[:INGESTS_UNTRUSTED]->(:MCPResource)<-[:HAS_ACCESS_TO*1..3]-(sensitive:MCPTool)
WHERE untrusted <> sensitive
  AND any(cap IN sensitive.capability_surface WHERE cap IN ['credential_access', 'file_write', 'email_send'])
MERGE (untrusted)-[e:IFC_VIOLATION]->(sensitive)
SET e.scan_id = $scan_id, e.last_seen = datetime(), e.is_composite = true,
    e.source_collector = 'mcp', e.confidence = 0.6, e.risk_weight = 0.3,
    e.evidence_version = 1,
    e.evidence_node_ids = [node IN nodes(witness) | node.objectid],
    e.evidence_relationship_ids = [relationship IN relationships(witness) | id(relationship)]
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
