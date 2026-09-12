package processors

import (
	"context"
	"fmt"
	"time"

	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

type PoisonedInstructions struct{}

func (p *PoisonedInstructions) Name() string           { return "poisoned_instructions" }
func (p *PoisonedInstructions) Dependencies() []string { return nil }

func (p *PoisonedInstructions) Process(ctx context.Context, db graph.GraphDB, scanID string) (graph.ProcessingStats, error) {
	start := time.Now()

	poisoningCypher := `
MATCH (f:InstructionFile)
WHERE f.instruction_verdict = 'poisoning'
  AND f.instruction_scope IN ['exact_project', 'exact_user']
MERGE (f)-[e:POISONED_INSTRUCTIONS]->(f)
ON CREATE SET e.confidence = 1.0,
              e.is_composite = true,
              e.source_collector = 'config',
              e.scan_id = $scan_id,
              e.risk_weight = 0.7,
              e.last_seen = datetime(),
              e.evidence_version = 1,
              e.evidence_node_ids = [f.objectid],
              e.evidence_relationship_ids = []
ON MATCH SET  e.scan_id = $scan_id,
              e.last_seen = datetime(),
              e.confidence = 1.0,
              e.is_composite = true,
              e.source_collector = 'config',
              e.risk_weight = 0.7,
              e.evidence_version = 1,
              e.evidence_node_ids = [f.objectid],
              e.evidence_relationship_ids = []
RETURN count(*) AS written`

	n, err := db.ExecuteWrite(ctx, poisoningCypher, map[string]any{"scan_id": scanID})
	if err != nil {
		return graph.ProcessingStats{
			ProcessorName: p.Name(),
			Duration:      time.Since(start),
		}, err
	}

	signalCypher := `
MATCH (f:InstructionFile)
WHERE f.instruction_verdict = 'signal'
   OR (f.instruction_verdict = 'poisoning' AND f.instruction_scope = 'deep')
MERGE (f)-[e:INSTRUCTION_SIGNAL]->(f)
ON CREATE SET e.confidence = 1.0,
              e.is_composite = true,
              e.source_collector = 'config',
              e.scan_id = $scan_id,
              e.risk_weight = 0.3,
              e.last_seen = datetime(),
              e.evidence_version = 1,
              e.evidence_node_ids = [f.objectid],
              e.evidence_relationship_ids = []
ON MATCH SET  e.scan_id = $scan_id,
              e.last_seen = datetime(),
              e.confidence = 1.0,
              e.is_composite = true,
              e.source_collector = 'config',
              e.risk_weight = 0.3,
              e.evidence_version = 1,
              e.evidence_node_ids = [f.objectid],
              e.evidence_relationship_ids = []
RETURN count(*) AS written`
	signals, err := db.ExecuteWrite(ctx, signalCypher, map[string]any{"scan_id": scanID})
	if err != nil {
		return graph.ProcessingStats{
			ProcessorName: p.Name(),
			EdgesCreated:  n,
			Duration:      time.Since(start),
		}, err
	}

	// Strong, directly applicable poisoned instructions can influence any tool
	// exposed through the same AgentInstance. Only an explicitly declared
	// destructive sink qualifies. The first WITH applies the existing
	// per-(agent, source) 20-sink cap; the second deterministically selects one
	// witness when multiple agents establish the same source/target edge.
	destructivePathCypher := fmt.Sprintf(`
MATCH (a:AgentInstance)-[loads:LOADS_INSTRUCTIONS]->(f:InstructionFile)
WHERE f.instruction_verdict = 'poisoning'
  AND f.instruction_scope IN ['exact_project', 'exact_user']
MATCH (a)-[sink_trust:TRUSTS_SERVER]->(sink_server:MCPServer)
      -[sink_provides:PROVIDES_TOOL]->(snk:MCPTool)
WHERE %s
WITH a, f, loads, sink_server, sink_trust, sink_provides, snk
ORDER BY sink_server.objectid
WITH a, f, loads, snk, head(collect({
  server: sink_server,
  trust: sink_trust,
  provides: sink_provides
})) AS sink_evidence
ORDER BY snk.objectid
WITH a, f, loads, collect({
  node: snk,
  server: sink_evidence.server,
  trust: sink_evidence.trust,
  provides: sink_evidence.provides
})[..20] AS sinks
UNWIND sinks AS sink
WITH f, sink.node AS snk, a, loads,
     sink.server AS sink_server, sink.trust AS sink_trust,
     sink.provides AS sink_provides
ORDER BY f.objectid, snk.objectid, a.objectid, sink_server.objectid
WITH f, snk, head(collect({
  agent: a,
  loads: loads,
  server: sink_server,
  trust: sink_trust,
  provides: sink_provides
})) AS witness
MERGE (f)-[e:POISONS_CONTEXT]->(snk)
SET e.scan_id = $scan_id, e.last_seen = datetime(), e.is_composite = true,
    e.source_collector = 'config', e.confidence = 0.6, e.risk_weight = 0.4,
    e.evidence_version = 1,
    e.evidence_node_ids = [
      witness.agent.objectid, f.objectid,
      witness.server.objectid, snk.objectid
    ],
    e.evidence_relationship_ids = [
      id(witness.loads), id(witness.trust), id(witness.provides)
    ]
RETURN count(*) AS written`, destructiveSinkPredicate("snk"))
	destructivePaths, err := db.ExecuteWrite(ctx, destructivePathCypher, map[string]any{"scan_id": scanID})
	if err != nil {
		return graph.ProcessingStats{
			ProcessorName: p.Name(),
			EdgesCreated:  n + signals,
			Duration:      time.Since(start),
		}, err
	}

	return graph.ProcessingStats{
		ProcessorName: p.Name(),
		EdgesCreated:  n + signals + destructivePaths,
		Duration:      time.Since(start),
	}, nil
}
