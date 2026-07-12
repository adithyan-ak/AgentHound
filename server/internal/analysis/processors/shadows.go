package processors

import (
	"context"
	"time"

	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

type Shadows struct{}

func (p *Shadows) Name() string           { return "shadows" }
func (p *Shadows) Dependencies() []string { return nil }

func (p *Shadows) Process(ctx context.Context, db graph.GraphDB, scanID string) (graph.ProcessingStats, error) {
	start := time.Now()

	// A SHADOWS edge means t1 specifically impersonates/overrides t2 by
	// naming it in t1's description. The match must be target-specific:
	// t1's description has to contain t2's name. We deliberately do NOT
	// branch on t1.has_cross_references — that flag is target-blind (it
	// is true if t1 references *any* sibling tool, see modules/mcp/
	// signals.go), so OR-ing it in made one flagged tool shadow every
	// tool on every other server, a cartesian blow-up of false positives.
	// has_cross_references still feeds tool risk scoring as a node
	// property (server/internal/analysis/riskscore/tool.go); it just no
	// longer manufactures SHADOWS edges.
	shadowsCypher := `
MATCH (s1:MCPServer)-[:PROVIDES_TOOL]->(t1:MCPTool),
      (s2:MCPServer)-[:PROVIDES_TOOL]->(t2:MCPTool)
WHERE s1.scan_id = $scan_id AND t1.scan_id = $scan_id
  AND s2.scan_id = $scan_id AND t2.scan_id = $scan_id
  AND s1 <> s2
  AND t1 <> t2
  AND t1.description IS NOT NULL
  AND t2.name IS NOT NULL
  AND toLower(t1.description) CONTAINS toLower(t2.name)
MERGE (t1)-[e:SHADOWS]->(t2)
ON CREATE SET e.confidence = CASE WHEN t1.has_injection_patterns = true THEN 0.9 ELSE 0.6 END,
              e.is_composite = true,
              e.source_collector = 'mcp',
              e.scan_id = $scan_id,
              e.risk_weight = 0.4,
              e.last_seen = datetime()
ON MATCH SET  e.scan_id = $scan_id,
              e.last_seen = datetime()
RETURN count(*) AS written`

	shadowsN, err := db.ExecuteWrite(ctx, shadowsCypher, map[string]any{"scan_id": scanID})
	if err != nil {
		return graph.ProcessingStats{
			ProcessorName: p.Name(),
			Duration:      time.Since(start),
		}, err
	}

	// POISONS_CONTEXT is the deliberate widening of the narrow SHADOWS
	// guard above: an injection-bearing tool can poison the shared agent
	// context that drives a high-capability sibling tool, even without
	// naming it. Co-residency is scoped to a single AgentInstance — src and
	// snk must both hang off servers that same agent trusts
	// (AgentInstance-[:TRUSTS_SERVER]->MCPServer-[:PROVIDES_TOOL]->MCPTool),
	// per the design in FEATURE_RESEARCH.md §5 and the per-agent counting in
	// scripts/perf-check.sh. Without that scope the two MATCHes form a global
	// cross product (every injection tool poisons every high-cap tool
	// anywhere), a cross-tenant false-positive cascade.
	//
	// The fan-out is capped per (agent, source) at 20 sinks. Grouping by
	// `a, src` (not `src` alone) is load-bearing: keying on src alone would
	// union the sink sets of every agent that co-resides with the source,
	// re-globalizing the cap. perf-check.sh enforces the downstream ≤200
	// pairs-per-agent operator heuristic (10 sources × 20); the per-source
	// cap itself is regression-gated by
	// poisons_context_perf_integration_test.go.
	//
	// The cap TRUNCATES, it does not suppress: a (agent, source) pair with
	// >20 eligible sinks keeps the first 20 by objectid (deterministic via
	// ORDER BY, so the chosen set is stable across runs and stale-edge
	// cleanup). Dropping the whole over-cap group instead would blind the
	// detector exactly when a poisoner is co-resident with the MOST
	// high-capability sinks (the worst case) and would let an attacker
	// suppress the finding by registering a 21st sink. count(DISTINCT
	// [src, snk]) reports edges actually MERGEd (one source can be reached
	// via multiple agents, so the raw row count would over-report).
	poisonsCypher := `
MATCH (a:AgentInstance)-[:TRUSTS_SERVER]->(srcServer:MCPServer)-[:PROVIDES_TOOL]->(src:MCPTool)
WHERE a.scan_id = $scan_id AND srcServer.scan_id = $scan_id AND src.scan_id = $scan_id
  AND src.has_injection_patterns = true
MATCH (a)-[:TRUSTS_SERVER]->(snkServer:MCPServer)-[:PROVIDES_TOOL]->(snk:MCPTool)
WHERE snkServer.scan_id = $scan_id AND snk.scan_id = $scan_id
  AND src <> snk
  AND any(cap IN snk.capability_surface WHERE cap IN ['shell_access', 'code_execution', 'credential_access', 'email_send'])
WITH a, src, snk
ORDER BY snk.objectid
WITH a, src, collect(DISTINCT snk)[..20] AS sinks
UNWIND sinks AS snk
MERGE (src)-[e:POISONS_CONTEXT]->(snk)
SET e.scan_id = $scan_id, e.last_seen = datetime(), e.is_composite = true,
    e.source_collector = 'mcp', e.confidence = 0.6, e.risk_weight = 0.4
RETURN count(DISTINCT [src, snk]) AS written`

	poisonsN, err := db.ExecuteWrite(ctx, poisonsCypher, map[string]any{"scan_id": scanID})
	if err != nil {
		return graph.ProcessingStats{
			ProcessorName: p.Name(),
			EdgesCreated:  shadowsN,
			Duration:      time.Since(start),
		}, err
	}

	return graph.ProcessingStats{
		ProcessorName: p.Name(),
		EdgesCreated:  shadowsN + poisonsN,
		Duration:      time.Since(start),
	}, nil
}
