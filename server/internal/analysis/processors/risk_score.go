package processors

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/adithyan-ak/agenthound/server/internal/analysis/riskscore"
	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

type RiskScore struct{}

func (p *RiskScore) Name() string { return "risk_score" }

func (p *RiskScore) Dependencies() []string {
	return []string{
		"has_access_to",
		"can_execute",
		"shadows",
		"poisoned_description",
		"poisoned_instructions",
		"can_reach",
		"can_exfiltrate",
		"can_impersonate",
		"cross_protocol",
	}
}

func (p *RiskScore) Process(ctx context.Context, db graph.GraphDB, scanID string) (graph.ProcessingStats, error) {
	start := time.Now()
	var updated int

	type scorer struct {
		kind string
		fn   func(context.Context, graph.GraphDB, string) (float64, error)
	}

	scorers := []scorer{
		{"AgentInstance", riskscore.AgentRiskScore},
		{"A2AAgent", riskscore.A2AAgentRiskScore},
		{"MCPServer", riskscore.ServerRiskScore},
		{"MCPTool", riskscore.ToolRiskScore},
	}

	for _, s := range scorers {
		n, err := scoreNodes(ctx, db, scanID, s.kind, s.fn)
		if err != nil {
			return graph.ProcessingStats{
				ProcessorName: p.Name(),
				NodesUpdated:  updated,
				Duration:      time.Since(start),
			}, fmt.Errorf("scoring %s nodes: %w", s.kind, err)
		}
		updated += n
	}

	return graph.ProcessingStats{
		ProcessorName: p.Name(),
		NodesUpdated:  updated,
		Duration:      time.Since(start),
	}, nil
}

// riskScorePageSize bounds each page of the exhaustive node walk. Scoring
// pages until a short page is returned, so a graph with more than one page of
// a kind is fully scored instead of silently capped at the first 10,000.
const riskScorePageSize = 10000

func scoreNodes(ctx context.Context, db graph.GraphDB, scanID, kind string, scoreFn func(context.Context, graph.GraphDB, string) (float64, error)) (int, error) {
	var updated int
	for offset := 0; ; offset += riskScorePageSize {
		rows, err := db.Query(ctx, fmt.Sprintf(
			"MATCH (n:%s) WHERE n.scan_id = $scan_id RETURN n.objectid AS id ORDER BY id SKIP $offset LIMIT $limit",
			kind,
		), map[string]any{"scan_id": scanID, "offset": offset, "limit": riskScorePageSize})
		if err != nil {
			return updated, fmt.Errorf("list %s: %w", kind, err)
		}
		scopedCtx := riskscore.WithScanScope(ctx, scanID)
		for _, row := range rows {
			nodeID, _ := row["id"].(string)
			if nodeID == "" {
				continue
			}
			score, err := scoreFn(scopedCtx, db, nodeID)
			if err != nil {
				slog.Warn("risk score computation failed", "kind", kind, "node", nodeID, "error", err)
				continue
			}
			if _, err := db.ExecuteWrite(ctx,
				"MATCH (n {objectid: $id, scan_id: $scan_id}) SET n.risk_score = $score RETURN count(n)",
				map[string]any{"id": nodeID, "scan_id": scanID, "score": score},
			); err != nil {
				slog.Warn("risk score update failed", "kind", kind, "node", nodeID, "error", err)
				continue
			}
			updated++
		}
		// A short (or empty) page means the kind is exhausted.
		if len(rows) < riskScorePageSize {
			break
		}
	}
	return updated, nil
}
