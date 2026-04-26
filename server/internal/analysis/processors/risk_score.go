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
		{"MCPServer", riskscore.ServerRiskScore},
		{"MCPTool", riskscore.ToolRiskScore},
	}

	for _, s := range scorers {
		n, err := scoreNodes(ctx, db, s.kind, s.fn)
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

func scoreNodes(ctx context.Context, db graph.GraphDB, kind string, scoreFn func(context.Context, graph.GraphDB, string) (float64, error)) (int, error) {
	nodes, err := db.ListNodes(ctx, kind, 10000)
	if err != nil {
		return 0, fmt.Errorf("list %s: %w", kind, err)
	}

	var updated int
	for _, node := range nodes {
		score, err := scoreFn(ctx, db, node.ID)
		if err != nil {
			slog.Warn("risk score computation failed", "kind", kind, "node", node.ID, "error", err)
			continue
		}

		if err := db.UpdateNodeProperties(ctx, node.ID, map[string]any{
			"risk_score": score,
		}); err != nil {
			slog.Warn("risk score update failed", "kind", kind, "node", node.ID, "error", err)
			continue
		}
		updated++
	}

	return updated, nil
}
