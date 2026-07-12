package processors

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
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
	var scoringErrs []error

	type scorer struct {
		kind string
		fn   func(context.Context, graph.GraphDB, string) (riskscore.Assessment, error)
	}

	scorers := []scorer{
		{"AgentInstance", riskscore.AgentRiskAssessment},
		{"A2AAgent", riskscore.A2AAgentRiskAssessment},
		{"MCPServer", riskscore.ServerRiskAssessment},
		{"MCPTool", riskscore.ToolRiskAssessment},
	}

	for _, s := range scorers {
		n, err := scoreNodesAssessment(ctx, db, s.kind, s.fn)
		updated += n
		if err != nil {
			scoringErrs = append(
				scoringErrs,
				fmt.Errorf("scoring %s nodes: %w", s.kind, err),
			)
		}
	}

	// Continue across nodes and kinds to report every integrity failure, but
	// return the joined error: risk scoring is a required stage, so any missing
	// assessment must fail publication rather than publish a best-effort mix.
	return graph.ProcessingStats{
		ProcessorName: p.Name(),
		NodesUpdated:  updated,
		Duration:      time.Since(start),
	}, errors.Join(scoringErrs...)
}

func scoreNodesAssessment(
	ctx context.Context,
	db graph.GraphDB,
	kind string,
	scoreFn func(context.Context, graph.GraphDB, string) (riskscore.Assessment, error),
) (int, error) {
	var updated int
	var nodeErrs []error
	const pageSize = 1000
	offset := 0
	revision := ""
	var total int64
	havePage := false
	var nodesToScore []ingest.Node

	for {
		nodes, page, err := db.ListNodesPage(ctx, kind, pageSize, offset, revision)
		if err != nil {
			return updated, fmt.Errorf("list %s at offset %d: %w", kind, offset, err)
		}
		if page.Offset != offset {
			return updated, fmt.Errorf(
				"list %s returned offset %d, want %d", kind, page.Offset, offset,
			)
		}
		if !havePage {
			revision = page.Revision
			total = page.Total
			havePage = true
		} else {
			if page.Revision != revision {
				return updated, fmt.Errorf(
					"list %s revision changed from %q to %q", kind, revision, page.Revision,
				)
			}
			if page.Total != total {
				return updated, fmt.Errorf(
					"list %s total changed from %d to %d", kind, total, page.Total,
				)
			}
		}
		nodesToScore = append(nodesToScore, nodes...)

		if !page.HasMore {
			if !page.Complete {
				return updated, fmt.Errorf("list %s ended with an incomplete page", kind)
			}
			if int64(len(nodesToScore)) != total {
				return updated, fmt.Errorf(
					"list %s returned %d nodes, want total %d", kind, len(nodesToScore), total,
				)
			}
			break
		}
		if page.Complete {
			return updated, fmt.Errorf("list %s returned complete=true with has_more=true", kind)
		}
		if revision == "" {
			return updated, fmt.Errorf("list %s omitted a continuation revision", kind)
		}
		if len(nodes) == 0 {
			return updated, fmt.Errorf("list %s returned an empty page with has_more=true at offset %d", kind, offset)
		}
		offset += len(nodes)
	}

	// Finish the revision-consistent read before mutating any node. Risk-score
	// updates advance graph_updated_at, so interleaving writes with page reads
	// would invalidate our own continuation token.
	for _, node := range nodesToScore {
		assessment, err := scoreFn(ctx, db, node.ID)
		if err != nil {
			nodeErrs = append(nodeErrs, fmt.Errorf("compute %s %s: %w", kind, node.ID, err))
			continue
		}

		if err := db.UpdateNodeProperties(ctx, node.ID, map[string]any{
			"risk_score":               assessment.Score,
			"risk_score_min":           assessment.Min,
			"risk_score_max":           assessment.Max,
			"risk_assessment_complete": assessment.Complete,
			"risk_unknown_factors":     assessment.UnknownFactors,
		}); err != nil {
			nodeErrs = append(nodeErrs, fmt.Errorf("update %s %s: %w", kind, node.ID, err))
			continue
		}
		updated++
	}

	return updated, errors.Join(nodeErrs...)
}
