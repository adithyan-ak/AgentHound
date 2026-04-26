package analysis

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

type PostProcessor = graph.PostProcessor
type ProcessingStats = graph.ProcessingStats

func RunPostProcessors(ctx context.Context, db graph.GraphDB, scanID string, collectors []string) ([]ProcessingStats, error) {
	processors := allProcessors()
	if err := validateDependencyOrder(processors); err != nil {
		return nil, fmt.Errorf("invalid processor ordering: %w", err)
	}

	deleted, err := cleanStaleCompositeEdges(ctx, db, scanID, collectors)
	if err != nil {
		slog.Warn("stale edge cleanup failed", "error", err)
	} else if deleted > 0 {
		slog.Info("cleaned stale composite edges", "deleted", deleted)
	}

	var allStats []ProcessingStats
	for _, p := range processors {
		slog.Info("running post-processor", "name", p.Name())
		stats, err := p.Process(ctx, db, scanID)
		if err != nil {
			slog.Error("post-processor failed", "name", p.Name(), "error", err)
			stats.Error = err.Error()
		}
		allStats = append(allStats, stats)
		slog.Info("post-processor complete", "name", p.Name(), "edges", stats.EdgesCreated, "nodes", stats.NodesUpdated, "duration", stats.Duration)
	}

	return allStats, nil
}

func validateDependencyOrder(processors []PostProcessor) error {
	seen := make(map[string]bool)
	for _, p := range processors {
		for _, dep := range p.Dependencies() {
			if !seen[dep] {
				return fmt.Errorf("processor %q depends on %q which hasn't run yet", p.Name(), dep)
			}
		}
		seen[p.Name()] = true
	}
	return nil
}

func cleanStaleCompositeEdges(ctx context.Context, db graph.GraphDB, scanID string, collectors []string) (int, error) {
	if len(collectors) == 0 {
		return 0, nil
	}
	cypher := `MATCH ()-[r]->()
WHERE r.is_composite = true
  AND r.scan_id <> $current_scan_id
  AND r.source_collector IN $collectors
DELETE r
RETURN count(r) AS deleted`

	return db.ExecuteWrite(ctx, cypher, map[string]any{
		"current_scan_id": scanID,
		"collectors":      collectors,
	})
}
