package analysis

import (
	"context"
	"errors"
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

	var allStats []ProcessingStats
	var processorErrs []error
	for _, p := range processors {
		slog.Info("running post-processor", "name", p.Name())
		stats, err := p.Process(ctx, db, scanID)
		if err != nil {
			slog.Error("post-processor failed", "name", p.Name(), "error", err)
			stats.Error = err.Error()
			processorErrs = append(processorErrs, fmt.Errorf("%s: %w", p.Name(), err))
		}
		allStats = append(allStats, stats)
		slog.Info("post-processor complete", "name", p.Name(), "edges", stats.EdgesCreated, "nodes", stats.NodesUpdated, "duration", stats.Duration)
	}

	// Prior composite facts remain available until every processor has
	// successfully recomputed its candidate output. Cleanup before this point
	// can erase the last valid epoch when a later processor fails.
	if len(processorErrs) == 0 {
		deleted, err := cleanStaleCompositeEdges(ctx, db, scanID, collectors)
		if err != nil {
			slog.Error("stale edge cleanup failed", "error", err)
			processorErrs = append(processorErrs, fmt.Errorf("stale composite cleanup: %w", err))
		} else if deleted > 0 {
			slog.Info("cleaned stale composite edges", "deleted", deleted)
		}
	}

	return allStats, errors.Join(processorErrs...)
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
	collectors = expandCompositeCollectors(collectors)
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

func expandCompositeCollectors(collectors []string) []string {
	seen := make(map[string]bool, len(collectors)+1)
	out := make([]string, 0, len(collectors)+1)
	add := func(collector string) {
		if collector == "" || seen[collector] {
			return
		}
		seen[collector] = true
		out = append(out, collector)
	}
	for _, collector := range collectors {
		add(collector)
		switch collector {
		case "mcp", "config":
			add("cross_service_credential_chain")
		case "scan":
			add("mcp")
			add("config")
			add("a2a")
			add("cross_service_credential_chain")
		}
	}
	return out
}
