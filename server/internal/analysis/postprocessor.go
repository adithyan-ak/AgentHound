package analysis

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

type PostProcessor = graph.PostProcessor
type ProcessingStats = graph.ProcessingStats

func RunPostProcessors(
	ctx context.Context,
	db graph.GraphDB,
	scanID string,
	completeDomains []string,
) ([]ProcessingStats, error) {
	processors := allProcessors()
	if err := validateDependencyOrder(processors); err != nil {
		return nil, fmt.Errorf("invalid processor ordering: %w", err)
	}

	if !hasCompleteDomain(completeDomains) {
		return []ProcessingStats{}, nil
	}

	// A promoted raw domain may invalidate a composite whose provenance names
	// another collector (cross-protocol and credential-chain edges are the
	// canonical examples). Retire the whole derived epoch before rebuilding so
	// no processor can consume stale composite input from the prior epoch.
	deleted, err := beginCompositeEpoch(ctx, db)
	if err != nil {
		return nil, fmt.Errorf("begin composite epoch: %w", err)
	}
	if deleted > 0 {
		slog.Info("retired composite epoch", "deleted", deleted)
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

func hasCompleteDomain(domains []string) bool {
	for _, domain := range domains {
		if strings.TrimSpace(domain) != "" {
			return true
		}
	}
	return false
}

// beginCompositeEpoch atomically retires all derived edges and the one
// processor-owned node materialization that is not overwritten on a negative
// match. Every registered processor then rebuilds from the retained current raw
// projection in dependency order.
func beginCompositeEpoch(ctx context.Context, db graph.GraphDB) (int, error) {
	const cypher = `
CALL {
  MATCH ()-[r]->()
  WHERE r.is_composite = true
  WITH r
  DELETE r
  RETURN count(r) AS deleted
}
CALL {
  MATCH (c:Credential)
  WHERE c.blast_radius IS NOT NULL
  REMOVE c.blast_radius
  RETURN count(c) AS cleared
}
RETURN deleted`
	return db.ExecuteWrite(ctx, cypher, nil)
}
