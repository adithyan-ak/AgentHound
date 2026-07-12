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

	// Composite edges are immutable generation observations. Do not delete
	// prior-generation composites here: they are needed to restore a demoted
	// generation after deleting the current one. The generation's physical
	// node observations isolate processor MERGEs, and deleting a scan removes
	// only that generation's subgraph.

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
		case "scan":
			// A merged "scan" bundle is NOT itself a composite source_collector
			// — its processors tag composite edges with the CONSTITUENT
			// collectors (mcp/a2a/config) they derived from. Cleaning only a
			// bare "scan" domain therefore misses every stale composite from a
			// prior bundle. Expand to the constituent coverage domains the
			// bundle covers so a re-ingested "scan" actually retires its own
			// prior composites.
			add("mcp")
			add("a2a")
			add("config")
			add("cross_service_credential_chain")
		case "config":
			add("cross_service_credential_chain")
		}
	}
	return out
}
