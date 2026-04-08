package ingest

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/adithyan-ak/agenthound/internal/appdb"
	"github.com/adithyan-ak/agenthound/internal/graph"
	"github.com/adithyan-ak/agenthound/internal/model"
)

type Pipeline struct {
	validator  *Validator
	normalizer *Normalizer
	writer     *graph.Writer
	scanStore  *appdb.ScanStore
}

func NewPipeline(writer *graph.Writer, scanStore *appdb.ScanStore) *Pipeline {
	return &Pipeline{
		validator:  NewValidator(),
		normalizer: NewNormalizer(),
		writer:     writer,
		scanStore:  scanStore,
	}
}

func (p *Pipeline) Ingest(ctx context.Context, data *model.IngestData) (*model.IngestResult, error) {
	start := time.Now()
	result := &model.IngestResult{
		ScanID: data.Meta.ScanID,
	}

	// Stage 1: Validate
	if err := p.validator.Validate(data); err != nil {
		return nil, err
	}
	slog.Info("validation passed", "nodes", len(data.Graph.Nodes), "edges", len(data.Graph.Edges))

	// Stage 2: Normalize
	warnings := p.normalizer.Normalize(data)
	result.Warnings = warnings
	if len(warnings) > 0 {
		slog.Info("normalization warnings", "count", len(warnings))
	}

	// Stage 3: Record scan start
	if p.scanStore != nil {
		scan := &model.Scan{
			ID:        data.Meta.ScanID,
			Collector: data.Meta.Collector,
			Status:    model.ScanStatusRunning,
			StartedAt: time.Now().UTC(),
		}
		if err := p.scanStore.CreateScan(ctx, scan); err != nil {
			slog.Warn("failed to create scan record", "error", err)
		}
	}

	// Stage 4: Write nodes
	nodesWritten, err := p.writer.WriteNodes(ctx, data.Graph.Nodes, data.Meta.ScanID)
	if err != nil {
		p.failScan(ctx, data.Meta.ScanID, err)
		return nil, fmt.Errorf("write nodes: %w", err)
	}
	result.NodesWritten = nodesWritten
	slog.Info("nodes written", "count", nodesWritten)

	// Stage 5: Write edges
	edgesWritten, err := p.writer.WriteEdges(ctx, data.Graph.Edges, data.Meta.ScanID)
	if err != nil {
		p.failScan(ctx, data.Meta.ScanID, err)
		return nil, fmt.Errorf("write edges: %w", err)
	}
	result.EdgesWritten = edgesWritten
	slog.Info("edges written", "count", edgesWritten)

	// Stage 6: Record completion
	if p.scanStore != nil {
		if err := p.scanStore.UpdateScan(ctx, data.Meta.ScanID, model.ScanStatusCompleted, nodesWritten, edgesWritten, ""); err != nil {
			slog.Warn("failed to update scan record", "error", err)
		}
	}

	result.Duration = time.Since(start)
	slog.Info("ingest complete", "scan_id", data.Meta.ScanID, "nodes", nodesWritten, "edges", edgesWritten, "duration", result.Duration)
	return result, nil
}

func (p *Pipeline) failScan(ctx context.Context, scanID string, scanErr error) {
	if p.scanStore != nil {
		if err := p.scanStore.UpdateScan(ctx, scanID, model.ScanStatusFailed, 0, 0, scanErr.Error()); err != nil {
			slog.Warn("failed to record scan failure", "error", err)
		}
	}
}
