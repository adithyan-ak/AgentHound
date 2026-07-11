package ingest

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	sdkingest "github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/server/internal/analysis"
	"github.com/adithyan-ak/agenthound/server/internal/appdb"
	"github.com/adithyan-ak/agenthound/server/internal/graph"
	"github.com/adithyan-ak/agenthound/server/model"
)

// nodeEdgeWriter is the subset of *graph.Writer that Pipeline needs.
// Defining it as an interface lets tests substitute a recording mock.
// *graph.Writer satisfies it implicitly.
type nodeEdgeWriter interface {
	WriteObservationNodes(
		ctx context.Context,
		nodes []sdkingest.Node,
		scanID string,
		completeDomains []string,
	) (int, error)
	WriteObservationEdges(
		ctx context.Context,
		edges []sdkingest.Edge,
		scanID string,
		completeDomains []string,
	) (int, error)
}

// scanRecorder is the subset of *appdb.ScanStore that Pipeline needs.
// *appdb.ScanStore satisfies it implicitly.
type scanRecorder interface {
	CreateScan(ctx context.Context, scan *model.Scan) error
	UpdateScan(ctx context.Context, id, status string, nodeCount, edgeCount int, scanErr string) error
}

type scanLifecycleRecorder interface {
	BeginScan(ctx context.Context, scan *model.Scan, dirtyCoverage []string) ([]string, error)
	RecordFailure(ctx context.Context, failure appdb.ScanFailure) error
}

// postProcessFunc runs the analysis post-processors. Defaulted to
// analysis.RunPostProcessors; replaceable in tests to assert behavior
// without exercising every concrete processor.
type postProcessFunc func(ctx context.Context, db graph.GraphDB, scanID string, collectors []string) ([]graph.ProcessingStats, error)

// findingSnapshotter atomically replaces the per-scan findings snapshot.
// Passing an empty slice must remove prior rows for that scan. *appdb.FindingStore
// satisfies it implicitly; defined as an interface so tests can substitute a
// recorder and so a nil store cleanly disables the snapshot stage.
type findingSnapshotter interface {
	InsertFindings(ctx context.Context, scanID string, findings []model.Finding) error
}

type findingPublisher interface {
	FinalizeScan(ctx context.Context, params appdb.FinalizeScanParams) (*appdb.PublicationResult, error)
}

const legacyUnknownCoverageKey = "legacy:unknown"

// Pipeline serializes ingests through a single mutex.
//
// Raw-observation promotion and post-success composite cleanup both mutate the
// shared live projection. Serializing prevents two scans from retiring one
// another's candidate ownership tokens or composite epochs.
type Pipeline struct {
	mu           sync.Mutex
	validator    *Validator
	normalizer   *Normalizer
	writer       nodeEdgeWriter
	graphDB      graph.GraphDB
	scanStore    scanRecorder
	findingStore findingSnapshotter
	runPP        postProcessFunc
}

func NewPipeline(writer *graph.Writer, graphDB graph.GraphDB, scanStore *appdb.ScanStore, findingStore *appdb.FindingStore) *Pipeline {
	p := &Pipeline{
		validator:  NewValidator(),
		normalizer: NewNormalizer(),
		graphDB:    graphDB,
		runPP:      analysis.RunPostProcessors,
	}
	// Avoid the typed-nil-into-interface trap: assign only if the
	// concrete pointer is non-nil so `p.writer != nil` checks behave
	// the same as before the interface seam was introduced.
	if writer != nil {
		p.writer = writer
	}
	if scanStore != nil {
		p.scanStore = scanStore
	}
	if findingStore != nil {
		p.findingStore = findingStore
	}
	return p
}

func (p *Pipeline) Ingest(ctx context.Context, data *sdkingest.IngestData) (*sdkingest.IngestResult, error) {
	// Serialize ingests; see Pipeline doc-comment for why.
	p.mu.Lock()
	defer p.mu.Unlock()

	start := time.Now()
	if data == nil {
		return nil, fmt.Errorf("ingest data is nil")
	}
	result := &sdkingest.IngestResult{
		ScanID:         data.Meta.ScanID,
		Outcome:        sdkingest.OutcomeUnknown,
		CountSemantics: countSemanticsWriteRowsV1,
	}

	// Stage 1: Validate
	stageStart := time.Now()
	if err := p.validator.Validate(data); err != nil {
		return nil, err
	}
	appendStage(result, "validate", sdkingest.OutcomeComplete, true, stageStart, nil)
	slog.Info("validation passed", "nodes", len(data.Graph.Nodes), "edges", len(data.Graph.Edges))

	// Stage 2: Normalize
	stageStart = time.Now()
	normalizationWarnings := p.normalizer.Normalize(data)
	result.NormalizationWarnings = normalizationWarnings
	result.NormalizationStatus = sdkingest.NormalizationStatusComplete
	var normalizationDegradedErr error
	for _, warning := range normalizationWarnings {
		result.Warnings = append(result.Warnings, warning.Message)
		if warning.PublicationUnsafe {
			result.NormalizationStatus = sdkingest.NormalizationStatusDegraded
			normalizationDegradedErr = fmt.Errorf(
				"normalization dropped or ambiguously mapped evidence",
			)
		} else if result.NormalizationStatus == sdkingest.NormalizationStatusComplete {
			result.NormalizationStatus = sdkingest.NormalizationStatusWarning
		}
	}
	result.Collection = data.Meta.Collection
	result.NodesSubmitted = len(data.Graph.Nodes)
	result.EdgesSubmitted = len(data.Graph.Edges)
	normalizationStageState := sdkingest.OutcomeComplete
	if normalizationDegradedErr != nil {
		normalizationStageState = sdkingest.OutcomePartial
	}
	appendStage(
		result,
		"normalize",
		normalizationStageState,
		true,
		stageStart,
		normalizationDegradedErr,
	)
	if len(normalizationWarnings) > 0 {
		slog.Info(
			"normalization warnings",
			"count", len(normalizationWarnings),
			"status", result.NormalizationStatus,
		)
	}

	attributionComplete := prepareObservationDomains(data)
	keys := coverageKeys(data.Meta.Collection)
	completeDomains := sdkingest.CompleteCoverageDomains(data.Meta.Collection)
	if !attributionComplete || normalizationDegradedErr != nil {
		completeDomains = nil
	}
	coverageComplete := sdkingest.CollectionCoverageComplete(data.Meta.Collection) &&
		attributionComplete &&
		normalizationDegradedErr == nil
	writeGraph := coalesceObservationGraph(data.Graph)

	artifactObservedAt, timestampErr := parseArtifactObservedAt(data.Meta.Timestamp)
	if timestampErr != nil {
		result.Warnings = append(result.Warnings, timestampErr.Error())
	}
	initialScan := &model.Scan{
		ID:                 data.Meta.ScanID,
		Collector:          data.Meta.Collector,
		Status:             model.ScanStatusRunning,
		StartedAt:          time.Now().UTC(),
		ArtifactObservedAt: artifactObservedAt,
		CollectionStatus:   string(collectionState(data.Meta.Collection)),
		GraphStatus:        model.LifecyclePending,
		AnalysisStatus:     model.LifecyclePending,
		SnapshotStatus:     model.LifecyclePending,
		ProjectionStatus:   model.ProjectionUpdating,
		PublicationStatus:  model.PublicationUnpublished,
	}
	initialScan.Metadata = buildScanMetadata(
		data,
		result,
		nil,
		nil,
		graph.ReconciliationStats{},
		graph.ObservationCompleteness{},
		completeDomains,
	)

	// Stage 3: Record scan start and projection attempt.
	cumulativeDirtyCoverage := append([]string(nil), keys...)
	if p.scanStore != nil {
		if lifecycleStore, ok := p.scanStore.(scanLifecycleRecorder); ok {
			var err error
			cumulativeDirtyCoverage, err = lifecycleStore.BeginScan(ctx, initialScan, keys)
			if err != nil {
				return nil, fmt.Errorf("begin scan lifecycle: %w", err)
			}
		} else if err := p.scanStore.CreateScan(ctx, initialScan); err != nil {
			slog.Warn("failed to create scan record", "error", err)
		}
	}

	// Stage 4: Freeze the public graph totals before mutation.
	var (
		graphBefore    *model.GraphSnapshot
		graphBeforeErr error
	)
	stageStart = time.Now()
	if p.graphDB == nil {
		appendStage(result, "graph_stats_before", sdkingest.OutcomeNotApplicable, false, stageStart, nil)
	} else {
		stats, err := p.graphDB.GetStats(ctx)
		graphBeforeErr = err
		if err != nil {
			appendStage(result, "graph_stats_before", sdkingest.OutcomeFailed, true, stageStart, err)
		} else {
			graphBefore = modelGraphSnapshot(stats)
			result.GraphBefore = sdkGraphTotals(graphBefore)
			appendStage(result, "graph_stats_before", sdkingest.OutcomeComplete, true, stageStart, nil)
		}
	}

	// Stage 5: Write nodes.
	stageStart = time.Now()
	nodesWritten, err := p.writer.WriteObservationNodes(
		ctx,
		writeGraph.Nodes,
		data.Meta.ScanID,
		completeDomains,
	)
	result.NodesWritten = nodesWritten
	if err != nil {
		appendStage(result, "write_nodes", sdkingest.OutcomeFailed, true, stageStart, err)
		appendStage(result, "write_edges", sdkingest.OutcomeNotApplicable, true, time.Now(), nil)
		p.finishWriteFailure(ctx, data, result, graphBefore, completeDomains, fmt.Errorf("write nodes: %w", err))
		result.Duration = time.Since(start)
		return result, fmt.Errorf("write nodes: %w", err)
	}
	appendStage(result, "write_nodes", sdkingest.OutcomeComplete, true, stageStart, nil)
	slog.Info("nodes written", "count", nodesWritten)

	// Stage 6: Write edges.
	stageStart = time.Now()
	edgesWritten, err := p.writer.WriteObservationEdges(
		ctx,
		writeGraph.Edges,
		data.Meta.ScanID,
		completeDomains,
	)
	result.EdgesWritten = edgesWritten
	if err != nil {
		appendStage(result, "write_edges", sdkingest.OutcomeFailed, true, stageStart, err)
		p.finishWriteFailure(ctx, data, result, graphBefore, completeDomains, fmt.Errorf("write edges: %w", err))
		result.Duration = time.Since(start)
		return result, fmt.Errorf("write edges: %w", err)
	}
	appendStage(result, "write_edges", sdkingest.OutcomeComplete, true, stageStart, nil)
	slog.Info("edges written", "count", edgesWritten)

	// Stage 7: Reconcile stdio-v1 aliases against candidates already resident
	// in Neo4j. This updates compatibility properties only; it never copies or
	// rewires relationships from a many-to-one legacy aggregate.
	var identityCompatibilityErr error
	stageStart = time.Now()
	switch {
	case len(data.Meta.IdentityAliases) == 0:
		appendStage(
			result,
			"identity_compatibility",
			sdkingest.OutcomeNotApplicable,
			false,
			stageStart,
			nil,
		)
	case p.graphDB == nil:
		identityCompatibilityErr = fmt.Errorf("graph database unavailable")
		appendStage(
			result,
			"identity_compatibility",
			sdkingest.OutcomeFailed,
			true,
			stageStart,
			identityCompatibilityErr,
		)
	default:
		var resolved []sdkingest.IdentityAlias
		resolved, _, identityCompatibilityErr = graph.ReconcileMCPStdioIdentities(
			ctx,
			p.graphDB,
			data.Meta.IdentityAliases,
		)
		if len(resolved) > 0 {
			data.Meta.IdentityAliases = resolved
		}
		if identityCompatibilityErr != nil {
			appendStage(
				result,
				"identity_compatibility",
				sdkingest.OutcomeFailed,
				true,
				stageStart,
				identityCompatibilityErr,
			)
		} else {
			appendStage(
				result,
				"identity_compatibility",
				sdkingest.OutcomeComplete,
				true,
				stageStart,
				nil,
			)
		}
	}

	// Stage 8: Promote explicitly complete raw-observation domains. Unknown or
	// partial coverage is retained without retirement.
	var (
		reconciliation graph.ReconciliationStats
		reconcileErr   error
	)
	reconciliationDomains := completeDomains
	if identityCompatibilityErr != nil {
		reconciliationDomains = nil
	}
	stageStart = time.Now()
	if len(reconciliationDomains) == 0 {
		appendStage(result, "reconcile_observations", sdkingest.OutcomeUnknown, true, stageStart, nil)
	} else {
		reconciliation, reconcileErr = graph.ReconcileObservations(
			ctx,
			p.graphDB,
			data.Meta.ScanID,
			reconciliationDomains,
		)
		if reconcileErr != nil {
			appendStage(result, "reconcile_observations", sdkingest.OutcomeFailed, true, stageStart, reconcileErr)
		} else {
			appendStage(result, "reconcile_observations", sdkingest.OutcomeComplete, true, stageStart, nil)
		}
	}
	promotedDomains := reconciliationDomains
	if p.graphDB == nil || reconcileErr != nil {
		promotedDomains = nil
	}

	// Stage 9: Post-processing. Cleanup inside RunPostProcessors occurs only
	// after every processor successfully recomputes its output.
	var ppErr error
	stageStart = time.Now()
	if p.graphDB != nil && p.runPP != nil {
		var ppStats []graph.ProcessingStats
		ppStats, ppErr = p.runPP(
			ctx,
			p.graphDB,
			data.Meta.ScanID,
			coverageCollectors(promotedDomains),
		)
		if ppErr != nil {
			slog.Error("post-processing failed", "error", ppErr)
		}
		for _, s := range ppStats {
			result.PostProcessingStats = append(result.PostProcessingStats, sdkingest.PostProcessingStat{
				ProcessorName: s.ProcessorName,
				EdgesCreated:  s.EdgesCreated,
				NodesUpdated:  s.NodesUpdated,
				Duration:      s.Duration,
				Error:         s.Error,
			})
		}
		if ppErr != nil {
			appendStage(result, "analysis", sdkingest.OutcomeFailed, true, stageStart, ppErr)
		} else {
			appendStage(result, "analysis", sdkingest.OutcomeComplete, true, stageStart, nil)
		}
	} else {
		appendStage(result, "analysis", sdkingest.OutcomeNotApplicable, false, stageStart, nil)
	}

	// Stage 10: Remove ownerless nodes that were kept connected by the prior
	// composite epoch during the first reconciliation pass.
	var pruneErr error
	stageStart = time.Now()
	if ppErr == nil && len(promotedDomains) > 0 {
		var deleted int
		deleted, pruneErr = graph.PruneUnownedObservationNodes(ctx, p.graphDB)
		reconciliation.NodesDeleted += deleted
		if pruneErr != nil {
			appendStage(result, "prune_observations", sdkingest.OutcomeFailed, true, stageStart, pruneErr)
		} else {
			appendStage(result, "prune_observations", sdkingest.OutcomeComplete, true, stageStart, nil)
		}
	} else {
		appendStage(
			result,
			"prune_observations",
			sdkingest.OutcomeNotApplicable,
			len(promotedDomains) > 0,
			stageStart,
			nil,
		)
	}
	finalizedDomains := promotedDomains
	if pruneErr != nil {
		finalizedDomains = nil
	}

	// Stage 11: Explicitly account for pre-lifecycle/unknown graph facts.
	// They remain non-destructive, but the global projection cannot be
	// complete until a complete observation migrates them into managed
	// ownership (or an explicit migration does so).
	var (
		observationCompleteness  graph.ObservationCompleteness
		observationQueryErr      error
		observationIncompleteErr error
		observationStatus        string
		resolvedDirtyCoverage    []string
	)
	stageStart = time.Now()
	if p.graphDB == nil {
		observationQueryErr = fmt.Errorf("graph database unavailable")
		observationStatus = model.LifecycleFailed
		appendStage(
			result,
			"observation_completeness",
			sdkingest.OutcomeFailed,
			true,
			stageStart,
			observationQueryErr,
		)
	} else {
		observationCompleteness, observationQueryErr =
			graph.GetObservationCompleteness(ctx, p.graphDB)
		switch {
		case observationQueryErr != nil:
			observationStatus = model.LifecycleFailed
			appendStage(
				result,
				"observation_completeness",
				sdkingest.OutcomeFailed,
				true,
				stageStart,
				observationQueryErr,
			)
		case !observationCompleteness.Complete():
			observationStatus = model.LifecyclePartial
			observationIncompleteErr = fmt.Errorf(
				"legacy or unknown observations remain: %d legacy nodes, %d legacy relationships, %d unscoped nodes, %d unscoped relationships, %d property-incomplete nodes, %d property-incomplete relationships, %d identity-quarantined nodes",
				observationCompleteness.LegacyNodes,
				observationCompleteness.LegacyRelationships,
				observationCompleteness.UnscopedNodes,
				observationCompleteness.UnscopedRelationships,
				observationCompleteness.IncompletePropertyNodes,
				observationCompleteness.IncompletePropertyRelationships,
				observationCompleteness.IdentityQuarantinedNodes,
			)
			appendStage(
				result,
				"observation_completeness",
				sdkingest.OutcomePartial,
				true,
				stageStart,
				observationIncompleteErr,
			)
		default:
			observationStatus = model.LifecycleComplete
			resolvedDirtyCoverage = []string{legacyUnknownCoverageKey}
			appendStage(
				result,
				"observation_completeness",
				sdkingest.OutcomeComplete,
				true,
				stageStart,
				nil,
			)
		}
	}

	// Stage 12: Freeze the complete post-analysis graph revision.
	var (
		graphAfter    *model.GraphSnapshot
		graphAfterErr error
	)
	stageStart = time.Now()
	if p.graphDB == nil {
		appendStage(result, "graph_stats_after", sdkingest.OutcomeNotApplicable, false, stageStart, nil)
	} else {
		stats, err := p.graphDB.GetStats(ctx)
		graphAfterErr = err
		if err != nil {
			appendStage(result, "graph_stats_after", sdkingest.OutcomeFailed, true, stageStart, err)
		} else {
			graphAfter = modelGraphSnapshot(stats)
			result.GraphAfter = sdkGraphTotals(graphAfter)
			appendStage(result, "graph_stats_after", sdkingest.OutcomeComplete, true, stageStart, nil)
		}
	}

	// Stage 13: Materialize a candidate finding snapshot. Failed analysis
	// deliberately finalizes an unavailable/empty snapshot for this scan so a
	// same-ID retry cannot leave stale rows behind.
	var (
		snapshot    []model.Finding
		snapshotErr error
	)
	stageStart = time.Now()
	switch {
	case p.findingStore == nil:
		appendStage(result, "snapshot", sdkingest.OutcomeNotApplicable, false, stageStart, nil)
	case p.graphDB == nil:
		snapshotErr = fmt.Errorf("graph database unavailable")
		appendStage(result, "snapshot", sdkingest.OutcomeFailed, true, stageStart, snapshotErr)
	case p.runPP == nil:
		snapshotErr = fmt.Errorf("analysis pipeline unavailable")
		appendStage(result, "snapshot", sdkingest.OutcomeFailed, true, stageStart, snapshotErr)
	case ppErr != nil:
		snapshotErr = fmt.Errorf("analysis incomplete: %w", ppErr)
		appendStage(result, "snapshot", sdkingest.OutcomeFailed, true, stageStart, snapshotErr)
	default:
		snapshot, snapshotErr = analysis.QueryFindings(ctx, p.graphDB, "")
		if snapshotErr != nil {
			appendStage(result, "snapshot", sdkingest.OutcomeFailed, true, stageStart, snapshotErr)
		} else {
			if snapshot == nil {
				snapshot = []model.Finding{}
			}
			appendStage(result, "snapshot", sdkingest.OutcomeComplete, true, stageStart, nil)
		}
	}

	dirtyCoverage := append([]string(nil), cumulativeDirtyCoverage...)
	if attributionComplete &&
		artifactObservedAt != nil &&
		timestampErr == nil &&
		identityCompatibilityErr == nil &&
		reconcileErr == nil &&
		pruneErr == nil &&
		ppErr == nil &&
		graphBeforeErr == nil &&
		graphAfterErr == nil &&
		snapshotErr == nil {
		dirtyCoverage = subtractCoverage(
			cumulativeDirtyCoverage,
			finalizedDomains,
			resolvedDirtyCoverage,
		)
		dirtyCoverage = mergeCoverage(
			dirtyCoverage,
			incompleteCoverageDomains(data.Meta.Collection),
		)
	}
	if observationQueryErr != nil || observationIncompleteErr != nil {
		dirtyCoverage = mergeCoverage(dirtyCoverage, []string{legacyUnknownCoverageKey})
	} else {
		dirtyCoverage = subtractCoverage(dirtyCoverage, resolvedDirtyCoverage)
	}

	_, publicationCapable := p.findingStore.(findingPublisher)
	requiredComplete := coverageComplete &&
		artifactObservedAt != nil &&
		timestampErr == nil &&
		identityCompatibilityErr == nil &&
		reconcileErr == nil &&
		pruneErr == nil &&
		ppErr == nil &&
		graphBeforeErr == nil &&
		graphAfterErr == nil &&
		snapshotErr == nil &&
		observationQueryErr == nil &&
		observationIncompleteErr == nil &&
		p.graphDB != nil &&
		p.runPP != nil
	publish := requiredComplete && publicationCapable && len(dirtyCoverage) == 0

	graphStatus := model.LifecyclePartial
	if data.Meta.Collection == nil {
		graphStatus = model.LifecycleUnknown
	} else if coverageComplete &&
		identityCompatibilityErr == nil &&
		reconcileErr == nil &&
		pruneErr == nil {
		graphStatus = model.LifecycleComplete
	}
	analysisStatus := model.LifecycleComplete
	if ppErr != nil {
		analysisStatus = model.LifecycleFailed
	} else if p.graphDB == nil || p.runPP == nil {
		analysisStatus = model.LifecycleNotApplicable
	}
	snapshotStatus := model.LifecycleComplete
	if snapshotErr != nil {
		snapshotStatus = model.LifecycleFailed
	} else if p.findingStore == nil {
		snapshotStatus = model.LifecycleNotApplicable
	}

	finalStatus := model.ScanStatusCompletedWithErrors
	projectionStatus := model.ProjectionIncomplete
	if publish {
		finalStatus = model.ScanStatusCompleted
		projectionStatus = model.ProjectionComplete
	} else if requiredComplete && !publicationCapable {
		// Preserve compatibility for in-process/test deployments that
		// intentionally omit PostgreSQL publication support.
		finalStatus = model.ScanStatusCompleted
		projectionStatus = model.ProjectionUnknown
	}
	var coverageErr error
	if !coverageComplete {
		coverageErr = fmt.Errorf("collection coverage is partial, unknown, or lacks per-fact attribution")
	}
	var dirtyCoverageErr error
	if len(dirtyCoverage) > 0 {
		dirtyCoverageErr = fmt.Errorf(
			"unresolved dirty coverage remains: %v",
			dirtyCoverage,
		)
	}
	finalError := joinedStageErrors(
		timestampErr,
		normalizationDegradedErr,
		coverageErr,
		dirtyCoverageErr,
		identityCompatibilityErr,
		reconcileErr,
		pruneErr,
		ppErr,
		graphBeforeErr,
		graphAfterErr,
		snapshotErr,
		observationQueryErr,
		observationIncompleteErr,
	)

	stageStart = time.Now()
	if publish {
		appendStage(result, "publication", sdkingest.OutcomeComplete, true, stageStart, nil)
	} else {
		publicationReason := fmt.Errorf("publication withheld: projection is not complete")
		if dirtyCoverageErr != nil {
			publicationReason = fmt.Errorf("publication withheld: %w", dirtyCoverageErr)
		}
		appendStage(result, "publication", sdkingest.OutcomeNotApplicable, true, stageStart, publicationReason)
	}

	completedAt := time.Now().UTC()
	finalScan := model.Scan{
		ID:                 data.Meta.ScanID,
		Collector:          data.Meta.Collector,
		Status:             finalStatus,
		StartedAt:          initialScan.StartedAt,
		CompletedAt:        &completedAt,
		ArtifactObservedAt: artifactObservedAt,
		NodeCount:          result.NodesWritten,
		EdgeCount:          result.EdgesWritten,
		Error:              finalError,
		CollectionStatus:   string(collectionState(data.Meta.Collection)),
		GraphStatus:        graphStatus,
		AnalysisStatus:     analysisStatus,
		SnapshotStatus:     snapshotStatus,
		ProjectionStatus:   projectionStatus,
		PublicationStatus:  model.PublicationUnpublished,
		ComparisonKey:      comparisonKey(data, attributionComplete),
	}
	finalScan.Metadata = buildScanMetadata(
		data,
		result,
		graphBefore,
		graphAfter,
		reconciliation,
		observationCompleteness,
		finalizedDomains,
	)

	if publisher, ok := p.findingStore.(findingPublisher); ok {
		publication, err := publisher.FinalizeScan(ctx, appdb.FinalizeScanParams{
			Scan:                  finalScan,
			Findings:              snapshot,
			Stages:                result.Stages,
			Collection:            data.Meta.Collection,
			Ruleset:               data.Meta.Ruleset,
			IdentitySchemes:       data.Meta.IdentitySchemes,
			NormalizationStatus:   result.NormalizationStatus,
			NormalizationWarnings: result.NormalizationWarnings,
			ObservationStatus:     observationStatus,
			ObservationDetails:    modelObservationCompleteness(observationCompleteness),
			CoverageKeys:          keys,
			CompleteDomains:       finalizedDomains,
			ResolvedDirtyCoverage: resolvedDirtyCoverage,
			DirtyCoverage:         dirtyCoverage,
			GraphBefore:           graphBefore,
			GraphAfter:            graphAfter,
			Publish:               publish,
		})
		if err != nil {
			slog.Error("scan finalization failed", "error", err)
			publicationErr := fmt.Errorf("publication: %w", err)
			result.Stages[len(result.Stages)-1].State = sdkingest.OutcomeFailed
			result.Stages[len(result.Stages)-1].Error = publicationErr.Error()
			result.Outcome = sdkingest.OutcomePartial
			result.ProjectionStatus = model.ProjectionIncomplete
			result.Duration = time.Since(start)
			p.recordFailure(ctx, appdb.ScanFailure{
				ID:               data.Meta.ScanID,
				Status:           model.ScanStatusCompletedWithErrors,
				NodeCount:        result.NodesWritten,
				EdgeCount:        result.EdgesWritten,
				Error:            publicationErr.Error(),
				CollectionStatus: finalScan.CollectionStatus,
				GraphStatus:      finalScan.GraphStatus,
				AnalysisStatus:   finalScan.AnalysisStatus,
				SnapshotStatus:   model.LifecycleFailed,
				ProjectionStatus: model.ProjectionIncomplete,
				DirtyCoverage:    dirtyCoverage,
				Metadata: buildScanMetadata(
					data,
					result,
					graphBefore,
					graphAfter,
					reconciliation,
					observationCompleteness,
					finalizedDomains,
				),
			})
			return result, nil
		}
		if publication != nil {
			result.PublishedRevision = publication.Revision
			if publish && !publication.Published {
				publish = false
				result.Stages[len(result.Stages)-1].State = sdkingest.OutcomeNotApplicable
				result.Stages[len(result.Stages)-1].Error =
					"publication withheld: inherited dirty coverage remains"
			}
		}
	} else {
		// Compatibility path for unit tests and callers that deliberately
		// construct a pipeline without the lifecycle publication store.
		if p.findingStore != nil {
			compatibilitySnapshot := snapshot
			if snapshotErr != nil {
				// InsertFindings is replacement-based, so an explicit empty
				// snapshot clears stale rows left by a same-ID prior attempt.
				compatibilitySnapshot = []model.Finding{}
			}
			if err := p.findingStore.InsertFindings(ctx, data.Meta.ScanID, compatibilitySnapshot); err != nil {
				slog.Warn("findings snapshot insert failed", "error", err)
				finalStatus = model.ScanStatusCompletedWithErrors
				finalError = err.Error()
			}
		}
		if p.scanStore != nil {
			if err := p.scanStore.UpdateScan(
				ctx,
				data.Meta.ScanID,
				finalStatus,
				result.NodesWritten,
				result.EdgesWritten,
				finalError,
			); err != nil {
				slog.Warn("failed to update scan record", "error", err)
			}
		}
	}

	if publish {
		result.Outcome = sdkingest.OutcomeComplete
		result.ProjectionStatus = model.ProjectionComplete
	} else if requiredComplete && !publicationCapable {
		result.Outcome = sdkingest.OutcomeComplete
		result.ProjectionStatus = model.ProjectionUnknown
	} else {
		result.Outcome = sdkingest.OutcomePartial
		result.ProjectionStatus = model.ProjectionIncomplete
	}
	result.Duration = time.Since(start)
	slog.Info("ingest complete",
		"scan_id", data.Meta.ScanID,
		"node_write_rows", result.NodesWritten,
		"edge_write_rows", result.EdgesWritten,
		"outcome", result.Outcome,
		"projection_status", result.ProjectionStatus,
		"duration", result.Duration,
	)
	return result, nil
}

func (p *Pipeline) finishWriteFailure(
	ctx context.Context,
	data *sdkingest.IngestData,
	result *sdkingest.IngestResult,
	graphBefore *model.GraphSnapshot,
	completeDomains []string,
	writeErr error,
) {
	now := time.Now()
	appendStage(result, "identity_compatibility", sdkingest.OutcomeNotApplicable, false, now, nil)
	appendStage(result, "reconcile_observations", sdkingest.OutcomeNotApplicable, true, now, nil)
	appendStage(result, "analysis", sdkingest.OutcomeNotApplicable, true, now, nil)
	appendStage(result, "prune_observations", sdkingest.OutcomeNotApplicable, true, now, nil)

	var graphAfter *model.GraphSnapshot
	if p.graphDB != nil {
		stageStart := time.Now()
		stats, err := p.graphDB.GetStats(ctx)
		if err != nil {
			appendStage(result, "graph_stats_after", sdkingest.OutcomeFailed, true, stageStart, err)
		} else {
			graphAfter = modelGraphSnapshot(stats)
			result.GraphAfter = sdkGraphTotals(graphAfter)
			appendStage(result, "graph_stats_after", sdkingest.OutcomeComplete, true, stageStart, nil)
		}
	} else {
		appendStage(result, "graph_stats_after", sdkingest.OutcomeNotApplicable, false, now, nil)
	}
	appendStage(result, "snapshot", sdkingest.OutcomeNotApplicable, true, now, nil)
	appendStage(result, "publication", sdkingest.OutcomeNotApplicable, true, now, nil)

	result.Outcome = sdkingest.OutcomeFailed
	result.ProjectionStatus = model.ProjectionIncomplete
	result.Duration = time.Since(now)
	p.recordFailure(ctx, appdb.ScanFailure{
		ID:               data.Meta.ScanID,
		Status:           model.ScanStatusFailed,
		NodeCount:        result.NodesWritten,
		EdgeCount:        result.EdgesWritten,
		Error:            writeErr.Error(),
		CollectionStatus: string(collectionState(data.Meta.Collection)),
		GraphStatus:      model.LifecycleFailed,
		AnalysisStatus:   model.LifecycleNotApplicable,
		SnapshotStatus:   model.LifecycleNotApplicable,
		ProjectionStatus: model.ProjectionIncomplete,
		DirtyCoverage:    coverageKeys(data.Meta.Collection),
		Metadata: buildScanMetadata(
			data,
			result,
			graphBefore,
			graphAfter,
			graph.ReconciliationStats{},
			graph.ObservationCompleteness{},
			completeDomains,
		),
	})
}

func (p *Pipeline) recordFailure(ctx context.Context, failure appdb.ScanFailure) {
	if p.scanStore == nil {
		return
	}
	if lifecycleStore, ok := p.scanStore.(scanLifecycleRecorder); ok {
		if err := lifecycleStore.RecordFailure(ctx, failure); err != nil {
			slog.Warn("failed to record scan lifecycle failure", "error", err)
		}
		return
	}
	if err := p.scanStore.UpdateScan(
		ctx,
		failure.ID,
		failure.Status,
		failure.NodeCount,
		failure.EdgeCount,
		failure.Error,
	); err != nil {
		slog.Warn("failed to record scan failure", "error", err)
	}
}
