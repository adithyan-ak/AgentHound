package ingest

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
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

// scanLifecycleRecorder is the lifecycle subset of *appdb.ScanStore used by
// Pipeline. It remains an interface so tests can substitute a recorder, but
// every ingest requires both operations.
type scanLifecycleRecorder interface {
	CollectionPointRecognized(ctx context.Context, collectionPointID string) (bool, error)
	BeginScan(
		ctx context.Context,
		scan *model.Scan,
		dirtyCoverage []string,
		coverageParents map[string]string,
	) ([]string, error)
	RecordCampaignRejection(
		ctx context.Context,
		audit appdb.CampaignRejectionAudit,
	) error
	ResolveRetiredCoverage(
		ctx context.Context,
		roots []sdkingest.CoverageRoot,
	) ([]string, error)
	RecordFailure(ctx context.Context, failure appdb.ScanFailure) error
}

// postProcessFunc runs the analysis post-processors. Defaulted to
// analysis.RunPostProcessors; replaceable in tests to assert behavior
// without exercising every concrete processor. Complete domains enable a
// fresh global composite epoch; empty input preserves the current epoch.
type postProcessFunc func(ctx context.Context, db graph.GraphDB, scanID string, completeDomains []string) ([]graph.ProcessingStats, error)

// findingPublisher is the atomic lifecycle/publication subset of
// *appdb.FindingStore. The interface is a real test seam, not an optional
// capability: every ingest finalizes through it.
type findingPublisher interface {
	FinalizeScan(ctx context.Context, params appdb.FinalizeScanParams) (*appdb.PublicationResult, error)
}

type storageVerifier interface {
	Verify(context.Context) error
}

// Pipeline serializes ingests through a single mutex.
//
// Raw-observation promotion and composite epoch replacement both mutate the
// shared live projection. Serializing prevents two scans from retiring one
// another's candidate ownership tokens or derived epochs.
type Pipeline struct {
	mu           sync.Mutex
	validator    *Validator
	normalizer   *Normalizer
	writer       nodeEdgeWriter
	graphDB      graph.GraphDB
	scanStore    scanLifecycleRecorder
	findingStore findingPublisher
	runPP        postProcessFunc
	storageGuard storageVerifier
}

func NewPipeline(
	writer *graph.Writer,
	graphDB graph.GraphDB,
	scanStore *appdb.ScanStore,
	findingStore *appdb.FindingStore,
	storageGuard storageVerifier,
) *Pipeline {
	p := &Pipeline{
		validator:    NewValidator(),
		normalizer:   NewNormalizer(),
		graphDB:      graphDB,
		runPP:        analysis.RunPostProcessors,
		storageGuard: storageGuard,
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
	// Storage-pair verification is the first operation after the nil check. It is
	// read-only and deliberately precedes generic validation because invalid
	// campaign handling writes a PostgreSQL audit row.
	if p.storageGuard == nil {
		return nil, fmt.Errorf("storage binding admission guard unavailable")
	}
	if err := p.storageGuard.Verify(ctx); err != nil {
		return nil, err
	}
	result := &sdkingest.IngestResult{
		ScanID:  data.Meta.ScanID,
		Outcome: sdkingest.OutcomeUnknown,
		Identity: sdkingest.IngestIdentityResult{
			CollectionPointID: data.Meta.Identity.CollectionPointID,
			NetworkContextID:  data.Meta.Identity.NetworkContextID,
			Quality:           data.Meta.Identity.Quality,
			NetworkQuality:    data.Meta.Identity.NetworkQuality,
			NetworkClass:      data.Meta.Identity.NetworkClass,
			Display:           data.Meta.Identity.Display,
			Recognition:       "unknown",
		},
	}

	// Stage 1: Validate
	stageStart := time.Now()
	if err := p.validator.Validate(data); err != nil {
		if isCampaignSubmission(data) {
			return nil, p.rejectCampaignArtifact(
				ctx,
				campaignAuditIdentityFromData(data),
				campaignRejectionGenericIngestInvalid,
			)
		}
		return nil, err
	}
	appendStage(result, "validate", sdkingest.OutcomeComplete, true, stageStart, nil)
	slog.Info("validation passed", "nodes", len(data.Graph.Nodes), "edges", len(data.Graph.Edges))

	// Campaign artifacts receive their scenario-specific structural and live
	// topology validation before normalization, BeginScan, canonical writes, or
	// reconciliation. Rejections are audit-only PostgreSQL rows and cannot dirty
	// or retire coverage.
	if err := p.prevalidateCampaignArtifact(ctx, data); err != nil {
		return nil, err
	}

	result.Collection = *data.Meta.Collection
	stageStart = time.Now()
	rulesetState, rulesetErr := rulesetPublicationState(data.Meta.Ruleset)
	appendStage(result, "ruleset", rulesetState, true, stageStart, rulesetErr)

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
	result.Submitted.Nodes = len(data.Graph.Nodes)
	result.Submitted.Edges = len(data.Graph.Edges)
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
	authoritativeRoots := sdkingest.CompleteAuthoritativeRoots(data.Meta.Collection)
	if !attributionComplete || normalizationDegradedErr != nil {
		completeDomains = nil
		authoritativeRoots = nil
	}
	coverageComplete := sdkingest.CollectionCoverageComplete(data.Meta.Collection) &&
		attributionComplete &&
		normalizationDegradedErr == nil
	// Preserve owner-scoped contributions through the pipeline. The graph
	// writer fingerprints each original owner before deterministically
	// coalescing compatible contributions into unique database rows.
	writeGraph := data.Graph

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
	if p.scanStore == nil {
		return nil, fmt.Errorf("begin scan lifecycle: lifecycle store unavailable")
	}
	recognized, err := p.scanStore.CollectionPointRecognized(
		ctx,
		data.Meta.Identity.CollectionPointID,
	)
	if err != nil {
		return nil, err
	}
	if recognized {
		result.Identity.Recognition = "recognized"
	} else {
		result.Identity.Recognition = "new"
	}

	// Stage 3: Record scan start and projection attempt.
	if p.findingStore == nil {
		return nil, fmt.Errorf("begin scan lifecycle: publication store unavailable")
	}
	retiredDomains, err := p.scanStore.ResolveRetiredCoverage(ctx, authoritativeRoots)
	if err != nil {
		return nil, fmt.Errorf("resolve authoritative coverage: %w", err)
	}
	reconciliationDomains := mergeCoverage(completeDomains, retiredDomains)
	cumulativeDirtyCoverage, err := p.scanStore.BeginScan(
		ctx,
		initialScan,
		mergeCoverage(keys, retiredDomains),
		sdkingest.CoverageParents(data.Meta.Collection),
	)
	if err != nil {
		return nil, fmt.Errorf("begin scan lifecycle: %w", err)
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
			result.GraphTotals.Before = sdkGraphTotals(graphBefore)
			appendStage(result, "graph_stats_before", sdkingest.OutcomeComplete, true, stageStart, nil)
		}
	}

	// Stage 5: Write nodes.
	stageStart = time.Now()
	nodesWritten, err := p.writer.WriteObservationNodes(
		ctx,
		writeGraph.Nodes,
		data.Meta.ScanID,
		reconciliationDomains,
	)
	result.WriteRows.Nodes = nodesWritten
	if err != nil {
		appendStage(result, "write_nodes", sdkingest.OutcomeFailed, true, stageStart, err)
		appendStage(result, "write_edges", sdkingest.OutcomeNotApplicable, true, time.Now(), nil)
		p.finishWriteFailure(ctx, data, result, graphBefore, reconciliationDomains, fmt.Errorf("write nodes: %w", err))
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
		reconciliationDomains,
	)
	result.WriteRows.Edges = edgesWritten
	if err != nil {
		appendStage(result, "write_edges", sdkingest.OutcomeFailed, true, stageStart, err)
		p.finishWriteFailure(ctx, data, result, graphBefore, reconciliationDomains, fmt.Errorf("write edges: %w", err))
		result.Duration = time.Since(start)
		return result, fmt.Errorf("write edges: %w", err)
	}
	appendStage(result, "write_edges", sdkingest.OutcomeComplete, true, stageStart, nil)
	slog.Info("edges written", "count", edgesWritten)

	pristineEmptyProjection := graphBefore != nil &&
		graphBefore.TotalNodes == 0 &&
		graphBefore.TotalEdges == 0 &&
		len(writeGraph.Nodes) == 0 &&
		len(writeGraph.Edges) == 0 &&
		result.WriteRows.Nodes == 0 &&
		result.WriteRows.Edges == 0
	if pristineEmptyProjection {
		slog.Info("using pristine empty projection fast path")
	}

	// Stage 7: Promote explicitly complete raw-observation domains. Unknown or
	// partial coverage is retained without retirement.
	var (
		reconciliation graph.ReconciliationStats
		reconcileErr   error
	)
	stageStart = time.Now()
	if pristineEmptyProjection {
		appendStage(result, "reconcile_observations", sdkingest.OutcomeComplete, true, stageStart, nil)
	} else if len(reconciliationDomains) == 0 {
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

	// Stage 8: Post-processing. Any promoted raw domain starts a fresh global
	// composite epoch, rebuilt from the retained current raw projection.
	var ppErr error
	stageStart = time.Now()
	if pristineEmptyProjection && p.graphDB != nil && p.runPP != nil {
		appendStage(result, "analysis", sdkingest.OutcomeComplete, true, stageStart, nil)
	} else if p.graphDB != nil && p.runPP != nil {
		var ppStats []graph.ProcessingStats
		ppStats, ppErr = p.runPP(
			ctx,
			p.graphDB,
			data.Meta.ScanID,
			promotedDomains,
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

	// Stage 9: Remove ownerless nodes that were kept connected by the prior
	// composite epoch during the first reconciliation pass.
	var pruneErr error
	stageStart = time.Now()
	if pristineEmptyProjection && ppErr == nil && len(promotedDomains) > 0 {
		appendStage(result, "prune_observations", sdkingest.OutcomeComplete, true, stageStart, nil)
	} else if ppErr == nil && len(promotedDomains) > 0 {
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

	// Stage 10: Verify property completeness for public managed raw facts.
	var (
		observationCompleteness  graph.ObservationCompleteness
		observationQueryErr      error
		observationIncompleteErr error
		observationStatus        string
	)
	stageStart = time.Now()
	if pristineEmptyProjection {
		observationStatus = model.LifecycleComplete
		appendStage(
			result,
			"observation_completeness",
			sdkingest.OutcomeComplete,
			true,
			stageStart,
			nil,
		)
	} else if p.graphDB == nil {
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
				"managed raw observations are publication-unsafe: "+
					"%d property-incomplete nodes, %d property-incomplete relationships, "+
					"%d tokenless nodes, %d raw relationships incident to tokenless nodes",
				observationCompleteness.IncompletePropertyNodes,
				observationCompleteness.IncompletePropertyRelationships,
				observationCompleteness.TokenlessNodes,
				observationCompleteness.TokenlessIncidentRelationships,
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

	// Stage 11: Freeze the complete post-analysis graph revision.
	var (
		graphAfter    *model.GraphSnapshot
		graphAfterErr error
	)
	stageStart = time.Now()
	if pristineEmptyProjection {
		graphAfter = &model.GraphSnapshot{
			NodeCounts: map[string]int64{},
			EdgeCounts: map[string]int64{},
		}
		result.GraphTotals.After = sdkGraphTotals(graphAfter)
		appendStage(result, "graph_stats_after", sdkingest.OutcomeComplete, true, stageStart, nil)
	} else if p.graphDB == nil {
		appendStage(result, "graph_stats_after", sdkingest.OutcomeNotApplicable, false, stageStart, nil)
	} else {
		stats, err := p.graphDB.GetStats(ctx)
		graphAfterErr = err
		if err != nil {
			appendStage(result, "graph_stats_after", sdkingest.OutcomeFailed, true, stageStart, err)
		} else {
			graphAfter = modelGraphSnapshot(stats)
			result.GraphTotals.After = sdkGraphTotals(graphAfter)
			appendStage(result, "graph_stats_after", sdkingest.OutcomeComplete, true, stageStart, nil)
		}
	}

	// Stage 12: Materialize a candidate finding snapshot. Failed analysis
	// deliberately finalizes an unavailable/empty snapshot for this scan so a
	// same-ID retry cannot leave stale rows behind.
	var (
		snapshot    []model.Finding
		snapshotErr error
	)
	stageStart = time.Now()
	switch {
	case p.graphDB == nil:
		snapshotErr = fmt.Errorf("graph database unavailable")
		appendStage(result, "snapshot", sdkingest.OutcomeFailed, true, stageStart, snapshotErr)
	case p.runPP == nil:
		snapshotErr = fmt.Errorf("analysis pipeline unavailable")
		appendStage(result, "snapshot", sdkingest.OutcomeFailed, true, stageStart, snapshotErr)
	case ppErr != nil:
		snapshotErr = fmt.Errorf("analysis incomplete: %w", ppErr)
		appendStage(result, "snapshot", sdkingest.OutcomeFailed, true, stageStart, snapshotErr)
	case pristineEmptyProjection:
		snapshot = []model.Finding{}
		appendStage(result, "snapshot", sdkingest.OutcomeComplete, true, stageStart, nil)
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
	if snapshot == nil {
		snapshot = []model.Finding{}
	}
	result.Findings = len(snapshot)

	publicationDomains := finalizedDomains
	if observationQueryErr != nil || observationIncompleteErr != nil {
		publicationDomains = nil
	}
	publicationCompleteDomains := completeDomains
	publicationRetiredDomains := retiredDomains
	publicationAuthoritativeRoots := authoritativeRoots
	if publicationDomains == nil {
		publicationCompleteDomains = nil
		publicationRetiredDomains = nil
		publicationAuthoritativeRoots = nil
	}
	dirtyCoverage := append([]string(nil), cumulativeDirtyCoverage...)
	if attributionComplete &&
		rulesetErr == nil &&
		artifactObservedAt != nil &&
		timestampErr == nil &&
		reconcileErr == nil &&
		pruneErr == nil &&
		ppErr == nil &&
		graphBeforeErr == nil &&
		graphAfterErr == nil &&
		snapshotErr == nil &&
		observationQueryErr == nil &&
		observationIncompleteErr == nil {
		dirtyCoverage = subtractCoverage(
			cumulativeDirtyCoverage,
			publicationDomains,
		)
		dirtyCoverage = mergeCoverage(
			dirtyCoverage,
			incompleteCoverageDomains(data.Meta.Collection),
		)
	}

	requiredComplete := coverageComplete &&
		rulesetErr == nil &&
		artifactObservedAt != nil &&
		timestampErr == nil &&
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
	publish := requiredComplete && len(dirtyCoverage) == 0

	graphStatus := model.LifecyclePartial
	if data.Meta.Collection == nil {
		graphStatus = model.LifecycleUnknown
	} else if coverageComplete &&
		reconcileErr == nil &&
		pruneErr == nil &&
		observationQueryErr == nil &&
		observationIncompleteErr == nil {
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
	}

	finalStatus := model.ScanStatusCompletedWithErrors
	projectionStatus := model.ProjectionIncomplete
	if publish {
		finalStatus = model.ScanStatusCompleted
		projectionStatus = model.ProjectionComplete
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
		rulesetErr,
		coverageErr,
		dirtyCoverageErr,
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
		if rulesetErr != nil {
			publicationReason = fmt.Errorf("publication withheld: %w", rulesetErr)
		} else if dirtyCoverageErr != nil {
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
		NodeWriteRows:      result.WriteRows.Nodes,
		EdgeWriteRows:      result.WriteRows.Edges,
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
		publicationDomains,
	)

	publication, err := p.findingStore.FinalizeScan(ctx, appdb.FinalizeScanParams{
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
		CoverageParents:       sdkingest.CoverageParents(data.Meta.Collection),
		CompleteDomains:       publicationCompleteDomains,
		ResolvedDirtyCoverage: publicationRetiredDomains,
		AuthoritativeRoots:    publicationAuthoritativeRoots,
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
			NodeWriteRows:    result.WriteRows.Nodes,
			EdgeWriteRows:    result.WriteRows.Edges,
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
				publicationDomains,
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

	if publish {
		result.Outcome = sdkingest.OutcomeComplete
		result.ProjectionStatus = model.ProjectionComplete
	} else {
		result.Outcome = sdkingest.OutcomePartial
		result.ProjectionStatus = model.ProjectionIncomplete
	}
	result.Duration = time.Since(start)
	slog.Info("ingest complete",
		"scan_id", data.Meta.ScanID,
		"node_write_rows", result.WriteRows.Nodes,
		"edge_write_rows", result.WriteRows.Edges,
		"outcome", result.Outcome,
		"projection_status", result.ProjectionStatus,
		"duration", result.Duration,
	)
	return result, nil
}

func rulesetPublicationState(
	ruleset *sdkingest.RulesetManifest,
) (sdkingest.OutcomeState, error) {
	if ruleset == nil {
		return sdkingest.OutcomeUnknown, fmt.Errorf("ruleset manifest is unavailable")
	}
	if ruleset.LoadState == sdkingest.OutcomeComplete && len(ruleset.Errors) == 0 {
		return sdkingest.OutcomeComplete, nil
	}
	if len(ruleset.Errors) > 0 {
		state := ruleset.LoadState
		if state == sdkingest.OutcomeComplete {
			state = sdkingest.OutcomeFailed
		}
		return state, fmt.Errorf(
			"ruleset load reported errors: %s",
			strings.Join(ruleset.Errors, "; "),
		)
	}
	return ruleset.LoadState, fmt.Errorf(
		"ruleset load state is %s",
		ruleset.LoadState,
	)
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
			result.GraphTotals.After = sdkGraphTotals(graphAfter)
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
		NodeWriteRows:    result.WriteRows.Nodes,
		EdgeWriteRows:    result.WriteRows.Edges,
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
	if err := p.scanStore.RecordFailure(ctx, failure); err != nil {
		slog.Warn("failed to record scan failure", "error", err)
	}
}
