package appdb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	sdkingest "github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/server/model"
	"github.com/jackc/pgx/v5"
)

type FinalizeScanParams struct {
	Scan                  model.Scan
	Findings              []model.Finding
	Stages                []sdkingest.StageResult
	Collection            *sdkingest.CollectionReport
	Ruleset               *sdkingest.RulesetManifest
	IdentitySchemes       []sdkingest.IdentityScheme
	NormalizationStatus   sdkingest.NormalizationStatus
	NormalizationWarnings []sdkingest.NormalizationWarning
	ObservationStatus     string
	ObservationDetails    model.PostureObservationCompleteness
	CoverageKeys          []string
	CompleteDomains       []string
	ResolvedDirtyCoverage []string
	DirtyCoverage         []string
	GraphBefore           *model.GraphSnapshot
	GraphAfter            *model.GraphSnapshot
	Publish               bool
}

type PublicationResult struct {
	Revision           *int64
	PublishedAt        *time.Time
	ComparableToScanID string
	Export             *model.PostureExport
	Published          bool
	DirtyCoverage      []string
}

// FinalizeScan atomically replaces the per-scan finding snapshot, advances
// complete coverage heads, freezes graph totals, finalizes the scan row, and
// optionally publishes one persisted export revision.
func (s *FindingStore) FinalizeScan(
	ctx context.Context,
	params FinalizeScanParams,
) (*PublicationResult, error) {
	if params.Scan.ID == "" {
		return nil, errors.New("finalize scan: empty scan id")
	}
	if params.Publish && params.GraphAfter == nil {
		return nil, errors.New("finalize scan: published scan requires graph totals")
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return nil, fmt.Errorf("begin scan finalization: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	requestedPublish := params.Publish
	var inheritedJSON []byte
	if err := tx.QueryRow(ctx, `SELECT dirty_coverage
		FROM posture_state WHERE singleton = TRUE
		FOR UPDATE`).Scan(&inheritedJSON); err != nil {
		return nil, fmt.Errorf("lock projection state for finalization: %w", err)
	}
	var inheritedDirty []string
	if err := json.Unmarshal(inheritedJSON, &inheritedDirty); err != nil {
		return nil, fmt.Errorf("decode inherited dirty coverage: %w", err)
	}
	params.DirtyCoverage = finalizedDirtyCoverage(
		inheritedDirty,
		params.CompleteDomains,
		params.ResolvedDirtyCoverage,
		params.DirtyCoverage,
	)
	params.Publish = params.Publish && len(params.DirtyCoverage) == 0
	if requestedPublish && !params.Publish {
		params.Scan.Status = model.ScanStatusCompletedWithErrors
		params.Scan.ProjectionStatus = model.ProjectionIncomplete
		dirtyErr := fmt.Sprintf(
			"publication withheld: unresolved dirty coverage: %v",
			params.DirtyCoverage,
		)
		if params.Scan.Error == "" {
			params.Scan.Error = dirtyErr
		} else {
			params.Scan.Error += "; " + dirtyErr
		}
	}

	preservePublishedSnapshot := false
	if !params.Publish {
		if err := tx.QueryRow(ctx, `SELECT coalesce(published_scan_id = $1, false)
			FROM posture_state WHERE singleton = TRUE`,
			params.Scan.ID,
		).Scan(&preservePublishedSnapshot); err != nil {
			return nil, fmt.Errorf("check published snapshot retry: %w", err)
		}
	}
	if !preservePublishedSnapshot {
		if err := replaceFindingsTx(ctx, tx, params.Scan.ID, params.Findings); err != nil {
			return nil, err
		}
	}
	for _, domain := range params.CompleteDomains {
		if domain == "" {
			continue
		}
		if _, err := tx.Exec(ctx, `INSERT INTO coverage_heads (coverage_key, scan_id, updated_at)
			VALUES ($1, $2, NOW())
			ON CONFLICT (coverage_key) DO UPDATE SET
			    scan_id = EXCLUDED.scan_id,
			    updated_at = NOW()`,
			domain, params.Scan.ID); err != nil {
			return nil, fmt.Errorf("promote coverage head %s: %w", domain, err)
		}
	}

	result := &PublicationResult{
		Published:     params.Publish,
		DirtyCoverage: append([]string(nil), params.DirtyCoverage...),
	}
	comparison := model.PostureComparison{}
	activeCoverageKeys := normalizeCoverageKeys(params.CoverageKeys)
	if params.Publish {
		var activeHeads []coverageHead
		activeHeads, err = activeCoverageHeadsTx(ctx, tx)
		if err != nil {
			return nil, err
		}
		activeCoverageKeys = make([]string, 0, len(activeHeads))
		for _, head := range activeHeads {
			activeCoverageKeys = append(activeCoverageKeys, head.Key)
		}
		params.Scan.ComparisonKey = comparisonKeyWithCoverageHeads(
			params.Scan.ComparisonKey,
			params.CompleteDomains,
			activeHeads,
		)
		comparison, err = priorComparablePublication(
			ctx,
			tx,
			params.Scan.ID,
			params.Scan.ComparisonKey,
			params.GraphAfter,
		)
		if err != nil {
			return nil, err
		}
	}
	result.ComparableToScanID = comparison.PreviousScanID

	var graphStatsJSON string
	if params.GraphAfter != nil {
		data, err := json.Marshal(params.GraphAfter)
		if err != nil {
			return nil, fmt.Errorf("marshal graph totals: %w", err)
		}
		graphStatsJSON = string(data)
	} else {
		graphStatsJSON = "{}"
	}

	if params.Publish {
		var revision int64
		var publishedAt time.Time
		err := tx.QueryRow(ctx, `INSERT INTO posture_publications
		    (scan_id, comparison_key, graph_stats, export)
		    VALUES ($1, NULLIF($2, ''), $3::jsonb, '{}'::jsonb)
		    RETURNING revision, published_at`,
			params.Scan.ID,
			params.Scan.ComparisonKey,
			graphStatsJSON,
		).Scan(&revision, &publishedAt)
		if err != nil {
			return nil, fmt.Errorf("create posture publication: %w", err)
		}

		findings, err := findingsForScanTx(ctx, tx, params.Scan.ID)
		if err != nil {
			return nil, err
		}
		export := buildPostureExport(
			params,
			revision,
			publishedAt,
			findings,
			comparison,
			activeCoverageKeys,
		)
		exportJSON, err := json.Marshal(export)
		if err != nil {
			return nil, fmt.Errorf("marshal posture export: %w", err)
		}
		if _, err := tx.Exec(ctx,
			`UPDATE posture_publications SET export = $1::jsonb WHERE revision = $2`,
			string(exportJSON), revision,
		); err != nil {
			return nil, fmt.Errorf("persist posture export: %w", err)
		}
		result.Revision = &revision
		result.PublishedAt = &publishedAt
		result.Export = &export
	}

	if err := finalizeScanRow(ctx, tx, params, result, preservePublishedSnapshot); err != nil {
		return nil, err
	}
	if err := finalizeProjectionState(ctx, tx, params, result); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit scan finalization: %w", err)
	}
	return result, nil
}

func finalizeScanRow(
	ctx context.Context,
	tx pgx.Tx,
	params FinalizeScanParams,
	result *PublicationResult,
	preservePublishedSnapshot bool,
) error {
	if params.Publish {
		if _, err := tx.Exec(ctx, `UPDATE scans SET
		    publication_status = $1,
		    lifecycle_updated_at = NOW()
		WHERE publication_status = $2 AND id <> $3`,
			model.PublicationSuperseded,
			model.PublicationPublished,
			params.Scan.ID,
		); err != nil {
			return fmt.Errorf("supersede prior publication scan: %w", err)
		}
	}

	var beforeNodes, beforeEdges, afterNodes, afterEdges *int64
	if params.GraphBefore != nil {
		beforeNodes = &params.GraphBefore.TotalNodes
		beforeEdges = &params.GraphBefore.TotalEdges
	}
	if params.GraphAfter != nil {
		afterNodes = &params.GraphAfter.TotalNodes
		afterEdges = &params.GraphAfter.TotalEdges
	}

	tag, err := tx.Exec(ctx, `UPDATE scans SET
	    status = $1,
	    completed_at = $2,
	    node_count = $3,
	    edge_count = $4,
	    error = NULLIF($5, ''),
	    collection_status = $6,
	    graph_status = $7,
	    analysis_status = $8,
	    snapshot_status = $9,
	    projection_status = $10,
	    publication_status = CASE
	        WHEN $11 THEN 'published'
	        WHEN publication_status = 'published' THEN publication_status
	        ELSE 'unpublished'
	    END,
	    comparison_key = CASE WHEN $22 THEN comparison_key ELSE NULLIF($12, '') END,
	    graph_total_nodes_before = CASE WHEN $22 THEN graph_total_nodes_before ELSE $13 END,
	    graph_total_edges_before = CASE WHEN $22 THEN graph_total_edges_before ELSE $14 END,
	    graph_total_nodes_after = CASE WHEN $22 THEN graph_total_nodes_after ELSE $15 END,
	    graph_total_edges_after = CASE WHEN $22 THEN graph_total_edges_after ELSE $16 END,
	    comparable_to_scan_id = CASE WHEN $22 THEN comparable_to_scan_id ELSE NULLIF($17, '') END,
	    published_revision = CASE
	        WHEN $11 THEN $18
	        WHEN publication_status = 'published' THEN published_revision
	        ELSE NULL
	    END,
	    published_at = CASE
	        WHEN $11 THEN $19
	        WHEN publication_status = 'published' THEN published_at
	        ELSE NULL
	    END,
	    metadata = $20,
	    lifecycle_updated_at = NOW()
	WHERE id = $21`,
		params.Scan.Status,
		params.Scan.CompletedAt,
		params.Scan.NodeCount,
		params.Scan.EdgeCount,
		params.Scan.Error,
		lifecycleOrUnknown(params.Scan.CollectionStatus),
		lifecycleOrUnknown(params.Scan.GraphStatus),
		lifecycleOrUnknown(params.Scan.AnalysisStatus),
		lifecycleOrUnknown(params.Scan.SnapshotStatus),
		projectionOrUnknown(params.Scan.ProjectionStatus),
		params.Publish,
		params.Scan.ComparisonKey,
		beforeNodes,
		beforeEdges,
		afterNodes,
		afterEdges,
		result.ComparableToScanID,
		result.Revision,
		result.PublishedAt,
		nonNilMetadata(params.Scan.Metadata),
		params.Scan.ID,
		preservePublishedSnapshot,
	)
	if err != nil {
		return fmt.Errorf("finalize scan row: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("finalize scan row: %w", pgx.ErrNoRows)
	}
	return nil
}

func finalizeProjectionState(
	ctx context.Context,
	tx pgx.Tx,
	params FinalizeScanParams,
	result *PublicationResult,
) error {
	dirtyJSON, err := json.Marshal(params.DirtyCoverage)
	if err != nil {
		return fmt.Errorf("marshal final dirty coverage: %w", err)
	}
	if params.Publish {
		revision := *result.Revision
		publishedAt := *result.PublishedAt
		_, err = tx.Exec(ctx, `UPDATE posture_state SET
		    projection_status = $1,
		    projection_scan_id = $2,
		    projection_error = NULL,
		    dirty_coverage = '[]'::jsonb,
		    projection_updated_at = NOW(),
		    published_revision = $3,
		    published_scan_id = $2,
		    published_at = $4
		WHERE singleton = TRUE`,
			model.ProjectionComplete,
			params.Scan.ID,
			revision,
			publishedAt,
		)
	} else {
		_, err = tx.Exec(ctx, `UPDATE posture_state SET
		    projection_status = $1,
		    projection_scan_id = $2,
		    projection_error = NULLIF($3, ''),
		    dirty_coverage = $4::jsonb,
		    projection_updated_at = NOW()
		WHERE singleton = TRUE`,
			model.ProjectionIncomplete,
			params.Scan.ID,
			params.Scan.Error,
			string(dirtyJSON),
		)
	}
	if err != nil {
		return fmt.Errorf("finalize projection state: %w", err)
	}
	return nil
}

func activeCoverageHeadsTx(ctx context.Context, tx pgx.Tx) ([]coverageHead, error) {
	rows, err := tx.Query(ctx, `SELECT coverage_key, scan_id
		FROM coverage_heads
		ORDER BY coverage_key`)
	if err != nil {
		return nil, fmt.Errorf("read active coverage keys: %w", err)
	}
	defer rows.Close()
	var heads []coverageHead
	for rows.Next() {
		var head coverageHead
		if err := rows.Scan(&head.Key, &head.ScanID); err != nil {
			return nil, fmt.Errorf("scan active coverage head: %w", err)
		}
		heads = append(heads, head)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read active coverage keys: %w", err)
	}
	return heads, nil
}

func findingsForScanTx(ctx context.Context, tx pgx.Tx, scanID string) ([]model.Finding, error) {
	rows, err := tx.Query(ctx, `
SELECT `+findingSelectColumns+`
FROM findings f
LEFT JOIN finding_triage t ON t.fingerprint = f.fingerprint
WHERE f.scan_id = $1
ORDER BY f.confidence DESC, f.fingerprint`, scanID)
	if err != nil {
		return nil, fmt.Errorf("read finalized findings: %w", err)
	}
	defer rows.Close()
	findings, err := scanFindings(rows)
	if err != nil {
		return nil, err
	}
	if findings == nil {
		findings = []model.Finding{}
	}
	return findings, nil
}

func priorComparablePublication(
	ctx context.Context,
	tx pgx.Tx,
	scanID, comparisonKey string,
	current *model.GraphSnapshot,
) (model.PostureComparison, error) {
	comparison := model.PostureComparison{}
	if comparisonKey == "" || current == nil {
		return comparison, nil
	}
	var (
		previousScanID string
		graphJSON      []byte
	)
	err := tx.QueryRow(ctx, `SELECT scan_id, graph_stats
	FROM posture_publications
	WHERE comparison_key = $1 AND scan_id <> $2
	ORDER BY revision DESC
	LIMIT 1`,
		comparisonKey, scanID,
	).Scan(&previousScanID, &graphJSON)
	if errors.Is(err, pgx.ErrNoRows) {
		return comparison, nil
	}
	if err != nil {
		return comparison, fmt.Errorf("find comparable publication: %w", err)
	}
	var previous model.GraphSnapshot
	if err := json.Unmarshal(graphJSON, &previous); err != nil {
		return comparison, fmt.Errorf("decode comparable graph totals: %w", err)
	}
	nodeDelta := current.TotalNodes - previous.TotalNodes
	edgeDelta := current.TotalEdges - previous.TotalEdges
	comparison.Comparable = true
	comparison.PreviousScanID = previousScanID
	comparison.Previous = &previous
	comparison.NodeDelta = &nodeDelta
	comparison.EdgeDelta = &edgeDelta
	return comparison, nil
}

func buildPostureExport(
	params FinalizeScanParams,
	revision int64,
	publishedAt time.Time,
	findings []model.Finding,
	comparison model.PostureComparison,
	activeCoverageKeys []string,
) model.PostureExport {
	completedAt := publishedAt
	if params.Scan.CompletedAt != nil {
		completedAt = *params.Scan.CompletedAt
	}
	graphAfter := model.GraphSnapshot{
		NodeCounts: map[string]int64{},
		EdgeCounts: map[string]int64{},
	}
	if params.GraphAfter != nil {
		graphAfter = *params.GraphAfter
	}
	stages := params.Stages
	if stages == nil {
		stages = []sdkingest.StageResult{}
	}
	if findings == nil {
		findings = []model.Finding{}
	}
	normalizationWarnings := append(
		[]sdkingest.NormalizationWarning(nil),
		params.NormalizationWarnings...,
	)
	if normalizationWarnings == nil {
		normalizationWarnings = []sdkingest.NormalizationWarning{}
	}
	normalizationStatus := params.NormalizationStatus
	if normalizationStatus == "" {
		normalizationStatus = sdkingest.NormalizationStatusUnknown
	}
	observationStatus := params.ObservationStatus
	if observationStatus == "" {
		observationStatus = model.LifecycleUnknown
	}
	rulesStatus := model.LifecycleUnknown
	if params.Ruleset != nil && params.Ruleset.LoadState != "" {
		rulesStatus = string(params.Ruleset.LoadState)
	}
	identityStatus := model.LifecycleUnknown
	if len(params.IdentitySchemes) > 0 {
		identityStatus = model.LifecycleComplete
	}
	return model.PostureExport{
		SchemaVersion: 2,
		Scope: model.PostureScope{
			ScanID:             params.Scan.ID,
			Revision:           revision,
			CoverageKeys:       normalizeCoverageKeys(params.CoverageKeys),
			ActiveCoverageKeys: normalizeCoverageKeys(activeCoverageKeys),
			DirtyCoverage:      []string{},
			ComparisonKey:      params.Scan.ComparisonKey,
			ProjectionState:    model.ProjectionComplete,
		},
		Completeness: model.PostureCompleteness{
			Collection:         params.Scan.CollectionStatus,
			Normalization:      normalizationStatus,
			Observation:        observationStatus,
			ObservationDetails: params.ObservationDetails,
			Rules:              rulesStatus,
			Identity:           identityStatus,
			Graph:              params.Scan.GraphStatus,
			Analysis:           params.Scan.AnalysisStatus,
			Snapshot:           params.Scan.SnapshotStatus,
			Projection:         model.ProjectionComplete,
			Publication:        model.LifecycleComplete,
			Warnings:           normalizationWarnings,
			Stages:             stages,
		},
		Observations: model.PostureObservationTimes{
			ArtifactObservedAt:  params.Scan.ArtifactObservedAt,
			IngestStartedAt:     params.Scan.StartedAt,
			AnalysisCompletedAt: completedAt,
			PublishedAt:         publishedAt,
		},
		Health: model.PostureHealthObservation{
			State:    "not_captured",
			Captured: false,
		},
		Limits: model.PostureExportLimits{
			Findings: model.PostureExportCardinality{
				Returned: len(findings),
				Total:    len(findings),
				Complete: true,
			},
		},
		Suppression: model.PostureSuppression{
			Policy:             "include_all_with_published_triage",
			SuppressedStatuses: append([]string(nil), suppressedStatuses...),
			TriageObservedAt:   publishedAt,
		},
		GraphBefore:     params.GraphBefore,
		GraphAfter:      graphAfter,
		Comparison:      comparison,
		Collection:      params.Collection,
		Ruleset:         params.Ruleset,
		IdentitySchemes: append([]sdkingest.IdentityScheme(nil), params.IdentitySchemes...),
		Findings:        findings,
	}
}

func (s *FindingStore) GetPublishedExport(ctx context.Context) (*model.PostureExport, error) {
	var data []byte
	err := s.pool.QueryRow(ctx, `SELECT pp.export
	FROM posture_state ps
	JOIN posture_publications pp ON pp.revision = ps.published_revision
	WHERE ps.singleton = TRUE`).Scan(&data)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get published export: %w", err)
	}
	var export model.PostureExport
	if err := json.Unmarshal(data, &export); err != nil {
		return nil, fmt.Errorf("decode published export: %w", err)
	}
	if export.Findings == nil {
		export.Findings = []model.Finding{}
	}
	if export.Scope.CoverageKeys == nil {
		export.Scope.CoverageKeys = []string{}
	}
	if export.Scope.ActiveCoverageKeys == nil {
		export.Scope.ActiveCoverageKeys = append(
			[]string{},
			export.Scope.CoverageKeys...,
		)
	}
	if export.Scope.DirtyCoverage == nil {
		export.Scope.DirtyCoverage = []string{}
	}
	if export.Completeness.Normalization == "" {
		export.Completeness.Normalization = sdkingest.NormalizationStatusUnknown
	}
	if export.Completeness.Observation == "" {
		export.Completeness.Observation = model.LifecycleUnknown
	}
	if export.Completeness.Warnings == nil {
		export.Completeness.Warnings = []sdkingest.NormalizationWarning{}
	}
	if export.Completeness.Stages == nil {
		export.Completeness.Stages = []sdkingest.StageResult{}
	}
	if export.Health.State == "" {
		export.Health.State = "not_captured"
		export.Health.Captured = false
	}
	for i := range export.Findings {
		if export.Findings[i].Variant == "" {
			export.Findings[i].Variant = model.FindingVariantUnknown
		}
		if export.Findings[i].Evidence.State == "" {
			export.Findings[i].Evidence.State = model.FindingEvidenceUnknown
		}
	}
	return &export, nil
}

func (s *FindingStore) GetProjectionState(ctx context.Context) (*model.ProjectionState, error) {
	var (
		state         model.ProjectionState
		dirtyJSON     []byte
		scanID        *string
		projectionErr *string
		publishedID   *string
	)
	err := s.pool.QueryRow(ctx, `SELECT
	    projection_status, projection_scan_id, projection_error,
	    dirty_coverage, projection_updated_at,
	    published_scan_id, published_revision, published_at
	FROM posture_state WHERE singleton = TRUE`).Scan(
		&state.Status,
		&scanID,
		&projectionErr,
		&dirtyJSON,
		&state.UpdatedAt,
		&publishedID,
		&state.PublishedRevision,
		&state.PublishedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("get projection state: %w", err)
	}
	if scanID != nil {
		state.ScanID = *scanID
	}
	if projectionErr != nil {
		state.Error = *projectionErr
	}
	if publishedID != nil {
		state.PublishedScanID = *publishedID
	}
	if err := json.Unmarshal(dirtyJSON, &state.DirtyCoverage); err != nil {
		return nil, fmt.Errorf("decode dirty coverage: %w", err)
	}
	if state.DirtyCoverage == nil {
		state.DirtyCoverage = []string{}
	}
	return &state, nil
}
