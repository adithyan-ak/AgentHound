package appdb

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	sdkingest "github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/server/model"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type ScanStore struct {
	pool *pgxpool.Pool
}

const scanSelectColumns = `id, collector, status, started_at, completed_at,
	node_write_rows, edge_write_rows, error, artifact_observed_at,
	collection_status, graph_status, analysis_status, snapshot_status,
	projection_status, publication_status, coalesce(comparison_key, ''),
	graph_total_nodes_before, graph_total_edges_before,
	graph_total_nodes_after, graph_total_edges_after,
	coalesce(comparable_to_scan_id, ''), published_revision, published_at,
	lifecycle_updated_at, coalesce(metadata, '{}'::jsonb)`

type ScanFailure struct {
	ID               string
	Status           string
	NodeWriteRows    int
	EdgeWriteRows    int
	Error            string
	CollectionStatus string
	GraphStatus      string
	AnalysisStatus   string
	SnapshotStatus   string
	ProjectionStatus string
	DirtyCoverage    []string
	Metadata         map[string]any
}

// CampaignRejectionAudit is the complete sanitized payload persisted for a
// campaign artifact rejected before BeginScan. It intentionally has no raw
// artifact, artifact digest, endpoint, witness, credential material, or
// free-form error.
type CampaignRejectionAudit struct {
	RejectionID     string
	RunID           string
	ScenarioID      string
	ScenarioVersion int
	Outcome         string
	ReasonCodes     []string
}

type ScanDeleteConflictError struct {
	Reason string
}

func (e *ScanDeleteConflictError) Error() string {
	return "scan cannot be deleted: " + e.Reason
}

type ScanPageInfo struct {
	Offset   int
	Limit    int
	Total    int64
	HasMore  bool
	Complete bool
	Revision string
}

type ScanRevisionMismatchError struct {
	Expected string
	Actual   string
}

func (e *ScanRevisionMismatchError) Error() string {
	return fmt.Sprintf("scan revision changed: expected %q, got %q", e.Expected, e.Actual)
}

type ScanListOrder string

const (
	ScanListOrderStarted   ScanListOrder = "started"
	ScanListOrderCompleted ScanListOrder = "completed"
	ScanListOrderPublished ScanListOrder = "published"
)

func scanListOrderClause(order ScanListOrder) string {
	switch order {
	case ScanListOrderCompleted:
		return "CASE WHEN status IN ('completed', 'completed_with_errors') THEN 0 ELSE 1 END, completed_at DESC NULLS LAST, started_at DESC, id DESC"
	case ScanListOrderPublished:
		return "CASE WHEN publication_status = 'published' THEN 0 ELSE 1 END, published_at DESC NULLS LAST, started_at DESC, id DESC"
	default:
		return "started_at DESC, id DESC"
	}
}

func NewScanStore(pool *pgxpool.Pool) *ScanStore {
	return &ScanStore{pool: pool}
}

func (s *ScanStore) CreateScan(ctx context.Context, scan *model.Scan) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO scans (
		    id, collector, status, started_at, artifact_observed_at, metadata,
		    collection_status, graph_status, analysis_status, snapshot_status,
		    projection_status, publication_status, lifecycle_updated_at
		 )
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,NOW())`,
		scan.ID,
		scan.Collector,
		scan.Status,
		scan.StartedAt,
		scan.ArtifactObservedAt,
		nonNilMetadata(scan.Metadata),
		lifecycleOrUnknown(scan.CollectionStatus),
		lifecycleOrUnknown(scan.GraphStatus),
		lifecycleOrUnknown(scan.AnalysisStatus),
		lifecycleOrUnknown(scan.SnapshotStatus),
		projectionOrUnknown(scan.ProjectionStatus),
		publicationOrUnpublished(scan.PublicationStatus),
	)
	if err != nil {
		return fmt.Errorf("create scan: %w", err)
	}
	return nil
}

// BeginScan records a new attempt and marks the mutable projection as
// updating in one PostgreSQL transaction. A same-ID retry keeps the previous
// finding rows and published revision visible until finalization atomically
// replaces them.
func (s *ScanStore) BeginScan(
	ctx context.Context,
	scan *model.Scan,
	dirtyCoverage []string,
) ([]string, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin scan lifecycle: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	_, err = tx.Exec(ctx, `INSERT INTO scans (
	    id, collector, status, started_at, completed_at, node_write_rows, edge_write_rows,
	    error, artifact_observed_at, metadata, collection_status, graph_status,
	    analysis_status, snapshot_status, projection_status, publication_status,
	    comparison_key, graph_total_nodes_before, graph_total_edges_before,
	    graph_total_nodes_after, graph_total_edges_after, comparable_to_scan_id,
	    lifecycle_updated_at
	) VALUES (
	    $1,$2,$3,$4,NULL,0,0,NULL,$5,$6,$7,$8,$9,$10,$11,$12,NULL,NULL,NULL,NULL,NULL,NULL,NOW()
	)
	ON CONFLICT (id) DO UPDATE SET
	    collector = EXCLUDED.collector,
	    status = EXCLUDED.status,
	    started_at = EXCLUDED.started_at,
	    completed_at = NULL,
	    node_write_rows = 0,
	    edge_write_rows = 0,
	    error = NULL,
	    artifact_observed_at = EXCLUDED.artifact_observed_at,
	    metadata = EXCLUDED.metadata,
	    collection_status = EXCLUDED.collection_status,
	    graph_status = EXCLUDED.graph_status,
	    analysis_status = EXCLUDED.analysis_status,
	    snapshot_status = EXCLUDED.snapshot_status,
	    projection_status = EXCLUDED.projection_status,
	    publication_status = CASE
	        WHEN scans.publication_status = 'published' THEN scans.publication_status
	        ELSE EXCLUDED.publication_status
	    END,
	    published_revision = CASE
	        WHEN scans.publication_status = 'published' THEN scans.published_revision
	        ELSE NULL
	    END,
	    published_at = CASE
	        WHEN scans.publication_status = 'published' THEN scans.published_at
	        ELSE NULL
	    END,
	    comparison_key = CASE
	        WHEN scans.publication_status = 'published' THEN scans.comparison_key
	        ELSE NULL
	    END,
	    graph_total_nodes_before = CASE
	        WHEN scans.publication_status = 'published' THEN scans.graph_total_nodes_before
	        ELSE NULL
	    END,
	    graph_total_edges_before = CASE
	        WHEN scans.publication_status = 'published' THEN scans.graph_total_edges_before
	        ELSE NULL
	    END,
	    graph_total_nodes_after = CASE
	        WHEN scans.publication_status = 'published' THEN scans.graph_total_nodes_after
	        ELSE NULL
	    END,
	    graph_total_edges_after = CASE
	        WHEN scans.publication_status = 'published' THEN scans.graph_total_edges_after
	        ELSE NULL
	    END,
	    comparable_to_scan_id = CASE
	        WHEN scans.publication_status = 'published' THEN scans.comparable_to_scan_id
	        ELSE NULL
	    END,
	    lifecycle_updated_at = NOW()`,
		scan.ID,
		scan.Collector,
		model.ScanStatusRunning,
		scan.StartedAt,
		scan.ArtifactObservedAt,
		nonNilMetadata(scan.Metadata),
		lifecycleOrUnknown(scan.CollectionStatus),
		model.LifecyclePending,
		model.LifecyclePending,
		model.LifecyclePending,
		model.ProjectionUpdating,
		model.PublicationUnpublished,
	)
	if err != nil {
		return nil, fmt.Errorf("begin scan row: %w", err)
	}

	var inheritedJSON []byte
	if err := tx.QueryRow(ctx, `SELECT dirty_coverage
		FROM posture_state WHERE singleton = TRUE
		FOR UPDATE`).Scan(&inheritedJSON); err != nil {
		return nil, fmt.Errorf("lock projection state: %w", err)
	}
	var inherited []string
	if err := json.Unmarshal(inheritedJSON, &inherited); err != nil {
		return nil, fmt.Errorf("decode inherited dirty coverage: %w", err)
	}
	cumulativeDirty := normalizeCoverageKeys(inherited, dirtyCoverage)
	dirtyJSON, err := json.Marshal(cumulativeDirty)
	if err != nil {
		return nil, fmt.Errorf("marshal dirty coverage: %w", err)
	}
	_, err = tx.Exec(ctx, `UPDATE posture_state
	SET projection_status = $1,
	    projection_scan_id = $2,
	    projection_error = NULL,
	    dirty_coverage = $3::jsonb,
	    projection_updated_at = NOW()
	WHERE singleton = TRUE`,
		model.ProjectionUpdating, scan.ID, string(dirtyJSON))
	if err != nil {
		return nil, fmt.Errorf("begin projection state: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit scan lifecycle: %w", err)
	}
	return cumulativeDirty, nil
}

// RecordCampaignRejection writes an audit-only failed scan row without touching
// posture_state, coverage_heads, findings, or the projection lifecycle. The
// random rejection ID is also the row ID, so an attacker-controlled submitted
// scan ID cannot overwrite prior scan history.
func (s *ScanStore) RecordCampaignRejection(
	ctx context.Context,
	audit CampaignRejectionAudit,
) error {
	now := time.Now().UTC()
	metadata := map[string]any{
		"campaign_rejection": map[string]any{
			"rejection_id":     audit.RejectionID,
			"run_id":           audit.RunID,
			"scenario_id":      audit.ScenarioID,
			"scenario_version": audit.ScenarioVersion,
			"outcome":          audit.Outcome,
			"reason_codes":     append([]string(nil), audit.ReasonCodes...),
		},
	}
	tag, err := s.pool.Exec(ctx, `INSERT INTO scans (
	    id, collector, status, started_at, completed_at, error, metadata,
	    collection_status, graph_status, analysis_status, snapshot_status,
	    projection_status, publication_status, lifecycle_updated_at
	) VALUES (
	    $1, 'scan', $2, $3, $3, $4, $5, $6, $7, $7, $7, $8, $9, $3
	)
	ON CONFLICT (id) DO NOTHING`,
		audit.RejectionID,
		model.ScanStatusFailed,
		now,
		"campaign artifact rejected",
		metadata,
		model.LifecycleFailed,
		model.LifecycleNotApplicable,
		model.ProjectionUnknown,
		model.PublicationUnpublished,
	)
	if err != nil {
		return fmt.Errorf("record campaign rejection: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("record campaign rejection: rejection id collision")
	}
	return nil
}

// ResolveRetiredCoverage returns prior child heads and inherited dirty child
// keys that are absent from a completed exhaustive collector-root active set.
// It is read before graph mutation so the pipeline can reconcile those scopes
// as complete-empty.
func (s *ScanStore) ResolveRetiredCoverage(
	ctx context.Context,
	roots []sdkingest.CoverageRoot,
) ([]string, error) {
	if len(roots) == 0 {
		return nil, nil
	}
	rootKeys := make([]string, 0, len(roots))
	for _, root := range roots {
		if root.CoverageKey == "" {
			continue
		}
		rootKeys = append(rootKeys, root.CoverageKey)
	}
	rootKeys = normalizeCoverageKeys(rootKeys)
	if len(rootKeys) == 0 {
		return nil, nil
	}

	rows, err := s.pool.Query(ctx, `SELECT coverage_key, root_key
		FROM coverage_heads
		WHERE root_key = ANY($1::text[])
		ORDER BY root_key, coverage_key`,
		rootKeys,
	)
	if err != nil {
		return nil, fmt.Errorf("read authoritative coverage children: %w", err)
	}
	defer rows.Close()

	var heads []coverageHead
	for rows.Next() {
		var head coverageHead
		if err := rows.Scan(&head.Key, &head.Root); err != nil {
			return nil, fmt.Errorf("scan authoritative coverage child: %w", err)
		}
		heads = append(heads, head)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read authoritative coverage children: %w", err)
	}

	var inheritedJSON []byte
	if err := s.pool.QueryRow(ctx, `SELECT dirty_coverage
		FROM posture_state WHERE singleton = TRUE`).Scan(&inheritedJSON); err != nil {
		return nil, fmt.Errorf("read inherited dirty coverage: %w", err)
	}
	var inheritedDirty []string
	if err := json.Unmarshal(inheritedJSON, &inheritedDirty); err != nil {
		return nil, fmt.Errorf("decode inherited dirty coverage: %w", err)
	}
	return retiredCoverageKeys(roots, heads, inheritedDirty), nil
}

func (s *ScanStore) RecordFailure(ctx context.Context, failure ScanFailure) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin failure lifecycle: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	now := time.Now().UTC()
	tag, err := tx.Exec(ctx, `UPDATE scans SET
	    status = $1,
	    completed_at = $2,
	    node_write_rows = $3,
	    edge_write_rows = $4,
	    error = $5,
	    collection_status = $6,
	    graph_status = $7,
	    analysis_status = $8,
	    snapshot_status = $9,
	    projection_status = $10,
	    metadata = $11,
	    lifecycle_updated_at = NOW()
	WHERE id = $12`,
		failure.Status,
		now,
		failure.NodeWriteRows,
		failure.EdgeWriteRows,
		failure.Error,
		lifecycleOrUnknown(failure.CollectionStatus),
		lifecycleOrUnknown(failure.GraphStatus),
		lifecycleOrUnknown(failure.AnalysisStatus),
		lifecycleOrUnknown(failure.SnapshotStatus),
		projectionOrUnknown(failure.ProjectionStatus),
		nonNilMetadata(failure.Metadata),
		failure.ID,
	)
	if err != nil {
		return fmt.Errorf("record scan failure: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("record scan failure: %w", pgx.ErrNoRows)
	}

	var inheritedJSON []byte
	if err := tx.QueryRow(ctx, `SELECT dirty_coverage
		FROM posture_state WHERE singleton = TRUE
		FOR UPDATE`).Scan(&inheritedJSON); err != nil {
		return fmt.Errorf("lock failed projection state: %w", err)
	}
	var inherited []string
	if err := json.Unmarshal(inheritedJSON, &inherited); err != nil {
		return fmt.Errorf("decode failed projection dirty coverage: %w", err)
	}
	dirtyJSON, err := json.Marshal(normalizeCoverageKeys(inherited, failure.DirtyCoverage))
	if err != nil {
		return fmt.Errorf("marshal dirty coverage: %w", err)
	}
	_, err = tx.Exec(ctx, `UPDATE posture_state SET
	    projection_status = $1,
	    projection_scan_id = $2,
	    projection_error = $3,
	    dirty_coverage = $4::jsonb,
	    projection_updated_at = NOW()
	WHERE singleton = TRUE`,
		model.ProjectionIncomplete,
		failure.ID,
		failure.Error,
		string(dirtyJSON),
	)
	if err != nil {
		return fmt.Errorf("record projection failure: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit failure lifecycle: %w", err)
	}
	return nil
}

func (s *ScanStore) GetScan(ctx context.Context, id string) (*model.Scan, error) {
	scan, err := scanScan(s.pool.QueryRow(ctx,
		`SELECT `+scanSelectColumns+` FROM scans WHERE id = $1`, id))
	if err != nil {
		return nil, fmt.Errorf("get scan: %w", err)
	}
	return scan, nil
}

func (s *ScanStore) ListScans(ctx context.Context, limit, offset int) ([]model.Scan, error) {
	scans, _, err := s.ListScansPage(ctx, limit, offset, "", ScanListOrderStarted)
	return scans, err
}

func (s *ScanStore) ListScansPage(
	ctx context.Context,
	limit, offset int,
	expectedRevision string,
	order ScanListOrder,
) ([]model.Scan, ScanPageInfo, error) {
	if limit <= 0 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	if order == "" {
		order = ScanListOrderStarted
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{
		IsoLevel:   pgx.RepeatableRead,
		AccessMode: pgx.ReadOnly,
	})
	if err != nil {
		return nil, ScanPageInfo{}, fmt.Errorf("list scans transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var total int64
	var latestStarted, latestCompleted, latestLifecycle, latestID string
	if err := tx.QueryRow(ctx, `SELECT count(*),
		coalesce(max(started_at)::text, ''),
		coalesce(max(completed_at)::text, ''),
		coalesce(max(lifecycle_updated_at)::text, ''),
		coalesce(max(id), '')
		FROM scans`).Scan(&total, &latestStarted, &latestCompleted, &latestLifecycle, &latestID); err != nil {
		return nil, ScanPageInfo{}, fmt.Errorf("scan page metadata: %w", err)
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf(
		"%d\x00%s\x00%s\x00%s\x00%s\x00%s",
		total, latestStarted, latestCompleted, latestLifecycle, latestID, order,
	)))
	revision := fmt.Sprintf("%x", sum[:])
	if expectedRevision != "" && expectedRevision != revision {
		return nil, ScanPageInfo{}, &ScanRevisionMismatchError{
			Expected: expectedRevision,
			Actual:   revision,
		}
	}

	rows, err := tx.Query(ctx,
		`SELECT `+scanSelectColumns+`
		 FROM scans ORDER BY `+scanListOrderClause(order)+` LIMIT $1 OFFSET $2`, limit+1, offset)
	if err != nil {
		return nil, ScanPageInfo{}, fmt.Errorf("list scans: %w", err)
	}
	defer rows.Close()

	scans := make([]model.Scan, 0, limit+1)
	for rows.Next() {
		scan, err := scanScan(rows)
		if err != nil {
			return nil, ScanPageInfo{}, fmt.Errorf("scan row: %w", err)
		}
		scans = append(scans, *scan)
	}
	if err := rows.Err(); err != nil {
		return nil, ScanPageInfo{}, err
	}
	hasMore := len(scans) > limit
	if hasMore {
		scans = scans[:limit]
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, ScanPageInfo{}, fmt.Errorf("commit scan page: %w", err)
	}
	return scans, ScanPageInfo{
		Offset:   offset,
		Limit:    limit,
		Total:    total,
		HasMore:  hasMore,
		Complete: !hasMore,
		Revision: revision,
	}, nil
}

func (s *ScanStore) DeleteScan(ctx context.Context, id string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin delete scan: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var status string
	if err := tx.QueryRow(ctx,
		`SELECT status FROM scans WHERE id = $1 FOR UPDATE`, id,
	).Scan(&status); err != nil {
		return fmt.Errorf("delete scan: %w", err)
	}
	if status == model.ScanStatusPending || status == model.ScanStatusRunning {
		return &ScanDeleteConflictError{Reason: "pending or running scans are active"}
	}

	var activeCoverage bool
	if err := tx.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM coverage_heads WHERE scan_id = $1)`, id,
	).Scan(&activeCoverage); err != nil {
		return fmt.Errorf("check scan coverage heads: %w", err)
	}
	if activeCoverage {
		return &ScanDeleteConflictError{Reason: "scan owns an active coverage head"}
	}

	var currentlyPublished bool
	if err := tx.QueryRow(ctx,
		`SELECT EXISTS (
		    SELECT 1 FROM posture_state
		    WHERE singleton = TRUE AND published_scan_id = $1
		)`, id,
	).Scan(&currentlyPublished); err != nil {
		return fmt.Errorf("check published scan: %w", err)
	}
	if currentlyPublished {
		return &ScanDeleteConflictError{Reason: "scan is the currently published posture"}
	}

	if _, err := tx.Exec(ctx, `UPDATE posture_state SET
	    projection_scan_id = NULL,
	    projection_updated_at = NOW()
	WHERE singleton = TRUE
	  AND projection_scan_id = $1
	  AND published_scan_id IS DISTINCT FROM $1`, id); err != nil {
		return fmt.Errorf("detach deleted scan from projection history: %w", err)
	}

	tag, err := tx.Exec(ctx, `DELETE FROM scans WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete scan history: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("delete scan: %w", pgx.ErrNoRows)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit delete scan: %w", err)
	}
	return nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanScan(row rowScanner) (*model.Scan, error) {
	scan := &model.Scan{}
	var scanErr *string
	err := row.Scan(
		&scan.ID,
		&scan.Collector,
		&scan.Status,
		&scan.StartedAt,
		&scan.CompletedAt,
		&scan.NodeWriteRows,
		&scan.EdgeWriteRows,
		&scanErr,
		&scan.ArtifactObservedAt,
		&scan.CollectionStatus,
		&scan.GraphStatus,
		&scan.AnalysisStatus,
		&scan.SnapshotStatus,
		&scan.ProjectionStatus,
		&scan.PublicationStatus,
		&scan.ComparisonKey,
		&scan.GraphTotalNodesBefore,
		&scan.GraphTotalEdgesBefore,
		&scan.GraphTotalNodesAfter,
		&scan.GraphTotalEdgesAfter,
		&scan.ComparableToScanID,
		&scan.PublishedRevision,
		&scan.PublishedAt,
		&scan.LifecycleUpdatedAt,
		&scan.Metadata,
	)
	if err != nil {
		return nil, err
	}
	if scanErr != nil {
		scan.Error = *scanErr
	}
	if scan.Metadata == nil {
		scan.Metadata = map[string]any{}
	}
	return scan, nil
}

func nonNilMetadata(metadata map[string]any) map[string]any {
	if metadata == nil {
		return map[string]any{}
	}
	return metadata
}

func lifecycleOrUnknown(value string) string {
	if value == "" {
		return model.LifecycleUnknown
	}
	return value
}

func projectionOrUnknown(value string) string {
	if value == "" {
		return model.ProjectionUnknown
	}
	return value
}

func publicationOrUnpublished(value string) string {
	if value == "" {
		return model.PublicationUnpublished
	}
	return value
}
