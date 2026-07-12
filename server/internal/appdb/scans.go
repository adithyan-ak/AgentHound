package appdb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/server/model"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type ScanStore struct {
	pool *pgxpool.Pool
}

func NewScanStore(pool *pgxpool.Pool) *ScanStore {
	return &ScanStore{pool: pool}
}

// scanSelectColumns is the shared projection for GetScan / ListScans /
// scope lookups. Order MUST match scanScanRow's Scan() argument order.
const scanSelectColumns = `id, collector, status, started_at, completed_at, node_count, edge_count, error, metadata,
	generation_id, is_current, schema_version, identity_version, coverage_status, coverage, stage_states,
	nodes_created, nodes_updated, nodes_unchanged, nodes_retired, nodes_before, nodes_after,
	edges_created, edges_updated, edges_unchanged, edges_retired, edges_before, edges_after,
	captured_at, scope, delete_state`

func (s *ScanStore) CreateScan(ctx context.Context, scan *model.Scan) error {
	coverageJSON, err := marshalCoverage(scan.Coverage)
	if err != nil {
		return fmt.Errorf("create scan: marshal coverage: %w", err)
	}
	coverageStatus := scan.CoverageStatus
	if !coverageStatus.Valid() {
		coverageStatus = ingest.StatusUnknown
	}
	schemaVersion := scan.SchemaVersion
	if schemaVersion == 0 {
		schemaVersion = ingest.CurrentSchemaVersion
	}
	identityVersion := scan.IdentityVersion
	if identityVersion == 0 {
		identityVersion = ingest.CurrentIdentityVersion
	}
	_, err = s.pool.Exec(ctx,
		`INSERT INTO scans
		   (id, collector, status, started_at, metadata,
		    generation_id, schema_version, identity_version, coverage_status, coverage, captured_at, scope)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		scan.ID, scan.Collector, scan.Status, scan.StartedAt, scan.Metadata,
		scan.GenerationID, schemaVersion, identityVersion, string(coverageStatus), coverageJSON, scan.CapturedAt,
		scopeOrCollector(scan))
	if err != nil {
		return fmt.Errorf("create scan: %w", err)
	}
	return nil
}

// UpdateScan records the terminal status plus the committed node/edge counts.
// It is intentionally narrow (status + counts + error) so the historical
// ingest-completion path stays stable; the full generation outcome (coverage,
// stage states, inventory deltas) is written by RecordGenerationOutcome.
func (s *ScanStore) UpdateScan(ctx context.Context, id, status string, nodeCount, edgeCount int, scanErr string) error {
	now := time.Now().UTC()
	_, err := s.pool.Exec(ctx,
		`UPDATE scans SET status = $1, completed_at = $2, node_count = $3, edge_count = $4, error = $5
		 WHERE id = $6`,
		status, now, nodeCount, edgeCount, scanErr, id)
	if err != nil {
		return fmt.Errorf("update scan: %w", err)
	}
	return nil
}

// RecordGenerationOutcome persists the generation-scoped truth columns for a
// scan: coverage roll-up + manifest, independent per-stage states, and the
// accurate node/edge inventory deltas. It deliberately does NOT flip
// is_current — promotion is a separate, gated step (PromoteGeneration) so a
// partial/failed generation can record honest metrics without becoming the
// default read target.
func (s *ScanStore) RecordGenerationOutcome(ctx context.Context, scan *model.Scan) error {
	coverageJSON, err := marshalCoverage(scan.Coverage)
	if err != nil {
		return fmt.Errorf("record generation outcome: marshal coverage: %w", err)
	}
	stageJSON, err := marshalStageStates(scan.StageStates)
	if err != nil {
		return fmt.Errorf("record generation outcome: marshal stage states: %w", err)
	}
	coverageStatus := scan.CoverageStatus
	if !coverageStatus.Valid() {
		coverageStatus = ingest.StatusUnknown
	}
	nodeInv := scan.NodeInventory
	if nodeInv == nil {
		nodeInv = &ingest.InventoryDelta{}
	}
	edgeInv := scan.EdgeInventory
	if edgeInv == nil {
		edgeInv = &ingest.InventoryDelta{}
	}
	_, err = s.pool.Exec(ctx,
		`UPDATE scans SET
		    generation_id = $1,
		    coverage_status = $2,
		    coverage = $3,
		    stage_states = $4,
		    nodes_created = $5, nodes_updated = $6, nodes_unchanged = $7,
		    nodes_retired = $8, nodes_before = $9, nodes_after = $10,
		    edges_created = $11, edges_updated = $12, edges_unchanged = $13,
		    edges_retired = $14, edges_before = $15, edges_after = $16,
		    captured_at = COALESCE($17, captured_at),
		    scope = COALESCE(NULLIF($19, ''), scope)
		 WHERE id = $18`,
		scan.GenerationID, string(coverageStatus), coverageJSON, stageJSON,
		nodeInv.Created, nodeInv.Updated, nodeInv.Unchanged, nodeInv.Retired, nodeInv.BeforeTotal, nodeInv.AfterTotal,
		edgeInv.Created, edgeInv.Updated, edgeInv.Unchanged, edgeInv.Retired, edgeInv.BeforeTotal, edgeInv.AfterTotal,
		scan.CapturedAt, scan.ID, scan.Scope)
	if err != nil {
		return fmt.Errorf("record generation outcome: %w", err)
	}
	return nil
}

// PromoteGeneration marks scanID as the current (default-read) generation for
// its scope, demoting any prior current scan of the SAME scope in a single
// transaction. Called only after the required ingest stages succeeded and the
// coverage-aware promotion gate allowed it. Scope keying (not collector) keeps
// a network sweep from demoting a local bundle that shares collector "scan".
func (s *ScanStore) PromoteGeneration(ctx context.Context, scanID, scope string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("promote generation: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx,
		`UPDATE scans SET is_current = FALSE WHERE scope = $1 AND is_current = TRUE AND id <> $2`,
		scope, scanID); err != nil {
		return fmt.Errorf("promote generation: demote prior: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`UPDATE scans SET is_current = TRUE WHERE id = $1`, scanID); err != nil {
		return fmt.Errorf("promote generation: promote: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("promote generation: commit: %w", err)
	}
	return nil
}

// CurrentScanForScope returns the promoted scan for a scope, or nil (no error)
// when none has been promoted yet. Generations of comparable scope share one
// current pointer.
func (s *ScanStore) CurrentScanForScope(ctx context.Context, scope string) (*model.Scan, error) {
	// delete_state = '' excludes a generation whose durable delete is in
	// progress or failed: is_current is not cleared until the row is finally
	// removed, so a crash mid-delete would otherwise leave a 'deleting'/
	// 'delete_failed' generation selectable as current. Gating on delete_state
	// makes a deleting generation drop out of the current view immediately —
	// before the recovery sweep finishes — so it can never be read as current
	// or reported complete.
	row := s.pool.QueryRow(ctx,
		`SELECT `+scanSelectColumns+`
		 FROM scans WHERE scope = $1 AND is_current = TRUE AND delete_state = ''
		 ORDER BY started_at DESC LIMIT 1`, scope)
	scan, err := scanScanRow(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("current scan for scope %q: %w", scope, err)
	}
	return scan, nil
}

// PriorValidScanForScope returns the most recent terminal, non-failed scan for
// the scope excluding excludeID. It is the generation that a delete of
// excludeID rematerializes as current. Returns nil (no error) when none exists.
func (s *ScanStore) PriorValidScanForScope(ctx context.Context, scope, excludeID string) (*model.Scan, error) {
	// delete_state = '' excludes a candidate whose own durable delete is in
	// progress or failed: rematerializing a generation that is itself being
	// deleted would re-expose facts that are mid-teardown, so a deleting/
	// delete_failed predecessor is never chosen as the restore target.
	row := s.pool.QueryRow(ctx,
		`SELECT `+scanSelectColumns+`
		 FROM scans
		 WHERE scope = $1 AND id <> $2
		   AND status IN ($3, $4)
		   AND delete_state = ''
		   AND coverage_status = 'complete'
		   AND stage_states->>'write' = 'succeeded'
		   AND stage_states->>'post_processing' IN ('succeeded', 'skipped')
		   AND stage_states->>'snapshot' IN ('succeeded', 'skipped')
		 ORDER BY started_at DESC LIMIT 1`,
		scope, excludeID, model.ScanStatusCompleted, model.ScanStatusCompletedWithErrors)
	scan, err := scanScanRow(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("prior valid scan for scope %q: %w", scope, err)
	}
	return scan, nil
}

// CurrentGenerations returns every promoted (is_current) scan across all
// collector scopes. It backs the generation gate: default reads scope to the
// generation_ids of these scans and derive completeness from their coverage,
// so staged/non-current generations are never surfaced by default.
func (s *ScanStore) CurrentGenerations(ctx context.Context) ([]model.Scan, error) {
	// delete_state = '' keeps a generation whose durable delete is in progress
	// or failed out of the default read scope and out of completeness: its
	// is_current flag survives until the row is removed, so without this gate a
	// crash mid-delete could surface a deleting generation as current or let it
	// contribute to an all-clear completeness verdict.
	rows, err := s.pool.Query(ctx,
		`SELECT `+scanSelectColumns+`
		 FROM scans WHERE is_current = TRUE AND delete_state = '' ORDER BY started_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("current generations: %w", err)
	}
	defer rows.Close()

	var scans []model.Scan
	for rows.Next() {
		scan, err := scanScanRow(rows)
		if err != nil {
			return nil, fmt.Errorf("current generation row: %w", err)
		}
		scans = append(scans, *scan)
	}
	return scans, rows.Err()
}

// CurrentDeletingGenerations returns the is_current scans whose durable delete
// is in progress or failed ('deleting'/'delete_failed'). These rows still carry
// is_current = TRUE (the flag is only cleared when the delete completes and the
// row is removed), so CurrentGenerations deliberately EXCLUDES them to keep them
// out of the default read scope. Left invisible, a scope stuck mid-delete would
// silently vanish and the remaining scopes could roll up to "complete"; the
// completeness layer reads this method to disclose those scopes as blockers /
// source errors instead.
func (s *ScanStore) CurrentDeletingGenerations(ctx context.Context) ([]model.Scan, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+scanSelectColumns+`
		 FROM scans WHERE is_current = TRUE AND delete_state <> '' ORDER BY started_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("current deleting generations: %w", err)
	}
	defer rows.Close()

	var scans []model.Scan
	for rows.Next() {
		scan, err := scanScanRow(rows)
		if err != nil {
			return nil, fmt.Errorf("current deleting generation row: %w", err)
		}
		scans = append(scans, *scan)
	}
	return scans, rows.Err()
}

func (s *ScanStore) GetScan(ctx context.Context, id string) (*model.Scan, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+scanSelectColumns+` FROM scans WHERE id = $1`, id)
	scan, err := scanScanRow(row)
	if err != nil {
		return nil, fmt.Errorf("get scan: %w", err)
	}
	return scan, nil
}

func (s *ScanStore) ListScans(ctx context.Context, limit, offset int) ([]model.Scan, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx,
		`SELECT `+scanSelectColumns+`
		 FROM scans ORDER BY started_at DESC LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list scans: %w", err)
	}
	defer rows.Close()

	var scans []model.Scan
	for rows.Next() {
		scan, err := scanScanRow(rows)
		if err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}
		scans = append(scans, *scan)
	}
	return scans, rows.Err()
}

// DeleteScan removes a scan row. It is idempotent: deleting an already-absent
// row is not an error, so a retried/recovered delete that already removed the
// row completes cleanly rather than failing.
func (s *ScanStore) DeleteScan(ctx context.Context, id string) error {
	if _, err := s.pool.Exec(ctx, `DELETE FROM scans WHERE id = $1`, id); err != nil {
		return fmt.Errorf("delete scan: %w", err)
	}
	return nil
}

// MarkDeleting records the 'deleting' lifecycle state on a scan BEFORE its
// graph observations are removed, so an interrupted delete is recoverable.
// Idempotent.
func (s *ScanStore) MarkDeleting(ctx context.Context, id string) error {
	if _, err := s.pool.Exec(ctx,
		`UPDATE scans SET delete_state = $1 WHERE id = $2`, model.DeleteStateDeleting, id); err != nil {
		return fmt.Errorf("mark scan deleting: %w", err)
	}
	return nil
}

// MarkDeleteFailed records that a delete attempt errored so it can be retried.
// Idempotent; a no-op if the row was already removed.
func (s *ScanStore) MarkDeleteFailed(ctx context.Context, id string) error {
	if _, err := s.pool.Exec(ctx,
		`UPDATE scans SET delete_state = $1 WHERE id = $2`, model.DeleteStateFailed, id); err != nil {
		return fmt.Errorf("mark scan delete_failed: %w", err)
	}
	return nil
}

// ScansInDeleteState returns every scan left in a non-terminal delete lifecycle
// ('deleting' or 'delete_failed'), used by the startup recovery sweep to finish
// interrupted deletes idempotently before the current pointer is exposed.
func (s *ScanStore) ScansInDeleteState(ctx context.Context) ([]model.Scan, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+scanSelectColumns+`
		 FROM scans WHERE delete_state IN ($1, $2) ORDER BY started_at ASC`,
		model.DeleteStateDeleting, model.DeleteStateFailed)
	if err != nil {
		return nil, fmt.Errorf("scans in delete state: %w", err)
	}
	defer rows.Close()
	var scans []model.Scan
	for rows.Next() {
		scan, err := scanScanRow(rows)
		if err != nil {
			return nil, fmt.Errorf("delete-state scan row: %w", err)
		}
		scans = append(scans, *scan)
	}
	return scans, rows.Err()
}

// rowScanner is satisfied by both pgx.Row (QueryRow) and pgx.Rows so
// scanScanRow serves single-row and multi-row reads with one implementation.
type rowScanner interface {
	Scan(dest ...any) error
}

// scanScanRow maps the scanSelectColumns projection into a model.Scan,
// including the migration-004 generation/coverage/stage/inventory columns.
func scanScanRow(row rowScanner) (*model.Scan, error) {
	var scan model.Scan
	var scanErr *string
	var coverageStatus string
	var coverageJSON, stageJSON []byte
	var nodeInv, edgeInv ingest.InventoryDelta

	if err := row.Scan(
		&scan.ID, &scan.Collector, &scan.Status, &scan.StartedAt, &scan.CompletedAt,
		&scan.NodeCount, &scan.EdgeCount, &scanErr, &scan.Metadata,
		&scan.GenerationID, &scan.IsCurrent, &scan.SchemaVersion, &scan.IdentityVersion,
		&coverageStatus, &coverageJSON, &stageJSON,
		&nodeInv.Created, &nodeInv.Updated, &nodeInv.Unchanged, &nodeInv.Retired, &nodeInv.BeforeTotal, &nodeInv.AfterTotal,
		&edgeInv.Created, &edgeInv.Updated, &edgeInv.Unchanged, &edgeInv.Retired, &edgeInv.BeforeTotal, &edgeInv.AfterTotal,
		&scan.CapturedAt, &scan.Scope, &scan.DeleteState,
	); err != nil {
		return nil, err
	}
	if scanErr != nil {
		scan.Error = *scanErr
	}
	scan.CoverageStatus = ingest.CollectionStatus(coverageStatus)
	if cov, err := unmarshalCoverage(coverageJSON); err != nil {
		return nil, fmt.Errorf("decode coverage: %w", err)
	} else {
		scan.Coverage = cov
	}
	if stages, err := unmarshalStageStates(stageJSON); err != nil {
		return nil, fmt.Errorf("decode stage states: %w", err)
	} else {
		scan.StageStates = stages
	}
	// Only surface inventory deltas when at least one field is populated so
	// legacy rows (all-zero defaults) don't fabricate a "0 discovered" claim.
	if nodeInv != (ingest.InventoryDelta{}) {
		ni := nodeInv
		scan.NodeInventory = &ni
	}
	if edgeInv != (ingest.InventoryDelta{}) {
		ei := edgeInv
		scan.EdgeInventory = &ei
	}
	return &scan, nil
}

// scopeOrCollector returns the scan's explicit scope key, falling back to the
// collector when no scope was set (so a caller that has not adopted the scope
// field still records a usable, collector-equivalent scope).
func scopeOrCollector(scan *model.Scan) string {
	if scan.Scope != "" {
		return scan.Scope
	}
	return scan.Collector
}

func marshalCoverage(c *ingest.CollectionCoverage) ([]byte, error) {
	if c == nil {
		return []byte("{}"), nil
	}
	return json.Marshal(c)
}

func unmarshalCoverage(data []byte) (*ingest.CollectionCoverage, error) {
	if len(data) == 0 || string(data) == "{}" || string(data) == "null" {
		return nil, nil
	}
	var c ingest.CollectionCoverage
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

func marshalStageStates(m map[string]ingest.StageState) ([]byte, error) {
	if len(m) == 0 {
		return []byte("{}"), nil
	}
	return json.Marshal(m)
}

func unmarshalStageStates(data []byte) (map[string]ingest.StageState, error) {
	if len(data) == 0 || string(data) == "{}" || string(data) == "null" {
		return nil, nil
	}
	var m map[string]ingest.StageState
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return m, nil
}
