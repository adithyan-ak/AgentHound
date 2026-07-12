package appdb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/adithyan-ak/agenthound/server/model"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// suppressedStatuses are triage decisions that hide a finding from the
// default findings view and from CI-style diffs/fail-on gates.
var suppressedStatuses = []string{"accepted-risk", "false-positive"}

// FindingStore persists per-scan finding snapshots and cross-scan triage
// state. Complete raw-domain promotion replaces the graph's global composite
// epoch, so the Postgres snapshot is the only diffable record of "what was
// found when".
type FindingStore struct {
	pool *pgxpool.Pool
}

func NewFindingStore(pool *pgxpool.Pool) *FindingStore {
	return &FindingStore{pool: pool}
}

// FindingsDiff is the result of comparing two scans' finding snapshots,
// keyed by fingerprint.
type FindingsDiff struct {
	ScanA     string          `json:"scan_a"`
	ScanB     string          `json:"scan_b"`
	Added     []model.Finding `json:"added"`
	Removed   []model.Finding `json:"removed"`
	Unchanged []model.Finding `json:"unchanged"`
}

type FindingScope struct {
	Mode             string     `json:"mode"`
	ScanID           string     `json:"scan_id"`
	Revision         *int64     `json:"revision"`
	PublishedAt      *time.Time `json:"published_at"`
	ProjectionStatus string     `json:"projection_status"`
	SnapshotStatus   string     `json:"snapshot_status"`
	Available        bool       `json:"available"`
	Stale            bool       `json:"stale"`
}

func replaceFindingsTx(ctx context.Context, tx pgx.Tx, scanID string, findings []model.Finding) error {
	if _, err := tx.Exec(ctx, `DELETE FROM findings WHERE scan_id = $1`, scanID); err != nil {
		return fmt.Errorf("delete prior findings snapshot: %w", err)
	}
	if len(findings) == 0 {
		return nil
	}

	batch := &pgx.Batch{}
	for _, f := range findings {
		owasp := f.OWASPMap
		if owasp == nil {
			owasp = []string{}
		}
		atlas := f.ATLASMap
		if atlas == nil {
			atlas = []string{}
		}
		if f.Variant == "" {
			f.Variant = model.FindingVariantUnknown
		}
		if f.Evidence.State == "" {
			f.Evidence.State = model.FindingEvidenceUnknown
		}
		evidenceJSON, err := json.Marshal(f.Evidence)
		if err != nil {
			return fmt.Errorf("marshal finding evidence %s: %w", f.ID, err)
		}
		var exactEvidenceJSON any
		if f.ExactEvidence != nil {
			encoded, err := json.Marshal(f.ExactEvidence)
			if err != nil {
				return fmt.Errorf("marshal exact finding evidence %s: %w", f.ID, err)
			}
			exactEvidenceJSON = string(encoded)
		}
		batch.Queue(
			`INSERT INTO findings
			   (scan_id, fingerprint, severity, category, title, description, edge_kind,
			    source_id, source_name, source_kind, target_id, target_name, target_kind,
			    confidence, owasp_map, atlas_map, variant, evidence, exact_evidence, cross_protocol)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18::jsonb,$19::jsonb,$20)`,
			scanID, f.ID, f.Severity, f.Category, f.Title, f.Description, f.EdgeKind,
			f.SourceID, f.SourceName, f.SourceKind, f.TargetID, f.TargetName, f.TargetKind,
			f.Confidence, owasp, atlas, f.Variant, string(evidenceJSON), exactEvidenceJSON,
			isCrossProtocol(f.SourceKind, f.TargetKind),
		)
	}

	results := tx.SendBatch(ctx, batch)
	for range findings {
		if _, err := results.Exec(); err != nil {
			_ = results.Close()
			return fmt.Errorf("insert findings batch: %w", err)
		}
	}
	if err := results.Close(); err != nil {
		return fmt.Errorf("close findings batch: %w", err)
	}
	return nil
}

const findingSelectColumns = `f.scan_id, f.captured_at, f.fingerprint, f.severity, f.category, f.title, f.description, f.edge_kind,
	f.source_id, f.source_name, f.source_kind, f.target_id, f.target_name, f.target_kind,
	f.confidence, f.owasp_map, f.atlas_map, f.variant, f.evidence, f.exact_evidence, t.status, t.note, t.updated_at`

// PublishedFindingScope resolves the one immutable finding snapshot currently
// advertised as posture. A partial Neo4j update does not move this pointer;
// callers can keep the prior rows while clearly marking them stale.
func (s *FindingStore) PublishedFindingScope(ctx context.Context) (FindingScope, error) {
	scope := FindingScope{
		Mode:             "published",
		ProjectionStatus: model.ProjectionUnknown,
		SnapshotStatus:   model.LifecycleUnknown,
	}
	var (
		scanID           *string
		revision         *int64
		publishedAt      *time.Time
		projectionScanID *string
	)
	err := s.pool.QueryRow(ctx, `SELECT
	    ps.published_scan_id,
	    ps.published_revision,
	    ps.published_at,
	    ps.projection_status,
	    ps.projection_scan_id,
	    coalesce(sc.snapshot_status, 'unknown')
	FROM posture_state ps
	LEFT JOIN scans sc ON sc.id = ps.published_scan_id
	WHERE ps.singleton = TRUE`).Scan(
		&scanID,
		&revision,
		&publishedAt,
		&scope.ProjectionStatus,
		&projectionScanID,
		&scope.SnapshotStatus,
	)
	if err != nil {
		return FindingScope{}, fmt.Errorf("published finding scope: %w", err)
	}
	if scanID == nil || revision == nil {
		return scope, nil
	}
	scope.ScanID = *scanID
	scope.Revision = revision
	scope.PublishedAt = publishedAt
	scope.Available = true
	scope.Stale = scope.ProjectionStatus != model.ProjectionComplete ||
		projectionScanID == nil ||
		*projectionScanID != scope.ScanID
	return scope, nil
}

func (s *FindingStore) ListPublished(
	ctx context.Context,
	severity string,
	includeSuppressed bool,
) ([]model.Finding, FindingScope, error) {
	scope, err := s.PublishedFindingScope(ctx)
	if err != nil {
		return nil, FindingScope{}, err
	}
	if !scope.Available {
		return []model.Finding{}, scope, nil
	}
	findings, err := s.ListForScan(ctx, scope.ScanID, severity, includeSuppressed)
	return findings, scope, err
}

func (s *FindingStore) ListForScan(
	ctx context.Context,
	scanID, severity string,
	includeSuppressed bool,
) ([]model.Finding, error) {
	query := `
SELECT ` + findingSelectColumns + `
FROM findings f
LEFT JOIN finding_triage t ON t.fingerprint = f.fingerprint
WHERE f.scan_id = $1
  AND ($2 = '' OR f.severity = $2)
  AND ($3 OR t.status IS NULL OR t.status NOT IN ('accepted-risk','false-positive'))
ORDER BY f.confidence DESC, f.fingerprint`

	rows, err := s.pool.Query(ctx, query, scanID, severity, includeSuppressed)
	if err != nil {
		return nil, fmt.Errorf("list findings for scan %s: %w", scanID, err)
	}
	defer rows.Close()
	return scanFindings(rows)
}

func (s *FindingStore) GetForScan(
	ctx context.Context,
	scanID, fingerprint string,
) (*model.Finding, error) {
	query := `
SELECT ` + findingSelectColumns + `
FROM findings f
LEFT JOIN finding_triage t ON t.fingerprint = f.fingerprint
WHERE f.scan_id = $1 AND f.fingerprint = $2`
	rows, err := s.pool.Query(ctx, query, scanID, fingerprint)
	if err != nil {
		return nil, fmt.Errorf("get finding %s for scan %s: %w", fingerprint, scanID, err)
	}
	defer rows.Close()
	findings, err := scanFindings(rows)
	if err != nil {
		return nil, err
	}
	if len(findings) == 0 {
		return nil, nil
	}
	return &findings[0], nil
}

func (s *FindingStore) GetPublished(
	ctx context.Context,
	fingerprint string,
) (*model.Finding, FindingScope, error) {
	scope, err := s.PublishedFindingScope(ctx)
	if err != nil {
		return nil, FindingScope{}, err
	}
	if !scope.Available {
		return nil, scope, nil
	}
	finding, err := s.GetForScan(ctx, scope.ScanID, fingerprint)
	return finding, scope, err
}

// findingsForScan returns every finding persisted for a single scan, with
// triage state attached.
func (s *FindingStore) findingsForScan(ctx context.Context, scanID string) ([]model.Finding, error) {
	return s.ListForScan(ctx, scanID, "", true)
}

// Diff compares two scans' snapshots. added = present in scanB but not
// scanA; removed = present in scanA but not scanB; unchanged = present in
// both. When includeSuppressed is false, suppressed findings are dropped
// from the added set so CI-style diffs don't re-alert on accepted risks.
func (s *FindingStore) Diff(ctx context.Context, scanA, scanB string, includeSuppressed bool) (*FindingsDiff, error) {
	a, err := s.findingsForScan(ctx, scanA)
	if err != nil {
		return nil, err
	}
	b, err := s.findingsForScan(ctx, scanB)
	if err != nil {
		return nil, err
	}

	aByFP := make(map[string]model.Finding, len(a))
	for _, f := range a {
		aByFP[f.ID] = f
	}
	bByFP := make(map[string]model.Finding, len(b))
	for _, f := range b {
		bByFP[f.ID] = f
	}

	diff := &FindingsDiff{ScanA: scanA, ScanB: scanB}
	for _, f := range b {
		if _, ok := aByFP[f.ID]; ok {
			diff.Unchanged = append(diff.Unchanged, f)
			continue
		}
		if !includeSuppressed && isSuppressed(f.Triage) {
			continue
		}
		diff.Added = append(diff.Added, f)
	}
	for _, f := range a {
		if _, ok := bByFP[f.ID]; !ok {
			diff.Removed = append(diff.Removed, f)
		}
	}
	return diff, nil
}

// GetTriage returns the triage state for a fingerprint, or nil if none has
// been recorded (callers treat nil as the implicit "new" status).
func (s *FindingStore) GetTriage(ctx context.Context, fingerprint string) (*model.TriageState, error) {
	var ts model.TriageState
	err := s.pool.QueryRow(ctx,
		`SELECT status, note, updated_at FROM finding_triage WHERE fingerprint = $1`,
		fingerprint).Scan(&ts.Status, &ts.Note, &ts.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get triage: %w", err)
	}
	return &ts, nil
}

// UpdateTriageStatus records (or updates) only the status for a fingerprint,
// preserving any existing analyst note. Used for status-only triage changes so
// routine status updates cannot silently destroy an analyst's note (AH-UI-34).
// On first insert the note defaults to empty; on conflict the note column is
// deliberately left out of the SET so it survives.
func (s *FindingStore) UpdateTriageStatus(ctx context.Context, fingerprint, status string) (*model.TriageState, error) {
	var ts model.TriageState
	err := s.pool.QueryRow(ctx,
		`INSERT INTO finding_triage (fingerprint, status, note, updated_at)
		 VALUES ($1, $2, '', NOW())
		 ON CONFLICT (fingerprint) DO UPDATE SET
		    status = EXCLUDED.status,
		    updated_at = NOW()
		 RETURNING status, note, updated_at`,
		fingerprint, status).Scan(&ts.Status, &ts.Note, &ts.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("update triage status: %w", err)
	}
	return &ts, nil
}

// UpsertTriage records (or updates) the triage decision for a fingerprint,
// including the note. Callers use this only when the note is explicitly
// provided (which includes explicit clearing to ""); status-only changes go
// through UpdateTriageStatus so the note is preserved.
func (s *FindingStore) UpsertTriage(ctx context.Context, fingerprint, status, note string) (*model.TriageState, error) {
	var ts model.TriageState
	err := s.pool.QueryRow(ctx,
		`INSERT INTO finding_triage (fingerprint, status, note, updated_at)
		 VALUES ($1, $2, $3, NOW())
		 ON CONFLICT (fingerprint) DO UPDATE SET
		    status = EXCLUDED.status,
		    note = EXCLUDED.note,
		    updated_at = NOW()
		 RETURNING status, note, updated_at`,
		fingerprint, status, note).Scan(&ts.Status, &ts.Note, &ts.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("upsert triage: %w", err)
	}
	return &ts, nil
}

// scanFindings maps result rows (with the LEFT JOIN triage columns) into
// model.Finding values. A NULL triage status yields a nil Triage pointer.
func scanFindings(rows pgx.Rows) ([]model.Finding, error) {
	var out []model.Finding
	for rows.Next() {
		var f model.Finding
		var status, note *string
		var updatedAt *time.Time
		var evidenceJSON, exactEvidenceJSON []byte
		if err := rows.Scan(
			&f.ScanID, &f.CapturedAt,
			&f.ID, &f.Severity, &f.Category, &f.Title, &f.Description, &f.EdgeKind,
			&f.SourceID, &f.SourceName, &f.SourceKind, &f.TargetID, &f.TargetName, &f.TargetKind,
			&f.Confidence, &f.OWASPMap, &f.ATLASMap, &f.Variant, &evidenceJSON, &exactEvidenceJSON,
			&status, &note, &updatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan finding row: %w", err)
		}
		f.ID = strings.TrimSpace(f.ID)
		if len(evidenceJSON) > 0 {
			if err := json.Unmarshal(evidenceJSON, &f.Evidence); err != nil {
				return nil, fmt.Errorf("decode finding %s evidence: %w", f.ID, err)
			}
		}
		if f.Evidence.Channels == nil {
			f.Evidence.Channels = []string{}
		}
		if len(exactEvidenceJSON) > 0 {
			var exact model.ExactFindingEvidence
			if err := json.Unmarshal(exactEvidenceJSON, &exact); err != nil {
				return nil, fmt.Errorf("decode finding %s exact evidence: %w", f.ID, err)
			}
			normalizeExactFindingEvidence(&exact)
			f.ExactEvidence = &exact
		}
		if status != nil {
			ts := &model.TriageState{Status: *status}
			if note != nil {
				ts.Note = *note
			}
			if updatedAt != nil {
				ts.UpdatedAt = *updatedAt
			}
			f.Triage = ts
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func normalizeExactFindingEvidence(exact *model.ExactFindingEvidence) {
	if exact.Nodes == nil {
		exact.Nodes = []model.ExactFindingEvidenceNode{}
	}
	if exact.Edges == nil {
		exact.Edges = []model.ExactFindingEvidenceEdge{}
	}
	if exact.Reasons == nil {
		exact.Reasons = []string{}
	}
	for i := range exact.Nodes {
		if exact.Nodes[i].Kinds == nil {
			exact.Nodes[i].Kinds = []string{}
		}
		if exact.Nodes[i].Properties == nil {
			exact.Nodes[i].Properties = map[string]any{}
		}
	}
	for i := range exact.Edges {
		if exact.Edges[i].Properties == nil {
			exact.Edges[i].Properties = map[string]any{}
		}
	}
}

func isSuppressed(ts *model.TriageState) bool {
	if ts == nil {
		return false
	}
	for _, s := range suppressedStatuses {
		if ts.Status == s {
			return true
		}
	}
	return false
}

// isCrossProtocol mirrors the UI's cross-protocol predicate: a finding
// whose endpoints straddle the A2A and MCP protocol families.
func isCrossProtocol(sourceKind, targetKind string) bool {
	a2a := func(k string) bool { return strings.HasPrefix(k, "A2A") }
	mcp := func(k string) bool { return strings.HasPrefix(k, "MCP") }
	return (a2a(sourceKind) && mcp(targetKind)) || (mcp(sourceKind) && a2a(targetKind))
}
