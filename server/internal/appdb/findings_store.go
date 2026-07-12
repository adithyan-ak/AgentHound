package appdb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/server/model"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// suppressedStatuses are triage decisions that hide a finding from the
// default findings view and from CI-style diffs/fail-on gates.
var suppressedStatuses = []string{"accepted-risk", "false-positive"}

// FindingStore persists per-scan finding snapshots and cross-scan triage
// state. The graph's stale-edge cleanup rewrites composite edges every
// scan, so the Postgres snapshot is the only diffable record of "what was
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

// InsertFindings persists a scan's finding occurrences. Idempotent: a re-run
// of the same scan_id overwrites the prior rows for that scan. Every truth-
// contract column (detection subtype/version, typed evidence DAG, confidence
// basis, nullable attack cost with missing-weight count, lifecycle, rule
// manifest, ATLAS map) is persisted so the list and detail endpoints read
// identical, fully-populated occurrences from one source.
func (s *FindingStore) InsertFindings(ctx context.Context, scanID string, findings []model.Finding) error {
	if scanID == "" {
		return errors.New("insert findings: empty scan_id")
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
		evidenceJSON, err := marshalJSONObject(f.EvidenceDAG)
		if err != nil {
			return fmt.Errorf("insert findings: marshal evidence_dag: %w", err)
		}
		compositeJSON, err := marshalJSONObject(f.CompositeProps)
		if err != nil {
			return fmt.Errorf("insert findings: marshal composite_props: %w", err)
		}
		ruleJSON, err := marshalJSONArray(f.RuleManifest)
		if err != nil {
			return fmt.Errorf("insert findings: marshal rule_manifest: %w", err)
		}
		atlasJSON, err := marshalStringArrayJSON(f.ATLASMap)
		if err != nil {
			return fmt.Errorf("insert findings: marshal atlas_map: %w", err)
		}
		lifecycle := f.Lifecycle
		if lifecycle == "" {
			lifecycle = "active"
		}
		batch.Queue(
			`INSERT INTO findings
			   (scan_id, fingerprint, severity, category, title, description, edge_kind,
			    source_id, source_name, source_kind, target_id, target_name, target_kind,
			    confidence, owasp_map, cross_protocol, generation_id,
			    detection_subtype, detection_version, evidence_dag, composite_props, confidence_basis,
			    attack_cost, weight_total, weight_missing_count, lifecycle, rule_manifest, atlas_map)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,
			         $18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28)
			 ON CONFLICT (scan_id, fingerprint) DO UPDATE SET
			    severity = EXCLUDED.severity,
			    category = EXCLUDED.category,
			    title = EXCLUDED.title,
			    description = EXCLUDED.description,
			    edge_kind = EXCLUDED.edge_kind,
			    source_id = EXCLUDED.source_id,
			    source_name = EXCLUDED.source_name,
			    source_kind = EXCLUDED.source_kind,
			    target_id = EXCLUDED.target_id,
			    target_name = EXCLUDED.target_name,
			    target_kind = EXCLUDED.target_kind,
			    confidence = EXCLUDED.confidence,
			    owasp_map = EXCLUDED.owasp_map,
			    cross_protocol = EXCLUDED.cross_protocol,
			    generation_id = EXCLUDED.generation_id,
			    detection_subtype = EXCLUDED.detection_subtype,
			    detection_version = EXCLUDED.detection_version,
			    evidence_dag = EXCLUDED.evidence_dag,
			    composite_props = EXCLUDED.composite_props,
			    confidence_basis = EXCLUDED.confidence_basis,
			    attack_cost = EXCLUDED.attack_cost,
			    weight_total = EXCLUDED.weight_total,
			    weight_missing_count = EXCLUDED.weight_missing_count,
			    lifecycle = EXCLUDED.lifecycle,
			    rule_manifest = EXCLUDED.rule_manifest,
			    atlas_map = EXCLUDED.atlas_map`,
			scanID, f.ID, f.Severity, f.Category, f.Title, f.Description, f.EdgeKind,
			f.SourceID, f.SourceName, f.SourceKind, f.TargetID, f.TargetName, f.TargetKind,
			f.Confidence, owasp, isCrossProtocol(f.SourceKind, f.TargetKind), f.GenerationID,
			f.DetectionSubtype, f.DetectionVersion, evidenceJSON, compositeJSON, f.ConfidenceBasis,
			f.AttackCost, f.WeightTotal, f.WeightMissingCount, lifecycle, ruleJSON, atlasJSON,
		)
	}

	br := s.pool.SendBatch(ctx, batch)
	defer br.Close()
	for range findings {
		if _, err := br.Exec(); err != nil {
			return fmt.Errorf("insert findings batch: %w", err)
		}
	}
	return nil
}

// DeleteFindingsForScan removes a scan's persisted finding snapshot. Called
// during coordinated scan deletion so a deleted generation leaves no orphan
// findings behind. Absent rows are not an error (idempotent).
func (s *FindingStore) DeleteFindingsForScan(ctx context.Context, scanID string) error {
	if scanID == "" {
		return errors.New("delete findings: empty scan_id")
	}
	if _, err := s.pool.Exec(ctx, `DELETE FROM findings WHERE scan_id = $1`, scanID); err != nil {
		return fmt.Errorf("delete findings for scan %s: %w", scanID, err)
	}
	return nil
}

const findingSelectColumns = `f.fingerprint, f.severity, f.category, f.title, f.description, f.edge_kind,
	f.source_id, f.source_name, f.source_kind, f.target_id, f.target_name, f.target_kind,
	f.confidence, f.owasp_map, f.generation_id, f.detection_subtype, f.detection_version,
	f.evidence_dag, f.composite_props, f.confidence_basis, f.attack_cost, f.weight_total, f.weight_missing_count,
	f.lifecycle, f.rule_manifest, f.atlas_map, t.status, t.note, t.updated_at`

// findingLatestColumns is the outer projection over the DISTINCT ON subquery.
// It reads the same columns back from the `latest` alias (the LEFT JOIN triage
// columns live on `latest` at the outer level, not `t`). Order MUST match
// scanFindings' positional scan.
const findingLatestColumns = `latest.fingerprint, latest.severity, latest.category, latest.title, latest.description, latest.edge_kind,
	latest.source_id, latest.source_name, latest.source_kind, latest.target_id, latest.target_name, latest.target_kind,
	latest.confidence, latest.owasp_map, latest.generation_id, latest.detection_subtype, latest.detection_version,
	latest.evidence_dag, latest.composite_props, latest.confidence_basis, latest.attack_cost, latest.weight_total, latest.weight_missing_count,
	latest.lifecycle, latest.rule_manifest, latest.atlas_map, latest.status, latest.note, latest.updated_at`

// ListLatestPerFingerprint returns the most recent finding row per
// fingerprint (across all scans), with triage state attached. severity
// filters by exact level when non-empty. When includeSuppressed is false,
// findings triaged as accepted-risk / false-positive are dropped.
func (s *FindingStore) ListLatestPerFingerprint(ctx context.Context, severity string, includeSuppressed bool) ([]model.Finding, error) {
	// The inner subquery joins findings + finding_triage (aliases f, t) and
	// keeps the latest row per fingerprint. The outer query must read every
	// column back from the `latest` subquery — including the triage columns
	// (status/note/updated_at), which at the outer level live on `latest`,
	// NOT on `t` (that alias is only in scope inside the subquery). Listing
	// the outer columns explicitly keeps the projection order aligned with
	// scanFindings' positional scan.
	query := `
SELECT ` + findingLatestColumns + `
FROM (
    SELECT DISTINCT ON (f.fingerprint) ` + findingSelectColumns + `
    FROM findings f
    LEFT JOIN finding_triage t ON t.fingerprint = f.fingerprint
    ORDER BY f.fingerprint, f.captured_at DESC
) latest
WHERE ($1 = '' OR latest.severity = $1)
  AND ($2 OR latest.status IS NULL OR latest.status NOT IN ('accepted-risk','false-positive'))
ORDER BY latest.confidence DESC`

	rows, err := s.pool.Query(ctx, query, severity, includeSuppressed)
	if err != nil {
		return nil, fmt.Errorf("list findings: %w", err)
	}
	defer rows.Close()
	return scanFindings(rows)
}

// FindingQuery bounds a generation-scoped, completeness-aware finding read.
type FindingQuery struct {
	// GenerationIDs restricts the read to the current (promoted) generations.
	// An empty slice means "no current generation" and yields zero items —
	// default reads never surface staged/non-current occurrences.
	GenerationIDs     []string
	Severity          string
	IncludeSuppressed bool
	Limit             int
	Offset            int
}

// ListCurrentFindings returns the latest occurrence per fingerprint scoped to
// the given (current) generations, plus the total matching count for
// pagination. When GenerationIDs is empty the result is empty with total 0.
func (s *FindingStore) ListCurrentFindings(ctx context.Context, q FindingQuery) (items []model.Finding, total int, err error) {
	if len(q.GenerationIDs) == 0 {
		return []model.Finding{}, 0, nil
	}
	limit := q.Limit
	if limit <= 0 {
		limit = 50
	}
	offset := q.Offset
	if offset < 0 {
		offset = 0
	}

	// The DISTINCT ON subquery keeps the newest occurrence per fingerprint
	// within the current generations; the WHERE filters severity + suppression
	// on that latest row. total is counted over the same filtered set.
	base := `
FROM (
    SELECT DISTINCT ON (f.fingerprint) ` + findingSelectColumns + `
    FROM findings f
    LEFT JOIN finding_triage t ON t.fingerprint = f.fingerprint
    WHERE f.generation_id = ANY($1)
    ORDER BY f.fingerprint, f.captured_at DESC
) latest
WHERE ($2 = '' OR latest.severity = $2)
  AND ($3 OR latest.status IS NULL OR latest.status NOT IN ('accepted-risk','false-positive'))`

	if err := s.pool.QueryRow(ctx,
		`SELECT COUNT(*) `+base, q.GenerationIDs, q.Severity, q.IncludeSuppressed).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count current findings: %w", err)
	}

	rows, err := s.pool.Query(ctx,
		`SELECT `+findingLatestColumns+base+`
ORDER BY latest.confidence DESC
LIMIT $4 OFFSET $5`,
		q.GenerationIDs, q.Severity, q.IncludeSuppressed, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("list current findings: %w", err)
	}
	defer rows.Close()
	items, err = scanFindings(rows)
	if err != nil {
		return nil, 0, err
	}
	if items == nil {
		items = []model.Finding{}
	}
	return items, total, nil
}

// GetCurrentFinding returns a single finding occurrence by fingerprint scoped
// to the current generations, with triage joined. Returns nil (no error) when
// the fingerprint is absent from the current generations, so detail and list
// read from the identical source and shape.
func (s *FindingStore) GetCurrentFinding(ctx context.Context, generationIDs []string, fingerprint string) (*model.Finding, error) {
	if len(generationIDs) == 0 {
		return nil, nil
	}
	query := `
SELECT ` + findingLatestColumns + `
FROM (
    SELECT DISTINCT ON (f.fingerprint) ` + findingSelectColumns + `
    FROM findings f
    LEFT JOIN finding_triage t ON t.fingerprint = f.fingerprint
    WHERE f.generation_id = ANY($1) AND f.fingerprint = $2
    ORDER BY f.fingerprint, f.captured_at DESC
) latest
LIMIT 1`
	rows, err := s.pool.Query(ctx, query, generationIDs, fingerprint)
	if err != nil {
		return nil, fmt.Errorf("get current finding: %w", err)
	}
	defer rows.Close()
	found, err := scanFindings(rows)
	if err != nil {
		return nil, err
	}
	if len(found) == 0 {
		return nil, nil
	}
	return &found[0], nil
}

// findingsForScan returns every finding persisted for a single scan, with
// triage state attached.
func (s *FindingStore) findingsForScan(ctx context.Context, scanID string) ([]model.Finding, error) {
	query := `
SELECT ` + findingSelectColumns + `
FROM findings f
LEFT JOIN finding_triage t ON t.fingerprint = f.fingerprint
WHERE f.scan_id = $1
ORDER BY f.confidence DESC`

	rows, err := s.pool.Query(ctx, query, scanID)
	if err != nil {
		return nil, fmt.Errorf("findings for scan %s: %w", scanID, err)
	}
	defer rows.Close()
	return scanFindings(rows)
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

// UpsertTriage records (or updates) the triage decision for a fingerprint.
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

// PatchTriage applies field-level triage updates with preserve-vs-clear
// semantics: a nil pointer preserves the stored value, a non-nil pointer sets
// it (an explicit empty string clears). On first write for a fingerprint an
// omitted status defaults to "new" and an omitted note to empty.
func (s *FindingStore) PatchTriage(ctx context.Context, fingerprint string, status, note *string) (*model.TriageState, error) {
	var ts model.TriageState
	err := s.pool.QueryRow(ctx,
		`INSERT INTO finding_triage (fingerprint, status, note, updated_at)
		 VALUES ($1, COALESCE($2, 'new'), COALESCE($3, ''), NOW())
		 ON CONFLICT (fingerprint) DO UPDATE SET
		    status = COALESCE($2, finding_triage.status),
		    note = COALESCE($3, finding_triage.note),
		    updated_at = NOW()
		 RETURNING status, note, updated_at`,
		fingerprint, status, note).Scan(&ts.Status, &ts.Note, &ts.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("patch triage: %w", err)
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
		var evidenceJSON, compositeJSON, ruleJSON, atlasJSON []byte
		if err := rows.Scan(
			&f.ID, &f.Severity, &f.Category, &f.Title, &f.Description, &f.EdgeKind,
			&f.SourceID, &f.SourceName, &f.SourceKind, &f.TargetID, &f.TargetName, &f.TargetKind,
			&f.Confidence, &f.OWASPMap, &f.GenerationID, &f.DetectionSubtype, &f.DetectionVersion,
			&evidenceJSON, &compositeJSON, &f.ConfidenceBasis, &f.AttackCost, &f.WeightTotal, &f.WeightMissingCount,
			&f.Lifecycle, &ruleJSON, &atlasJSON, &status, &note, &updatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan finding row: %w", err)
		}
		f.ID = strings.TrimSpace(f.ID)
		if dag, err := unmarshalJSONObject(evidenceJSON); err != nil {
			return nil, fmt.Errorf("decode evidence_dag: %w", err)
		} else {
			f.EvidenceDAG = dag
		}
		if props, err := unmarshalJSONObject(compositeJSON); err != nil {
			return nil, fmt.Errorf("decode composite_props: %w", err)
		} else {
			f.CompositeProps = props
		}
		if rm, err := unmarshalRuleManifest(ruleJSON); err != nil {
			return nil, fmt.Errorf("decode rule_manifest: %w", err)
		} else {
			f.RuleManifest = rm
		}
		if am, err := unmarshalStringArrayJSON(atlasJSON); err != nil {
			return nil, fmt.Errorf("decode atlas_map: %w", err)
		} else {
			f.ATLASMap = am
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

// marshalJSONObject renders a JSONB object column value. A nil/empty map is
// stored as "{}" so the NOT NULL DEFAULT '{}' contract holds.
func marshalJSONObject(m map[string]any) ([]byte, error) {
	if len(m) == 0 {
		return []byte("{}"), nil
	}
	return json.Marshal(m)
}

func unmarshalJSONObject(data []byte) (map[string]any, error) {
	if len(data) == 0 || string(data) == "{}" || string(data) == "null" {
		return nil, nil
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func marshalJSONArray(entries []ingest.RuleManifestEntry) ([]byte, error) {
	if len(entries) == 0 {
		return []byte("[]"), nil
	}
	return json.Marshal(entries)
}

func unmarshalRuleManifest(data []byte) ([]ingest.RuleManifestEntry, error) {
	if len(data) == 0 || string(data) == "[]" || string(data) == "null" {
		return nil, nil
	}
	var m []ingest.RuleManifestEntry
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func marshalStringArrayJSON(vals []string) ([]byte, error) {
	if len(vals) == 0 {
		return []byte("[]"), nil
	}
	return json.Marshal(vals)
}

func unmarshalStringArrayJSON(data []byte) ([]string, error) {
	if len(data) == 0 || string(data) == "[]" || string(data) == "null" {
		return nil, nil
	}
	var m []string
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return m, nil
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
