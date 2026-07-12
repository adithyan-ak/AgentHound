-- 004_truth_contracts.sql
--
-- Foundation phase of the truthfulness contract reset. Extends the scan and
-- finding stores with the columns the generation-scoped, completeness-aware
-- posture requires. Prelaunch policy: this migration ADDS columns with safe
-- defaults; it assumes a clean database reset / re-ingest rather than
-- backfilling meaningful values into pre-existing rows. Later phases populate
-- these columns; this migration only makes the schema able to hold the truth.
--
-- All additions are additive: existing INSERT/SELECT statements in scans.go and
-- findings_store.go name their columns explicitly, so new defaulted columns do
-- not perturb the current read/write paths.

-- ---------------------------------------------------------------------------
-- scans: generation identity, coverage, independent stage states, accurate
-- write/inventory metrics, and a distinct collection-capture timestamp.
-- ---------------------------------------------------------------------------

-- Graph generation this scan materialized. Reads scoped to a generation see a
-- consistent snapshot; only a promoted generation is current.
ALTER TABLE scans ADD COLUMN IF NOT EXISTS generation_id TEXT NOT NULL DEFAULT '';
ALTER TABLE scans ADD COLUMN IF NOT EXISTS is_current BOOLEAN NOT NULL DEFAULT FALSE;

-- Canonical contract + identity versions the artifact was produced against.
ALTER TABLE scans ADD COLUMN IF NOT EXISTS schema_version INT NOT NULL DEFAULT 1;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS identity_version INT NOT NULL DEFAULT 1;

-- Roll-up collection status: absence is only clean when 'complete'.
ALTER TABLE scans ADD COLUMN IF NOT EXISTS coverage_status TEXT NOT NULL DEFAULT 'unknown'
    CHECK (coverage_status IN ('complete','partial','failed','unknown'));

-- Full coverage manifest (constituent collectors, per-target/per-method
-- outcomes, rule manifest, truncation) as emitted on IngestMeta.Coverage.
ALTER TABLE scans ADD COLUMN IF NOT EXISTS coverage JSONB NOT NULL DEFAULT '{}';

-- Per-stage outcome map: { "write": "...", "post_processing": "...",
-- "snapshot": "...", "promotion": "..." }. A failure in one stage is no longer
-- masked by success in another, nor recorded as 0/0 success-like history.
ALTER TABLE scans ADD COLUMN IF NOT EXISTS stage_states JSONB NOT NULL DEFAULT '{}';

-- Accurate node/edge inventory deltas. MERGE row counts are no longer
-- mislabeled as discoveries or growth.
ALTER TABLE scans ADD COLUMN IF NOT EXISTS nodes_created   INT NOT NULL DEFAULT 0;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS nodes_updated   INT NOT NULL DEFAULT 0;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS nodes_unchanged INT NOT NULL DEFAULT 0;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS nodes_retired   INT NOT NULL DEFAULT 0;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS nodes_before    INT NOT NULL DEFAULT 0;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS nodes_after     INT NOT NULL DEFAULT 0;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS edges_created   INT NOT NULL DEFAULT 0;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS edges_updated   INT NOT NULL DEFAULT 0;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS edges_unchanged INT NOT NULL DEFAULT 0;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS edges_retired   INT NOT NULL DEFAULT 0;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS edges_before    INT NOT NULL DEFAULT 0;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS edges_after     INT NOT NULL DEFAULT 0;

-- Collection-capture completion time, distinct from completed_at (server
-- ingest completion). Nullable until collection reports it.
ALTER TABLE scans ADD COLUMN IF NOT EXISTS captured_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_scans_generation ON scans(generation_id);
CREATE INDEX IF NOT EXISTS idx_scans_is_current ON scans(is_current);
CREATE INDEX IF NOT EXISTS idx_scans_coverage_status ON scans(coverage_status);

-- ---------------------------------------------------------------------------
-- findings: generation scope, detection subtype/version, typed evidence DAG,
-- confidence basis, nullable attack cost with missing-weight accounting,
-- lifecycle, rule manifest, and ATLAS mapping.
-- ---------------------------------------------------------------------------

ALTER TABLE findings ADD COLUMN IF NOT EXISTS generation_id TEXT NOT NULL DEFAULT '';

-- Detection variant + semantics version so a finding's derivation is
-- reconstructable even as detectors evolve.
ALTER TABLE findings ADD COLUMN IF NOT EXISTS detection_subtype TEXT NOT NULL DEFAULT '';
ALTER TABLE findings ADD COLUMN IF NOT EXISTS detection_version TEXT NOT NULL DEFAULT '';

-- Typed evidence DAG (observed/synthetic/reversed joins, connected
-- components) backing the finding.
ALTER TABLE findings ADD COLUMN IF NOT EXISTS evidence_dag JSONB NOT NULL DEFAULT '{}';

-- How confidence was derived (rule/match/basis), so a lexical hint cannot
-- silently present as certainty.
ALTER TABLE findings ADD COLUMN IF NOT EXISTS confidence_basis TEXT NOT NULL DEFAULT '';

-- Attack cost is NULLABLE: NULL means "unknown" (a required weight was
-- absent), never a benign zero. weight_missing_count records how many.
ALTER TABLE findings ADD COLUMN IF NOT EXISTS attack_cost DOUBLE PRECISION;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS weight_total DOUBLE PRECISION;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS weight_missing_count INT NOT NULL DEFAULT 0;

-- Finding lifecycle state (active/resolved/regressed/...). Kept as free text
-- with a default so later phases can extend the vocabulary without a schema
-- change; the authoritative set lives in the analysis layer.
ALTER TABLE findings ADD COLUMN IF NOT EXISTS lifecycle TEXT NOT NULL DEFAULT 'active';

-- Rule manifest entries that produced this finding and ATLAS technique map.
ALTER TABLE findings ADD COLUMN IF NOT EXISTS rule_manifest JSONB NOT NULL DEFAULT '[]';
ALTER TABLE findings ADD COLUMN IF NOT EXISTS atlas_map JSONB NOT NULL DEFAULT '[]';

CREATE INDEX IF NOT EXISTS idx_findings_generation ON findings(generation_id);
CREATE INDEX IF NOT EXISTS idx_findings_lifecycle ON findings(lifecycle);
