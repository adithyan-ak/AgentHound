-- 005_projection_lifecycle.sql
--
-- Separate an ingest attempt, the mutable Neo4j projection, and the latest
-- published complete posture. Legacy rows remain explicitly unknown: the
-- migration cannot reconstruct collection coverage or graph state after the
-- fact and therefore must not backfill reassuring lifecycle claims.

ALTER TABLE scans
    ADD COLUMN IF NOT EXISTS artifact_observed_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS collection_status TEXT NOT NULL DEFAULT 'unknown',
    ADD COLUMN IF NOT EXISTS graph_status TEXT NOT NULL DEFAULT 'unknown',
    ADD COLUMN IF NOT EXISTS analysis_status TEXT NOT NULL DEFAULT 'unknown',
    ADD COLUMN IF NOT EXISTS snapshot_status TEXT NOT NULL DEFAULT 'unknown',
    ADD COLUMN IF NOT EXISTS projection_status TEXT NOT NULL DEFAULT 'unknown',
    ADD COLUMN IF NOT EXISTS publication_status TEXT NOT NULL DEFAULT 'unpublished',
    ADD COLUMN IF NOT EXISTS comparison_key TEXT,
    ADD COLUMN IF NOT EXISTS graph_total_nodes_before BIGINT,
    ADD COLUMN IF NOT EXISTS graph_total_edges_before BIGINT,
    ADD COLUMN IF NOT EXISTS graph_total_nodes_after BIGINT,
    ADD COLUMN IF NOT EXISTS graph_total_edges_after BIGINT,
    ADD COLUMN IF NOT EXISTS comparable_to_scan_id TEXT,
    ADD COLUMN IF NOT EXISTS published_revision BIGINT,
    ADD COLUMN IF NOT EXISTS published_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS lifecycle_updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

CREATE TABLE IF NOT EXISTS coverage_heads (
    coverage_key TEXT PRIMARY KEY,
    scan_id      TEXT NOT NULL REFERENCES scans(id) ON DELETE RESTRICT,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_coverage_heads_scan_id
    ON coverage_heads(scan_id);

CREATE TABLE IF NOT EXISTS posture_publications (
    revision       BIGSERIAL PRIMARY KEY,
    scan_id        TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    comparison_key TEXT,
    graph_stats     JSONB NOT NULL DEFAULT '{}',
    export          JSONB NOT NULL DEFAULT '{}',
    published_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_posture_publications_scan_id
    ON posture_publications(scan_id);
CREATE INDEX IF NOT EXISTS idx_posture_publications_comparison_key
    ON posture_publications(comparison_key, revision DESC);

CREATE TABLE IF NOT EXISTS posture_state (
    singleton           BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    projection_status   TEXT NOT NULL DEFAULT 'unknown',
    projection_scan_id  TEXT,
    projection_error    TEXT,
    dirty_coverage      JSONB NOT NULL DEFAULT '[]',
    projection_updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    published_revision  BIGINT REFERENCES posture_publications(revision) ON DELETE SET NULL,
    published_scan_id   TEXT REFERENCES scans(id) ON DELETE RESTRICT,
    published_at        TIMESTAMPTZ
);

INSERT INTO posture_state (singleton)
VALUES (TRUE)
ON CONFLICT (singleton) DO NOTHING;
