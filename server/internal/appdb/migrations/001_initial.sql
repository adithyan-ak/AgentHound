CREATE TABLE IF NOT EXISTS schema_migrations (
    version     INT PRIMARY KEY,
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS scans (
    id                       TEXT PRIMARY KEY,
    collector                TEXT NOT NULL,
    status                   TEXT NOT NULL DEFAULT 'pending',
    started_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at             TIMESTAMPTZ,
    node_write_rows          INT NOT NULL DEFAULT 0,
    edge_write_rows          INT NOT NULL DEFAULT 0,
    error                    TEXT,
    metadata                 JSONB NOT NULL DEFAULT '{}',
    artifact_observed_at     TIMESTAMPTZ,
    collection_status        TEXT NOT NULL DEFAULT 'unknown',
    graph_status             TEXT NOT NULL DEFAULT 'unknown',
    analysis_status          TEXT NOT NULL DEFAULT 'unknown',
    snapshot_status          TEXT NOT NULL DEFAULT 'unknown',
    projection_status        TEXT NOT NULL DEFAULT 'unknown',
    publication_status       TEXT NOT NULL DEFAULT 'unpublished',
    comparison_key           TEXT,
    graph_total_nodes_before BIGINT,
    graph_total_edges_before BIGINT,
    graph_total_nodes_after  BIGINT,
    graph_total_edges_after  BIGINT,
    comparable_to_scan_id    TEXT,
    published_revision       BIGINT,
    published_at             TIMESTAMPTZ,
    lifecycle_updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scans_collector ON scans(collector);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);

CREATE TABLE IF NOT EXISTS findings (
    scan_id        TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    fingerprint    CHAR(16) NOT NULL,
    severity       TEXT NOT NULL DEFAULT '',
    category       TEXT NOT NULL DEFAULT '',
    title          TEXT NOT NULL DEFAULT '',
    description    TEXT NOT NULL DEFAULT '',
    edge_kind      TEXT NOT NULL DEFAULT '',
    source_id      TEXT NOT NULL DEFAULT '',
    source_name    TEXT NOT NULL DEFAULT '',
    source_kind    TEXT NOT NULL DEFAULT '',
    target_id      TEXT NOT NULL DEFAULT '',
    target_name    TEXT NOT NULL DEFAULT '',
    target_kind    TEXT NOT NULL DEFAULT '',
    confidence     DOUBLE PRECISION NOT NULL DEFAULT 0,
    owasp_map      JSONB NOT NULL DEFAULT '[]',
    atlas_map      JSONB NOT NULL DEFAULT '[]',
    variant        TEXT NOT NULL DEFAULT 'unknown',
    evidence       JSONB NOT NULL DEFAULT '{"state":"unknown"}',
    exact_evidence JSONB,
    cross_protocol BOOLEAN NOT NULL DEFAULT FALSE,
    captured_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (scan_id, fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(fingerprint);
CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_edge_kind ON findings(edge_kind);

CREATE TABLE IF NOT EXISTS finding_triage (
    fingerprint CHAR(16) PRIMARY KEY,
    status      TEXT NOT NULL DEFAULT 'new'
                CHECK (status IN ('new','triaging','confirmed','accepted-risk','false-positive')),
    note        TEXT NOT NULL DEFAULT '',
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS coverage_heads (
    coverage_key TEXT PRIMARY KEY,
    scan_id      TEXT NOT NULL REFERENCES scans(id) ON DELETE RESTRICT,
    root_key     TEXT,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_coverage_heads_scan_id
    ON coverage_heads(scan_id);
CREATE INDEX IF NOT EXISTS idx_coverage_heads_root_key
    ON coverage_heads(root_key);

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
    singleton             BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    projection_status     TEXT NOT NULL DEFAULT 'unknown',
    projection_scan_id    TEXT,
    projection_error      TEXT,
    dirty_coverage        JSONB NOT NULL DEFAULT '[]',
    projection_updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    published_revision    BIGINT REFERENCES posture_publications(revision) ON DELETE SET NULL,
    published_scan_id     TEXT REFERENCES scans(id) ON DELETE RESTRICT,
    published_at          TIMESTAMPTZ
);

INSERT INTO posture_state (singleton)
VALUES (TRUE)
ON CONFLICT (singleton) DO NOTHING;
