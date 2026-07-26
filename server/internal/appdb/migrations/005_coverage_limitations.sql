CREATE TABLE IF NOT EXISTS coverage_limitations (
    coverage_key        TEXT PRIMARY KEY,
    parent_coverage_key TEXT,
    state               TEXT NOT NULL
                        CHECK (state IN ('unknown', 'partial', 'failed', 'truncated')),
    scan_id             TEXT NOT NULL REFERENCES scans(id) ON DELETE RESTRICT,
    observed_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_coverage_limitations_scan_id
    ON coverage_limitations(scan_id);

CREATE INDEX IF NOT EXISTS idx_coverage_limitations_parent
    ON coverage_limitations(parent_coverage_key);

-- Before generic limited-evidence publication, only registered instruction
-- roots could publish with incomplete coverage. Preserve those active warnings
-- across upgrade so an existing limited posture cannot become a false all-clear.
INSERT INTO coverage_limitations
    (coverage_key, parent_coverage_key, state, scan_id, observed_at)
SELECT coverage_key, NULL, state, scan_id, updated_at
FROM coverage_heads
WHERE root_key IS NULL
  AND state IN ('partial', 'failed', 'truncated')
ON CONFLICT (coverage_key) DO NOTHING;
