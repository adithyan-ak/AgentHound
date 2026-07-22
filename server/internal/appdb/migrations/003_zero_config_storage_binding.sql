ALTER TABLE storage_binding DROP COLUMN IF EXISTS host_id;
ALTER TABLE storage_binding DROP COLUMN IF EXISTS network_realm_id;
ALTER TABLE storage_binding DROP COLUMN IF EXISTS realm_sha256;

CREATE TABLE IF NOT EXISTS coverage_memberships (
    coverage_key TEXT PRIMARY KEY,
    parent_key   TEXT NOT NULL,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_coverage_memberships_parent_key
    ON coverage_memberships(parent_key);
