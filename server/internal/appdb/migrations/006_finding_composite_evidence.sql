-- Persist the exact composite-edge properties used to derive finding impact.
-- Detail must remain independent of mutable/live Neo4j after the occurrence
-- snapshot is written.
ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS composite_props JSONB NOT NULL DEFAULT '{}';
