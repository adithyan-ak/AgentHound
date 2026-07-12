-- 005_scan_scope.sql
--
-- Second phase of the truthfulness contract reset. Adds an explicit generation
-- SCOPE key to scans, decoupled from the display `collector` column.
--
-- Motivation: the current-generation pointer, coverage-aware retention, and the
-- rematerializing delete are all keyed on a "comparable scope". Previously that
-- scope was `collector`, but a merged `agenthound scan` bundle and a network
-- scan BOTH carry collector = 'scan', so a network sweep of remote hosts shared
-- a scope with a local-host bundle and could demote/retire the other's facts.
-- The `scope` column lets the pipeline discriminate local vs network (and any
-- future scope split) without overloading the human-facing collector name.
--
-- Prelaunch policy: additive column with a safe default; existing rows are
-- backfilled to their collector so the scope-keyed reads keep working on a
-- database that predates this migration (a full reset/re-ingest repopulates
-- the discriminated scope from the pipeline).

ALTER TABLE scans ADD COLUMN IF NOT EXISTS scope TEXT NOT NULL DEFAULT '';

-- Backfill: an unscoped row adopts its collector as its scope, matching the
-- pre-migration behaviour (scope == collector) for single-collector artifacts.
UPDATE scans SET scope = collector WHERE scope = '';

CREATE INDEX IF NOT EXISTS idx_scans_scope ON scans(scope);
CREATE INDEX IF NOT EXISTS idx_scans_scope_current ON scans(scope, is_current);
