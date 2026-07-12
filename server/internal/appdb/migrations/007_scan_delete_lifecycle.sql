-- 007_scan_delete_lifecycle.sql
--
-- Durable, recoverable scan deletion. A scan delete mutates BOTH Neo4j (remove
-- the generation's graph observations) and Postgres (drop the finding snapshot
-- and the scan row). Without a persisted intent, an interruption between the
-- two stores leaves an inconsistent, unrecoverable state (graph gone, row
-- present, or vice versa).
--
-- This column records the deletion lifecycle so an interrupted delete is
-- recoverable by an idempotent retry:
--   ''             — not being deleted (normal).
--   'deleting'     — a delete is in progress. Persisted BEFORE the Neo4j graph
--                    mutation, so a crash mid-delete leaves this marker and the
--                    delete can be resumed idempotently.
--   'delete_failed'— a delete attempt errored; retryable.
--
-- A recovery sweep (RecoverPendingDeletes) resumes any scan left in
-- 'deleting'/'delete_failed' at startup, so the current-generation pointer is
-- only exposed once the delete is durably complete.

ALTER TABLE scans ADD COLUMN IF NOT EXISTS delete_state TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_scans_delete_state ON scans(delete_state)
  WHERE delete_state <> '';
