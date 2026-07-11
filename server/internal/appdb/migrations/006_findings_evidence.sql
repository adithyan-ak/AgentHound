-- 006_findings_evidence.sql
--
-- Persist the exact finding classification used at publication time. Legacy
-- rows cannot be safely reclassified from a later mutable graph, so both
-- fields default to explicit unknown evidence.

ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS variant TEXT NOT NULL DEFAULT 'unknown',
    ADD COLUMN IF NOT EXISTS evidence JSONB NOT NULL DEFAULT '{"state":"unknown"}';
