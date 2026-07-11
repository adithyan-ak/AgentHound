-- 007_exact_finding_evidence.sql
--
-- Freeze the exact detector-selected witness graph with each finding. Rows
-- created before this migration have no recoverable witness: a later mutable
-- Neo4j projection cannot safely backfill it.

ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS exact_evidence JSONB;

-- Older releases used positional templates that could assign a target name to
-- the source/tool role. Replace those persisted descriptions with conservative
-- actor-labelled text. Do not infer a channel or capability that the legacy row
-- did not retain.
UPDATE findings
SET description = format(
    'Legacy finding: source %s (%s) and target %s (%s) matched detector %s; predicate-specific witness evidence was not retained.',
    COALESCE(NULLIF(source_name, ''), NULLIF(source_id, ''), 'unknown'),
    COALESCE(NULLIF(source_kind, ''), 'unknown kind'),
    COALESCE(NULLIF(target_name, ''), NULLIF(target_id, ''), 'unknown'),
    COALESCE(NULLIF(target_kind, ''), 'unknown kind'),
    COALESCE(NULLIF(edge_kind, ''), 'unknown')
)
WHERE exact_evidence IS NULL;
