-- 008_atlas_rules_compat.sql
--
-- Backfill the deterministic MITRE ATLAS mappings that were added to new
-- finding snapshots in migration 004. Existing installations already applied
-- 004 with an empty-array default, so altering the column alone could not
-- recover mappings for their historical rows.
--
-- Non-empty mappings are preserved: they are persisted evidence and must not
-- be overwritten by a later software version. Effective rule manifests remain
-- additive JSONB scan metadata, so their canonical matcher definitions and
-- load failures require no destructive schema rewrite.

ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS atlas_map JSONB NOT NULL DEFAULT '[]';

UPDATE findings
SET atlas_map = CASE edge_kind
    WHEN 'CAN_EXFILTRATE_VIA' THEN '["AML.T0086"]'::jsonb
    WHEN 'POISONED_DESCRIPTION' THEN '["AML.T0051","AML.T0110"]'::jsonb
    WHEN 'SHADOWS' THEN '["AML.T0110"]'::jsonb
    WHEN 'POISONED_INSTRUCTIONS' THEN '["AML.T0051"]'::jsonb
    WHEN 'TAINTS' THEN '["AML.T0051"]'::jsonb
    WHEN 'IFC_VIOLATION' THEN '["AML.T0057","AML.T0086"]'::jsonb
    WHEN 'POISONS_CONTEXT' THEN '["AML.T0051","AML.T0110"]'::jsonb
    ELSE atlas_map
END
WHERE atlas_map = '[]'::jsonb
   OR atlas_map = 'null'::jsonb;
