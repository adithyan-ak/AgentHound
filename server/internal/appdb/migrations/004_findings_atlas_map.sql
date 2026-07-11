-- 004_findings_atlas_map.sql
--
-- AH-UI-32: persist each finding's MITRE ATLAS technique mapping alongside its
-- OWASP mapping. Live finding detail already computes atlas_map, but the
-- persisted per-scan snapshot dropped it, so finding lists and selected-finding
-- exports lost ATLAS provenance and disagreed with live detail.
--
-- Additive and backward-compatible: existing rows default to an empty array,
-- matching the Go `[]string{}` normalization used for owasp_map.

ALTER TABLE findings ADD COLUMN IF NOT EXISTS atlas_map JSONB NOT NULL DEFAULT '[]';
