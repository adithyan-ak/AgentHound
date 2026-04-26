-- 002_remove_multiuser.sql
--
-- Two-binary split (single-user posture): drop the auth/audit tables that
-- the deleted internal/auth + internal/audit packages used.
--
-- 001_initial.sql still creates these tables; this migration drops them.
-- Net effect:
--   * fresh installs run 001 (CREATE), then 002 (DROP) — tables exist for
--     the duration of one transaction, then are gone.
--   * upgraders see 002 drop their populated tables (any users / tokens /
--     audit history is destroyed — this is documented in the release notes).
--
-- The CREATE-then-DROP pattern is intentional: 001 is preserved verbatim
-- so its history (and any prior schema_migrations row) stays consistent.

DROP TABLE IF EXISTS api_tokens;
DROP TABLE IF EXISTS audit_log;
DROP TABLE IF EXISTS users;
DROP INDEX IF EXISTS idx_audit_log_timestamp;
DROP INDEX IF EXISTS idx_audit_log_action;
