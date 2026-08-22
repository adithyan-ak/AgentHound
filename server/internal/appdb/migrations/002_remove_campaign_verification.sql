-- Campaign verification was produced by a separate, later run. It must not be
-- relabeled as proof observed during a unified scan. Preserve the finding and
-- triage fingerprint, but return it to the conservative credential-path
-- baseline until a new same-scan proof is ingested.
UPDATE findings
SET evidence = jsonb_set(evidence - 'verification', '{state}', '"inferred"'::jsonb, true),
    confidence = LEAST(confidence, 0.6),
    severity = CASE WHEN severity = 'critical' THEN 'medium' ELSE severity END
WHERE evidence ->> 'state' = 'verified'
  AND evidence ? 'verification';
