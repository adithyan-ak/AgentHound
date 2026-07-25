ALTER TABLE coverage_heads
    ADD COLUMN IF NOT EXISTS state TEXT,
    ADD COLUMN IF NOT EXISTS discovery_mode TEXT,
    ADD COLUMN IF NOT EXISTS contract_generation INTEGER,
    ADD COLUMN IF NOT EXISTS contract_digest TEXT;

ALTER TABLE coverage_heads
    DROP CONSTRAINT IF EXISTS coverage_heads_root_state_check,
    ADD CONSTRAINT coverage_heads_root_state_check
        CHECK (state IS NULL OR state IN ('complete', 'truncated'));

ALTER TABLE coverage_heads
    DROP CONSTRAINT IF EXISTS coverage_heads_discovery_mode_check,
    ADD CONSTRAINT coverage_heads_discovery_mode_check
        CHECK (
            discovery_mode IS NULL OR
            discovery_mode IN ('exact_user', 'exact_project', 'deep')
        );

ALTER TABLE coverage_heads
    DROP CONSTRAINT IF EXISTS coverage_heads_contract_pair_check,
    ADD CONSTRAINT coverage_heads_contract_pair_check
        CHECK (
            (contract_generation IS NULL AND contract_digest IS NULL) OR
            (
                contract_generation IS NOT NULL AND
                contract_generation > 0 AND
                contract_digest IS NOT NULL AND
                contract_digest <> ''
            )
        );

ALTER TABLE coverage_heads
    DROP CONSTRAINT IF EXISTS coverage_heads_root_metadata_check,
    ADD CONSTRAINT coverage_heads_root_metadata_check
        CHECK (
            root_key IS NULL OR
            (
                state IS NULL AND
                discovery_mode IS NULL AND
                contract_generation IS NULL AND
                contract_digest IS NULL
            )
        );
