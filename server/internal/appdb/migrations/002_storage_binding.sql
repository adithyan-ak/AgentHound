CREATE TABLE IF NOT EXISTS storage_binding (
    singleton          BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    binding_version    SMALLINT NOT NULL,
    storage_pair_id    UUID NOT NULL,
    host_id            TEXT NOT NULL,
    network_realm_id   TEXT NOT NULL,
    realm_sha256       CHAR(64) NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
