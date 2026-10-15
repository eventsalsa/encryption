CREATE TABLE IF NOT EXISTS infrastructure.encryption_keys (
    scope TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    key_version INT NOT NULL,
    encrypted_dek BYTEA NOT NULL,
    kek_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ,
    PRIMARY KEY (scope, scope_id, key_version),
    CONSTRAINT scope_not_empty CHECK (scope <> ''),
    CONSTRAINT scope_id_not_empty CHECK (scope_id <> ''),
    CONSTRAINT key_version_positive CHECK (key_version > 0),
    CONSTRAINT encrypted_dek_not_empty CHECK (length(encrypted_dek) > 0),
    CONSTRAINT kek_id_not_empty CHECK (kek_id <> ''),
    CONSTRAINT revoked_after_created CHECK (revoked_at IS NULL OR revoked_at >= created_at)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_encryption_keys_active
    ON infrastructure.encryption_keys(scope, scope_id)
    WHERE revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_encryption_keys_kek_id
    ON infrastructure.encryption_keys(kek_id, scope, scope_id, key_version);
