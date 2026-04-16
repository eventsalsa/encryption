CREATE TABLE IF NOT EXISTS infrastructure.encryption_keys (
    scope TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    key_version INT NOT NULL,
    encrypted_key BYTEA NOT NULL,
    system_key_id TEXT NOT NULL DEFAULT 'default',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ,
    PRIMARY KEY (scope, scope_id, key_version),
    CONSTRAINT scope_not_empty CHECK (scope <> ''),
    CONSTRAINT scope_id_not_empty CHECK (scope_id <> ''),
    CONSTRAINT key_version_positive CHECK (key_version > 0),
    CONSTRAINT encrypted_key_not_empty CHECK (length(encrypted_key) > 0),
    CONSTRAINT system_key_id_not_empty CHECK (system_key_id <> '')
);

CREATE INDEX IF NOT EXISTS idx_encryption_keys_active
    ON infrastructure.encryption_keys(scope, scope_id, revoked_at)
    WHERE revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_encryption_keys_system_key_id
    ON infrastructure.encryption_keys(system_key_id);

CREATE INDEX IF NOT EXISTS idx_encryption_keys_scope
    ON infrastructure.encryption_keys(scope, scope_id, key_version DESC);
