package postgres

import (
	"context"
	"fmt"

	encryption "github.com/eventsalsa/encryption/encerr"
	"github.com/eventsalsa/encryption/keystore"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// PgxConn represents any pgx database executor (*pgxpool.Pool, pgx.Tx, *pgx.Conn).
type PgxConn interface {
	Query(ctx context.Context, query string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, query string, args ...any) pgx.Row
	Exec(ctx context.Context, query string, args ...any) (pgconn.CommandTag, error)
}

type pgxConn = PgxConn

// Config holds the schema and table names for the PostgreSQL keystore.
type Config struct {
	Schema string
	Table  string
}

const (
	// DefaultSchema is the default PostgreSQL schema for encryption keys.
	DefaultSchema = "infrastructure"
	// DefaultTable is the default PostgreSQL table name for encryption keys.
	DefaultTable = "encryption_keys"
)

// DefaultConfig returns the default PostgreSQL keystore configuration.
func DefaultConfig() Config {
	return Config{
		Schema: DefaultSchema,
		Table:  DefaultTable,
	}
}

// Store implements keystore persistence backed by PostgreSQL using pgx.
// It is a stateless configuration struct; all operations require an explicit pgx connection.
type Store struct {
	cfg Config
}

// ApplyDefaults fills in the default schema and table names when omitted.
func ApplyDefaults(cfg Config) Config {
	if cfg.Schema == "" {
		cfg.Schema = DefaultSchema
	}
	if cfg.Table == "" {
		cfg.Table = DefaultTable
	}
	return cfg
}

// NewStore creates a new stateless PostgreSQL keystore with the given config.
func NewStore(cfg Config) *Store {
	return &Store{cfg: ApplyDefaults(cfg)}
}

// fqtn returns the fully qualified table name (schema.table).
func (s *Store) fqtn() string {
	return fmt.Sprintf("%s.%s", s.cfg.Schema, s.cfg.Table)
}

// GetActiveKey returns the highest-version non-revoked key for the given scope using the provided connection.
func (s *Store) GetActiveKey(ctx context.Context, conn pgxConn, scope, scopeID string) (*keystore.EncryptedKey, error) {
	query := fmt.Sprintf(`SELECT scope, scope_id, key_version, encrypted_key, system_key_id, created_at, revoked_at
		FROM %s
		WHERE scope = $1 AND scope_id = $2 AND revoked_at IS NULL
		ORDER BY key_version DESC
		LIMIT 1`, s.fqtn())

	var k keystore.EncryptedKey
	err := conn.QueryRow(ctx, query, scope, scopeID).Scan(
		&k.Scope, &k.ScopeID, &k.KeyVersion, &k.EncryptedDEK,
		&k.SystemKeyID, &k.CreatedAt, &k.RevokedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, encryption.ErrKeyNotFound
	}
	if err != nil {
		return nil, err
	}
	return &k, nil
}

// GetKey returns a specific key version for the given scope using the provided connection.
func (s *Store) GetKey(ctx context.Context, conn pgxConn, scope, scopeID string, version int) (*keystore.EncryptedKey, error) {
	query := fmt.Sprintf(`SELECT scope, scope_id, key_version, encrypted_key, system_key_id, created_at, revoked_at
		FROM %s
		WHERE scope = $1 AND scope_id = $2 AND key_version = $3`, s.fqtn())

	var k keystore.EncryptedKey
	err := conn.QueryRow(ctx, query, scope, scopeID, version).Scan(
		&k.Scope, &k.ScopeID, &k.KeyVersion, &k.EncryptedDEK,
		&k.SystemKeyID, &k.CreatedAt, &k.RevokedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, encryption.ErrKeyNotFound
	}
	if err != nil {
		return nil, err
	}
	return &k, nil
}

// CreateKey inserts a new encrypted DEK into the keystore using the provided connection.
func (s *Store) CreateKey(ctx context.Context, conn pgxConn, scope, scopeID string, version int, encryptedDEK []byte, systemKeyID string) error {
	query := fmt.Sprintf(`INSERT INTO %s (scope, scope_id, key_version, encrypted_key, system_key_id)
		VALUES ($1, $2, $3, $4, $5)`, s.fqtn())

	_, err := conn.Exec(ctx, query, scope, scopeID, version, encryptedDEK, systemKeyID)
	return err
}

// RevokeKeys marks all active keys for the given scope as revoked,
// except the highest version (the current active key), using the provided connection.
func (s *Store) RevokeKeys(ctx context.Context, conn pgxConn, scope, scopeID string) error {
	fqtn := s.fqtn()
	query := fmt.Sprintf(`UPDATE %s SET revoked_at = NOW()
		WHERE scope = $1 AND scope_id = $2 AND revoked_at IS NULL
		AND key_version < (
			SELECT MAX(key_version) FROM %s
			WHERE scope = $1 AND scope_id = $2
		)`, fqtn, fqtn)

	_, err := conn.Exec(ctx, query, scope, scopeID)
	return err
}

// DestroyKeys permanently deletes all keys for the given scope using the provided connection.
func (s *Store) DestroyKeys(ctx context.Context, conn pgxConn, scope, scopeID string) error {
	query := fmt.Sprintf(`DELETE FROM %s
		WHERE scope = $1 AND scope_id = $2`, s.fqtn())

	_, err := conn.Exec(ctx, query, scope, scopeID)
	return err
}
