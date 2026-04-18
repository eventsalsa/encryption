package postgres

import (
	"context"
	"database/sql"
	"fmt"

	encryption "github.com/eventsalsa/encryption/encerr"
	"github.com/eventsalsa/encryption/keystore"
)

// queryable is satisfied by both *sql.DB and *sql.Tx.
type queryable interface {
	QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row
	ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error)
}

// TxExtractor extracts a *sql.Tx from context. Return nil if no tx is active.
// Used by consumers with their own transaction-propagation mechanism
// (e.g., Unit of Work, CQRS middleware).
type TxExtractor func(ctx context.Context) *sql.Tx

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

// Store implements keystore.KeyStore backed by PostgreSQL.
type Store struct {
	cfg     Config
	db      *sql.DB
	extract TxExtractor
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

// NewStore creates a new PostgreSQL-backed keystore with the given config.
// Empty Schema defaults to "infrastructure"; empty Table defaults to "encryption_keys".
// Reads use the connection pool. Writes auto-commit via *sql.DB.
// Use keystore.WithTx(ctx, tx) to opt into transaction participation.
func NewStore(cfg Config, db *sql.DB) *Store {
	return &Store{cfg: ApplyDefaults(cfg), db: db}
}

// NewStoreWithTxExtractor creates a store with a custom tx extractor.
// Resolution order: custom extractor → library's keystore.WithTx → *sql.DB.
//
// Use this for Unit of Work patterns where *sql.Tx lives under your
// own context key rather than the library's keystore.WithTx key.
func NewStoreWithTxExtractor(cfg Config, db *sql.DB, extract TxExtractor) *Store {
	return &Store{cfg: ApplyDefaults(cfg), db: db, extract: extract}
}

// conn resolves the active database handle for this context.
func (s *Store) conn(ctx context.Context) queryable {
	if s.extract != nil {
		if tx := s.extract(ctx); tx != nil {
			return tx
		}
	}
	if tx := keystore.TxFromContext(ctx); tx != nil {
		return tx
	}
	return s.db
}

// fqtn returns the fully qualified table name (schema.table).
func (s *Store) fqtn() string {
	return fmt.Sprintf("%s.%s", s.cfg.Schema, s.cfg.Table)
}

// GetActiveKey returns the highest-version non-revoked key for the given scope.
func (s *Store) GetActiveKey(ctx context.Context, scope, scopeID string) (*keystore.EncryptedKey, error) {
	query := fmt.Sprintf(`SELECT scope, scope_id, key_version, encrypted_key, system_key_id, created_at, revoked_at
		FROM %s
		WHERE scope = $1 AND scope_id = $2 AND revoked_at IS NULL
		ORDER BY key_version DESC
		LIMIT 1`, s.fqtn())

	var k keystore.EncryptedKey
	err := s.conn(ctx).QueryRowContext(ctx, query, scope, scopeID).Scan(
		&k.Scope, &k.ScopeID, &k.KeyVersion, &k.EncryptedDEK,
		&k.SystemKeyID, &k.CreatedAt, &k.RevokedAt,
	)
	if err == sql.ErrNoRows {
		return nil, encryption.ErrKeyNotFound
	}
	if err != nil {
		return nil, err
	}
	return &k, nil
}

// GetKey returns a specific key version for the given scope.
func (s *Store) GetKey(ctx context.Context, scope, scopeID string, version int) (*keystore.EncryptedKey, error) {
	query := fmt.Sprintf(`SELECT scope, scope_id, key_version, encrypted_key, system_key_id, created_at, revoked_at
		FROM %s
		WHERE scope = $1 AND scope_id = $2 AND key_version = $3`, s.fqtn())

	var k keystore.EncryptedKey
	err := s.conn(ctx).QueryRowContext(ctx, query, scope, scopeID, version).Scan(
		&k.Scope, &k.ScopeID, &k.KeyVersion, &k.EncryptedDEK,
		&k.SystemKeyID, &k.CreatedAt, &k.RevokedAt,
	)
	if err == sql.ErrNoRows {
		return nil, encryption.ErrKeyNotFound
	}
	if err != nil {
		return nil, err
	}
	return &k, nil
}

// CreateKey inserts a new encrypted DEK into the keystore.
func (s *Store) CreateKey(ctx context.Context, scope, scopeID string, version int, encryptedDEK []byte, systemKeyID string) error {
	query := fmt.Sprintf(`INSERT INTO %s (scope, scope_id, key_version, encrypted_key, system_key_id)
		VALUES ($1, $2, $3, $4, $5)`, s.fqtn())

	_, err := s.conn(ctx).ExecContext(ctx, query, scope, scopeID, version, encryptedDEK, systemKeyID)
	return err
}

// RevokeKeys marks all active keys for the given scope as revoked,
// except the highest version (the current active key).
// Use DestroyKeys to permanently remove all keys including the active one.
func (s *Store) RevokeKeys(ctx context.Context, scope, scopeID string) error {
	fqtn := s.fqtn()
	query := fmt.Sprintf(`UPDATE %s SET revoked_at = NOW()
		WHERE scope = $1 AND scope_id = $2 AND revoked_at IS NULL
		AND key_version < (
			SELECT MAX(key_version) FROM %s
			WHERE scope = $1 AND scope_id = $2
		)`, fqtn, fqtn)

	_, err := s.conn(ctx).ExecContext(ctx, query, scope, scopeID)
	return err
}

// DestroyKeys permanently deletes all keys for the given scope.
func (s *Store) DestroyKeys(ctx context.Context, scope, scopeID string) error {
	query := fmt.Sprintf(`DELETE FROM %s
		WHERE scope = $1 AND scope_id = $2`, s.fqtn())

	_, err := s.conn(ctx).ExecContext(ctx, query, scope, scopeID)
	return err
}
