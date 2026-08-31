package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/eventsalsa/encryption"
	"github.com/eventsalsa/encryption/envelope"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// pgxConn represents any pgx database executor (*pgxpool.Pool, pgx.Tx, *pgx.Conn).
// It is strictly unexported to prevent leaking database abstraction details.
type pgxConn interface {
	Query(ctx context.Context, query string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, query string, args ...any) pgx.Row
	Exec(ctx context.Context, query string, args ...any) (pgconn.CommandTag, error)
}

// EncryptedKey represents a stored encrypted DEK in PostgreSQL.
type EncryptedKey struct {
	Scope        string
	ScopeID      string
	KeyVersion   int
	EncryptedDEK []byte
	SystemKeyID  string
	CreatedAt    time.Time
	RevokedAt    *time.Time
}

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

// Store coordinates DEK generation, wrapping, and persistence in PostgreSQL.
// It is a stateless service; all database operations require an explicit pgx connection.
type Store struct {
	env *envelope.Envelope
	cfg Config
}

// NewStore creates a new PostgreSQL keystore wired to the given envelope crypto engine.
func NewStore(env *envelope.Envelope, cfg Config) *Store {
	if env == nil {
		panic("postgres: envelope is required")
	}
	return &Store{
		env: env,
		cfg: ApplyDefaults(cfg),
	}
}

// fqtn returns the fully qualified table name (schema.table).
func (s *Store) fqtn() string {
	return fmt.Sprintf("%s.%s", s.cfg.Schema, s.cfg.Table)
}

// CreateKey generates a new DEK via envelope, wraps it with the active system key,
// and inserts it into PostgreSQL at version 1. Returns ErrKeyExists if an active key already exists.
func (s *Store) CreateKey(ctx context.Context, conn pgxConn, scope, scopeID string) (int, error) {
	_, err := s.GetActiveKey(ctx, conn, scope, scopeID)
	if err == nil {
		return 0, encryption.ErrKeyExists
	}
	if !errors.Is(err, encryption.ErrKeyNotFound) {
		return 0, fmt.Errorf("postgres create key: check existing: %w", err)
	}

	dek, err := s.env.GenerateDEK()
	if err != nil {
		return 0, fmt.Errorf("postgres create key: %w", err)
	}
	defer encryption.ZeroBytes(dek)

	sysKeyID := s.env.ActiveKeyID()
	encDEK, err := s.env.WrapDEK(sysKeyID, dek)
	if err != nil {
		return 0, fmt.Errorf("postgres create key: %w", err)
	}

	query := fmt.Sprintf(`INSERT INTO %s (scope, scope_id, key_version, encrypted_key, system_key_id)
		VALUES ($1, $2, 1, $3, $4)`, s.fqtn())

	if _, err := conn.Exec(ctx, query, scope, scopeID, encDEK, sysKeyID); err != nil {
		return 0, fmt.Errorf("postgres create key: %w", err)
	}

	return 1, nil
}

// RotateKey generates a new DEK, wraps it with the active system key,
// inserts it with version = current_active_version + 1, and revokes all older versions.
func (s *Store) RotateKey(ctx context.Context, conn pgxConn, scope, scopeID string) (int, error) {
	current, err := s.GetActiveKey(ctx, conn, scope, scopeID)
	if err != nil {
		return 0, fmt.Errorf("postgres rotate key: get active: %w", err)
	}

	dek, err := s.env.GenerateDEK()
	if err != nil {
		return 0, fmt.Errorf("postgres rotate key: %w", err)
	}
	defer encryption.ZeroBytes(dek)

	sysKeyID := s.env.ActiveKeyID()
	encDEK, err := s.env.WrapDEK(sysKeyID, dek)
	if err != nil {
		return 0, fmt.Errorf("postgres rotate key: %w", err)
	}

	nextVersion := current.KeyVersion + 1
	query := fmt.Sprintf(`INSERT INTO %s (scope, scope_id, key_version, encrypted_key, system_key_id)
		VALUES ($1, $2, $3, $4, $5)`, s.fqtn())

	if _, err := conn.Exec(ctx, query, scope, scopeID, nextVersion, encDEK, sysKeyID); err != nil {
		return 0, fmt.Errorf("postgres rotate key: insert: %w", err)
	}

	if err := s.RevokeKeys(ctx, conn, scope, scopeID); err != nil {
		return 0, fmt.Errorf("postgres rotate key: revoke older: %w", err)
	}

	return nextVersion, nil
}

// GetActiveKey returns the highest-version non-revoked key for the given scope.
func (s *Store) GetActiveKey(ctx context.Context, conn pgxConn, scope, scopeID string) (*EncryptedKey, error) {
	query := fmt.Sprintf(`SELECT scope, scope_id, key_version, encrypted_key, system_key_id, created_at, revoked_at
		FROM %s
		WHERE scope = $1 AND scope_id = $2 AND revoked_at IS NULL
		ORDER BY key_version DESC
		LIMIT 1`, s.fqtn())

	var k EncryptedKey
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

// GetKey returns a specific key version for the given scope.
func (s *Store) GetKey(ctx context.Context, conn pgxConn, scope, scopeID string, version int) (*EncryptedKey, error) {
	query := fmt.Sprintf(`SELECT scope, scope_id, key_version, encrypted_key, system_key_id, created_at, revoked_at
		FROM %s
		WHERE scope = $1 AND scope_id = $2 AND key_version = $3`, s.fqtn())

	var k EncryptedKey
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

// RevokeKeys marks all active keys for the given scope as revoked,
// except the highest version (the current active key).
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

// DestroyKeys permanently deletes all keys for the given scope (GDPR crypto-shredding).
func (s *Store) DestroyKeys(ctx context.Context, conn pgxConn, scope, scopeID string) error {
	query := fmt.Sprintf(`DELETE FROM %s
		WHERE scope = $1 AND scope_id = $2`, s.fqtn())

	_, err := conn.Exec(ctx, query, scope, scopeID)
	return err
}

// ActiveKeyVersion returns the version number of the active key for the given scope.
func (s *Store) ActiveKeyVersion(ctx context.Context, conn pgxConn, scope, scopeID string) (int, error) {
	k, err := s.GetActiveKey(ctx, conn, scope, scopeID)
	if err != nil {
		return 0, err
	}
	return k.KeyVersion, nil
}
