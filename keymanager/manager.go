// Package keymanager orchestrates DEK lifecycle operations using envelope encryption.
package keymanager

import (
	"context"
	"errors"
	"fmt"

	encryption "github.com/eventsalsa/encryption/encerr"
	"github.com/eventsalsa/encryption/envelope"
	"github.com/eventsalsa/encryption/keystore"
	"github.com/eventsalsa/encryption/keystore/postgres"
)

// KeyStore persists and retrieves encrypted DEKs.
type KeyStore interface {
	GetActiveKey(ctx context.Context, conn postgres.PgxConn, scope, scopeID string) (*keystore.EncryptedKey, error)
	GetKey(ctx context.Context, conn postgres.PgxConn, scope, scopeID string, version int) (*keystore.EncryptedKey, error)
	CreateKey(ctx context.Context, conn postgres.PgxConn, scope, scopeID string, version int, encryptedDEK []byte, systemKeyID string) error
	RevokeKeys(ctx context.Context, conn postgres.PgxConn, scope, scopeID string) error
	DestroyKeys(ctx context.Context, conn postgres.PgxConn, scope, scopeID string) error
}

// Manager coordinates DEK creation, rotation, revocation, and destruction.
// It is a stateless singleton that delegates crypto to envelope.Envelope and persistence to KeyStore.
type Manager struct {
	store KeyStore
	env   *envelope.Envelope
}

// New returns a Manager wired to the given key store and envelope engine.
func New(store KeyStore, env *envelope.Envelope) *Manager {
	return &Manager{store: store, env: env}
}

// CreateKey generates a new DEK for the given scope, wraps it with the
// active system key, and stores it at version 1. Returns ErrKeyExists if the
// scope already has an active key.
func (m *Manager) CreateKey(ctx context.Context, conn postgres.PgxConn, scope, scopeID string) (int, error) {
	_, err := m.store.GetActiveKey(ctx, conn, scope, scopeID)
	if err == nil {
		return 0, encryption.ErrKeyExists
	}
	if !errors.Is(err, encryption.ErrKeyNotFound) {
		return 0, fmt.Errorf("keymanager: check existing key: %w", err)
	}

	dek, err := m.env.GenerateDEK()
	if err != nil {
		return 0, fmt.Errorf("keymanager: generate DEK: %w", err)
	}
	defer encryption.ZeroBytes(dek)

	sysKeyID := m.env.ActiveKeyID()
	encDEK, err := m.env.WrapDEK(sysKeyID, dek)
	if err != nil {
		return 0, fmt.Errorf("keymanager: wrap DEK: %w", err)
	}

	const version = 1
	if err := m.store.CreateKey(ctx, conn, scope, scopeID, version, encDEK, sysKeyID); err != nil {
		return 0, fmt.Errorf("keymanager: store DEK: %w", err)
	}

	return version, nil
}

// RotateKey generates a new DEK, wraps it, stores it at the next version,
// and revokes all previous versions. Returns ErrKeyNotFound if no active key exists.
func (m *Manager) RotateKey(ctx context.Context, conn postgres.PgxConn, scope, scopeID string) (int, error) {
	current, err := m.store.GetActiveKey(ctx, conn, scope, scopeID)
	if err != nil {
		return 0, fmt.Errorf("keymanager: get current key: %w", err)
	}

	dek, err := m.env.GenerateDEK()
	if err != nil {
		return 0, fmt.Errorf("keymanager: generate DEK: %w", err)
	}
	defer encryption.ZeroBytes(dek)

	sysKeyID := m.env.ActiveKeyID()
	encDEK, err := m.env.WrapDEK(sysKeyID, dek)
	if err != nil {
		return 0, fmt.Errorf("keymanager: wrap rotated DEK: %w", err)
	}

	newVersion := current.KeyVersion + 1
	if err := m.store.CreateKey(ctx, conn, scope, scopeID, newVersion, encDEK, sysKeyID); err != nil {
		return 0, fmt.Errorf("keymanager: store rotated DEK: %w", err)
	}

	if err := m.store.RevokeKeys(ctx, conn, scope, scopeID); err != nil {
		return 0, fmt.Errorf("keymanager: revoke old keys: %w", err)
	}

	return newVersion, nil
}

// RevokeKeys marks all keys for the scope as revoked, except the highest version.
// Use DestroyKeys to permanently remove all keys including the active one.
func (m *Manager) RevokeKeys(ctx context.Context, conn postgres.PgxConn, scope, scopeID string) error {
	return m.store.RevokeKeys(ctx, conn, scope, scopeID)
}

// DestroyKeys permanently removes all keys for the scope.
func (m *Manager) DestroyKeys(ctx context.Context, conn postgres.PgxConn, scope, scopeID string) error {
	return m.store.DestroyKeys(ctx, conn, scope, scopeID)
}

// ActiveKeyVersion returns the version number of the active key for the scope.
func (m *Manager) ActiveKeyVersion(ctx context.Context, conn postgres.PgxConn, scope, scopeID string) (int, error) {
	k, err := m.store.GetActiveKey(ctx, conn, scope, scopeID)
	if err != nil {
		return 0, err
	}
	return k.KeyVersion, nil
}
