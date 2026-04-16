// Package keymanager orchestrates DEK lifecycle operations using envelope encryption.
package keymanager

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/eventsalsa/encryption/cipher"
	encryption "github.com/eventsalsa/encryption/encerr"
	"github.com/eventsalsa/encryption/keystore"
	"github.com/eventsalsa/encryption/systemkey"
)

// Manager coordinates DEK creation, rotation, revocation, and destruction.
type Manager struct {
	keyring systemkey.Keyring
	store   keystore.KeyStore
	cipher  cipher.Cipher
}

// New returns a Manager wired to the given keyring, store, and cipher.
func New(keyring systemkey.Keyring, store keystore.KeyStore, c cipher.Cipher) *Manager {
	return &Manager{keyring: keyring, store: store, cipher: c}
}

// CreateKey generates a new DEK for the given scope, encrypts it with the
// active system key, and stores it at version 1. Returns ErrKeyExists if the
// scope already has an active key.
func (m *Manager) CreateKey(ctx context.Context, scope, scopeID string) (int, error) {
	_, err := m.store.GetActiveKey(ctx, scope, scopeID)
	if err == nil {
		return 0, encryption.ErrKeyExists
	}
	if !errors.Is(err, encryption.ErrKeyNotFound) {
		return 0, fmt.Errorf("keymanager: check existing key: %w", err)
	}

	dek := make([]byte, m.cipher.KeySize())
	defer encryption.ZeroBytes(dek)

	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return 0, fmt.Errorf("keymanager: generate DEK: %w", err)
	}

	sysKey, sysKeyID := m.keyring.ActiveKey()

	encDEK, err := m.cipher.Encrypt(sysKey, dek)
	if err != nil {
		return 0, fmt.Errorf("keymanager: encrypt DEK: %w", err)
	}

	const version = 1
	if err := m.store.CreateKey(ctx, scope, scopeID, version, encDEK, sysKeyID); err != nil {
		return 0, fmt.Errorf("keymanager: store DEK: %w", err)
	}

	return version, nil
}

// RotateKey generates a new DEK, encrypts it, stores it at the next version,
// and revokes all previous versions. Returns ErrKeyNotFound if no active key exists.
func (m *Manager) RotateKey(ctx context.Context, scope, scopeID string) (int, error) {
	current, err := m.store.GetActiveKey(ctx, scope, scopeID)
	if err != nil {
		return 0, fmt.Errorf("keymanager: get current key: %w", err)
	}

	dek := make([]byte, m.cipher.KeySize())
	defer encryption.ZeroBytes(dek)

	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return 0, fmt.Errorf("keymanager: generate DEK: %w", err)
	}

	sysKey, sysKeyID := m.keyring.ActiveKey()

	encDEK, err := m.cipher.Encrypt(sysKey, dek)
	if err != nil {
		return 0, fmt.Errorf("keymanager: encrypt DEK: %w", err)
	}

	newVersion := current.KeyVersion + 1
	if err := m.store.CreateKey(ctx, scope, scopeID, newVersion, encDEK, sysKeyID); err != nil {
		return 0, fmt.Errorf("keymanager: store rotated DEK: %w", err)
	}

	if err := m.store.RevokeKeys(ctx, scope, scopeID); err != nil {
		return 0, fmt.Errorf("keymanager: revoke old keys: %w", err)
	}

	return newVersion, nil
}

// RevokeKeys marks all keys for the scope as revoked, except the highest version.
// Use DestroyKeys to permanently remove all keys including the active one.
func (m *Manager) RevokeKeys(ctx context.Context, scope, scopeID string) error {
	return m.store.RevokeKeys(ctx, scope, scopeID)
}

// DestroyKeys permanently removes all keys for the scope.
func (m *Manager) DestroyKeys(ctx context.Context, scope, scopeID string) error {
	return m.store.DestroyKeys(ctx, scope, scopeID)
}

// ActiveKeyVersion returns the version number of the active key for the scope.
func (m *Manager) ActiveKeyVersion(ctx context.Context, scope, scopeID string) (int, error) {
	k, err := m.store.GetActiveKey(ctx, scope, scopeID)
	if err != nil {
		return 0, err
	}
	return k.KeyVersion, nil
}
