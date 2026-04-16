// Package testutil provides test helpers for encryption testing.
package testutil

import (
	"context"
	"crypto/rand"
	"sync"
	"time"

	"github.com/eventsalsa/encryption"
	"github.com/eventsalsa/encryption/keystore"
	"github.com/eventsalsa/encryption/systemkey"
)

// NewTestKeyring creates an in-memory keyring with a random 32-byte test key.
// The active key ID is "test-key-1".
func NewTestKeyring() systemkey.Keyring {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic("testutil: generate random key: " + err.Error())
	}
	return systemkey.NewKeyring(map[string][]byte{"test-key-1": key}, "test-key-1")
}

// InMemoryKeyStore implements keystore.KeyStore using an in-memory map.
// Safe for concurrent use. Intended for unit testing only.
type InMemoryKeyStore struct {
	mu   sync.RWMutex
	keys map[string][]keystore.EncryptedKey // keyed by "scope:scopeID"
}

// NewInMemoryKeyStore creates a new in-memory key store.
func NewInMemoryKeyStore() *InMemoryKeyStore {
	return &InMemoryKeyStore{
		keys: make(map[string][]keystore.EncryptedKey),
	}
}

func bucketKey(scope, scopeID string) string { return scope + ":" + scopeID }

// GetActiveKey returns the latest non-revoked key by highest KeyVersion.
func (s *InMemoryKeyStore) GetActiveKey(_ context.Context, scope, scopeID string) (*keystore.EncryptedKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var best *keystore.EncryptedKey
	for i := range s.keys[bucketKey(scope, scopeID)] {
		k := &s.keys[bucketKey(scope, scopeID)][i]
		if k.RevokedAt != nil {
			continue
		}
		if best == nil || k.KeyVersion > best.KeyVersion {
			best = k
		}
	}
	if best == nil {
		return nil, encryption.ErrKeyNotFound
	}
	out := *best
	return &out, nil
}

// GetKey returns the key with the exact version.
func (s *InMemoryKeyStore) GetKey(_ context.Context, scope, scopeID string, version int) (*keystore.EncryptedKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for i := range s.keys[bucketKey(scope, scopeID)] {
		k := &s.keys[bucketKey(scope, scopeID)][i]
		if k.KeyVersion == version {
			out := *k
			return &out, nil
		}
	}
	return nil, encryption.ErrKeyNotFound
}

// CreateKey appends a new EncryptedKey to the store.
func (s *InMemoryKeyStore) CreateKey(_ context.Context, scope, scopeID string, version int, encryptedDEK []byte, systemKeyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	bk := bucketKey(scope, scopeID)
	s.keys[bk] = append(s.keys[bk], keystore.EncryptedKey{
		Scope:        scope,
		ScopeID:      scopeID,
		KeyVersion:   version,
		EncryptedDEK: encryptedDEK,
		SystemKeyID:  systemKeyID,
		CreatedAt:    time.Now(),
	})
	return nil
}

// RevokeKeys marks all non-revoked keys for scope:scopeID as revoked,
// except the one with the highest version (the active key).
func (s *InMemoryKeyStore) RevokeKeys(_ context.Context, scope, scopeID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	bk := bucketKey(scope, scopeID)
	// Find the highest version so we can skip it.
	maxVer := -1
	for i := range s.keys[bk] {
		if s.keys[bk][i].KeyVersion > maxVer {
			maxVer = s.keys[bk][i].KeyVersion
		}
	}
	now := time.Now()
	for i := range s.keys[bk] {
		if s.keys[bk][i].RevokedAt == nil && s.keys[bk][i].KeyVersion < maxVer {
			s.keys[bk][i].RevokedAt = &now
		}
	}
	return nil
}

// DestroyKeys removes all keys for scope:scopeID.
func (s *InMemoryKeyStore) DestroyKeys(_ context.Context, scope, scopeID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.keys, bucketKey(scope, scopeID))
	return nil
}
