package keymanager_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	encryption "github.com/eventsalsa/encryption"
	"github.com/eventsalsa/encryption/cipher/aesgcm"
	"github.com/eventsalsa/encryption/keymanager"
	"github.com/eventsalsa/encryption/keystore"
	"github.com/eventsalsa/encryption/systemkey"
)

// mockKeyStore is an in-memory keystore for testing.
type mockKeyStore struct {
	mu   sync.Mutex
	keys map[string][]*keystore.EncryptedKey // "scope:scopeID" -> sorted by version
}

func newMockKeyStore() *mockKeyStore {
	return &mockKeyStore{keys: make(map[string][]*keystore.EncryptedKey)}
}

func keyID(scope, scopeID string) string { return scope + ":" + scopeID }

func (s *mockKeyStore) GetActiveKey(_ context.Context, scope, scopeID string) (*keystore.EncryptedKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	list := s.keys[keyID(scope, scopeID)]
	for i := len(list) - 1; i >= 0; i-- {
		if list[i].RevokedAt == nil {
			return list[i], nil
		}
	}
	return nil, encryption.ErrKeyNotFound
}

func (s *mockKeyStore) GetKey(_ context.Context, scope, scopeID string, version int) (*keystore.EncryptedKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, k := range s.keys[keyID(scope, scopeID)] {
		if k.KeyVersion == version {
			return k, nil
		}
	}
	return nil, encryption.ErrKeyNotFound
}

func (s *mockKeyStore) CreateKey(_ context.Context, scope, scopeID string, version int, encryptedDEK []byte, systemKeyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	id := keyID(scope, scopeID)
	s.keys[id] = append(s.keys[id], &keystore.EncryptedKey{
		Scope:        scope,
		ScopeID:      scopeID,
		KeyVersion:   version,
		EncryptedDEK: encryptedDEK,
		SystemKeyID:  systemKeyID,
		CreatedAt:    time.Now(),
	})
	return nil
}

func (s *mockKeyStore) RevokeKeys(_ context.Context, scope, scopeID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	id := keyID(scope, scopeID)
	list := s.keys[id]
	if len(list) == 0 {
		return nil
	}
	latest := list[len(list)-1].KeyVersion
	for _, k := range list {
		if k.KeyVersion != latest {
			k.RevokedAt = &now
		}
	}
	return nil
}

func (s *mockKeyStore) DestroyKeys(_ context.Context, scope, scopeID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.keys, keyID(scope, scopeID))
	return nil
}

func setup() (*keymanager.Manager, *mockKeyStore) {
	sysKey := make([]byte, 32)
	for i := range sysKey {
		sysKey[i] = byte(i)
	}
	keyring := systemkey.NewKeyring(map[string][]byte{"sk-1": sysKey}, "sk-1")
	store := newMockKeyStore()
	c := aesgcm.New()
	return keymanager.New(keyring, store, c), store
}

func TestCreateKey(t *testing.T) {
	mgr, _ := setup()
	ctx := context.Background()

	version, err := mgr.CreateKey(ctx, "user", "u-1")
	if err != nil {
		t.Fatalf("CreateKey: unexpected error: %v", err)
	}
	if version != 1 {
		t.Fatalf("CreateKey: expected version 1, got %d", version)
	}
}

func TestCreateKeyExists(t *testing.T) {
	mgr, _ := setup()
	ctx := context.Background()

	if _, err := mgr.CreateKey(ctx, "user", "u-1"); err != nil {
		t.Fatalf("first CreateKey: %v", err)
	}

	_, err := mgr.CreateKey(ctx, "user", "u-1")
	if !errors.Is(err, encryption.ErrKeyExists) {
		t.Fatalf("second CreateKey: expected ErrKeyExists, got %v", err)
	}
}

func TestRotateKey(t *testing.T) {
	mgr, store := setup()
	ctx := context.Background()

	if _, err := mgr.CreateKey(ctx, "user", "u-1"); err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	version, err := mgr.RotateKey(ctx, "user", "u-1")
	if err != nil {
		t.Fatalf("RotateKey: unexpected error: %v", err)
	}
	if version != 2 {
		t.Fatalf("RotateKey: expected version 2, got %d", version)
	}

	store.mu.Lock()
	list := store.keys["user:u-1"]
	store.mu.Unlock()
	for _, k := range list {
		if k.KeyVersion == 1 && k.RevokedAt == nil {
			t.Fatal("RotateKey: version 1 should be revoked")
		}
	}
}

func TestRotateKeyLeavesNewVersionActive(t *testing.T) {
	mgr, store := setup()
	ctx := context.Background()

	if _, err := mgr.CreateKey(ctx, "user", "u-1"); err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	newVer, err := mgr.RotateKey(ctx, "user", "u-1")
	if err != nil {
		t.Fatalf("RotateKey: %v", err)
	}

	// The rotated key must be active (not revoked).
	active, err := store.GetActiveKey(ctx, "user", "u-1")
	if err != nil {
		t.Fatalf("GetActiveKey after rotate: %v", err)
	}
	if active.KeyVersion != newVer {
		t.Fatalf("expected active version %d, got %d", newVer, active.KeyVersion)
	}
	if active.RevokedAt != nil {
		t.Fatal("rotated key should not be revoked")
	}

	// The old key must be revoked.
	old, err := store.GetKey(ctx, "user", "u-1", 1)
	if err != nil {
		t.Fatalf("GetKey(v1) after rotate: %v", err)
	}
	if old.RevokedAt == nil {
		t.Fatal("version 1 should be revoked after rotation")
	}
}

func TestRotateKeyNotFound(t *testing.T) {
	mgr, _ := setup()
	ctx := context.Background()

	_, err := mgr.RotateKey(ctx, "user", "u-1")
	if !errors.Is(err, encryption.ErrKeyNotFound) {
		t.Fatalf("RotateKey: expected ErrKeyNotFound, got %v", err)
	}
}

func TestDestroyKeys(t *testing.T) {
	mgr, store := setup()
	ctx := context.Background()

	if _, err := mgr.CreateKey(ctx, "user", "u-1"); err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	if err := mgr.DestroyKeys(ctx, "user", "u-1"); err != nil {
		t.Fatalf("DestroyKeys: %v", err)
	}

	store.mu.Lock()
	_, exists := store.keys["user:u-1"]
	store.mu.Unlock()
	if exists {
		t.Fatal("DestroyKeys: keys should be removed")
	}
}

func TestActiveKeyVersion(t *testing.T) {
	mgr, _ := setup()
	ctx := context.Background()

	if _, err := mgr.CreateKey(ctx, "user", "u-1"); err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	version, err := mgr.ActiveKeyVersion(ctx, "user", "u-1")
	if err != nil {
		t.Fatalf("ActiveKeyVersion: %v", err)
	}
	if version != 1 {
		t.Fatalf("ActiveKeyVersion: expected 1, got %d", version)
	}

	if _, err := mgr.RotateKey(ctx, "user", "u-1"); err != nil {
		t.Fatalf("RotateKey: %v", err)
	}

	version, err = mgr.ActiveKeyVersion(ctx, "user", "u-1")
	if err != nil {
		t.Fatalf("ActiveKeyVersion after rotate: %v", err)
	}
	if version != 2 {
		t.Fatalf("ActiveKeyVersion: expected 2, got %d", version)
	}
}
