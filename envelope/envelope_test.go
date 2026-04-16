package envelope_test

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"testing"
	"time"

	encryption "github.com/eventsalsa/encryption"
	"github.com/eventsalsa/encryption/cipher/aesgcm"
	"github.com/eventsalsa/encryption/envelope"
	"github.com/eventsalsa/encryption/keystore"
	"github.com/eventsalsa/encryption/systemkey"
)

// mockKeyStore is a simple in-memory keystore for testing.
type mockKeyStore struct {
	keys map[string]*keystore.EncryptedKey // "scope:scopeID:version"
}

func newMockKeyStore() *mockKeyStore {
	return &mockKeyStore{keys: make(map[string]*keystore.EncryptedKey)}
}

func mockKey(scope, scopeID string, version int) string {
	return fmt.Sprintf("%s:%s:%d", scope, scopeID, version)
}

func (m *mockKeyStore) GetActiveKey(_ context.Context, scope, scopeID string) (*keystore.EncryptedKey, error) {
	// Return the highest version for this scope/scopeID.
	var best *keystore.EncryptedKey
	prefix := fmt.Sprintf("%s:%s:", scope, scopeID)
	for k, v := range m.keys {
		if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			if best == nil || v.KeyVersion > best.KeyVersion {
				best = v
			}
		}
	}
	if best == nil {
		return nil, encryption.ErrKeyNotFound
	}
	return best, nil
}

func (m *mockKeyStore) GetKey(_ context.Context, scope, scopeID string, version int) (*keystore.EncryptedKey, error) {
	k, ok := m.keys[mockKey(scope, scopeID, version)]
	if !ok {
		return nil, encryption.ErrKeyNotFound
	}
	return k, nil
}

func (m *mockKeyStore) CreateKey(_ context.Context, scope, scopeID string, version int, encryptedDEK []byte, systemKeyID string) error {
	k := mockKey(scope, scopeID, version)
	if _, exists := m.keys[k]; exists {
		return encryption.ErrKeyExists
	}
	m.keys[k] = &keystore.EncryptedKey{
		Scope:        scope,
		ScopeID:      scopeID,
		KeyVersion:   version,
		EncryptedDEK: encryptedDEK,
		SystemKeyID:  systemKeyID,
		CreatedAt:    time.Now(),
	}
	return nil
}

func (m *mockKeyStore) RevokeKeys(context.Context, string, string) error {
	return nil
}

func (m *mockKeyStore) DestroyKeys(context.Context, string, string) error {
	return nil
}

// setup creates a test encryptor with a pre-seeded key for scope "tenant" / scopeID "abc".
func setup(t *testing.T) (*envelope.Encryptor, *mockKeyStore) {
	t.Helper()

	c := aesgcm.New()

	// Generate a system key.
	sysKey := make([]byte, c.KeySize())
	if _, err := rand.Read(sysKey); err != nil {
		t.Fatal(err)
	}
	keyID := "sys-key-1"
	keyring := systemkey.NewKeyring(map[string][]byte{keyID: sysKey}, keyID)

	// Generate a random DEK and encrypt it with the system key.
	dek := make([]byte, c.KeySize())
	if _, err := rand.Read(dek); err != nil {
		t.Fatal(err)
	}
	encDEK, err := c.Encrypt(sysKey, dek)
	if err != nil {
		t.Fatal(err)
	}

	store := newMockKeyStore()
	store.keys[mockKey("tenant", "abc", 1)] = &keystore.EncryptedKey{
		Scope:        "tenant",
		ScopeID:      "abc",
		KeyVersion:   1,
		EncryptedDEK: encDEK,
		SystemKeyID:  keyID,
		CreatedAt:    time.Now(),
	}

	enc := envelope.NewEncryptor(keyring, store, c)
	return enc, store
}

func TestEncryptDecryptRoundtrip(t *testing.T) {
	enc, _ := setup(t)
	ctx := context.Background()

	plaintext := "hello world"
	ct, ver, err := enc.Encrypt(ctx, "tenant", "abc", plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	got, err := enc.Decrypt(ctx, "tenant", "abc", ct, ver)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if got != plaintext {
		t.Fatalf("roundtrip: got %q, want %q", got, plaintext)
	}
}

func TestDecryptWrongVersionReturnsError(t *testing.T) {
	enc, _ := setup(t)
	ctx := context.Background()

	ct, _, err := enc.Encrypt(ctx, "tenant", "abc", "secret")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	_, err = enc.Decrypt(ctx, "tenant", "abc", ct, 999)
	if err == nil {
		t.Fatal("expected error for wrong version")
	}
	if !errors.Is(err, encryption.ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound, got: %v", err)
	}
}

func TestDecryptTamperedCiphertextReturnsError(t *testing.T) {
	enc, _ := setup(t)
	ctx := context.Background()

	ct, ver, err := enc.Encrypt(ctx, "tenant", "abc", "secret")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Tamper with the base64 ciphertext by flipping a character.
	tampered := []byte(ct)
	tampered[len(tampered)/2] ^= 0xff
	_, err = enc.Decrypt(ctx, "tenant", "abc", string(tampered), ver)
	if err == nil {
		t.Fatal("expected error for tampered ciphertext")
	}
}

func TestEncryptReturnsCorrectKeyVersion(t *testing.T) {
	enc, _ := setup(t)
	ctx := context.Background()

	_, ver, err := enc.Encrypt(ctx, "tenant", "abc", "data")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if ver != 1 {
		t.Fatalf("key version: got %d, want 1", ver)
	}
}

func TestEncryptKeyNotFoundForUnknownScope(t *testing.T) {
	enc, _ := setup(t)
	ctx := context.Background()

	_, _, err := enc.Encrypt(ctx, "unknown", "xyz", "data")
	if err == nil {
		t.Fatal("expected error for unknown scope")
	}
	if !errors.Is(err, encryption.ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound, got: %v", err)
	}
}
