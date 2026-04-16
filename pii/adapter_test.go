package pii_test

import (
	"context"
	"crypto/rand"
	"errors"
	"testing"

	encryption "github.com/eventsalsa/encryption"
	"github.com/eventsalsa/encryption/cipher/aesgcm"
	"github.com/eventsalsa/encryption/envelope"
	"github.com/eventsalsa/encryption/pii"
	"github.com/eventsalsa/encryption/testutil"
)

type userID string

func (u userID) String() string { return string(u) }

func setupPII(t *testing.T) *pii.Adapter[userID] {
	t.Helper()
	ctx := context.Background()

	keyring := testutil.NewTestKeyring()
	store := testutil.NewInMemoryKeyStore()
	c := aesgcm.New()

	sysKey, sysKeyID := keyring.ActiveKey()
	dek := make([]byte, c.KeySize())
	if _, err := rand.Read(dek); err != nil {
		t.Fatal(err)
	}
	encDEK, err := c.Encrypt(sysKey, dek)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CreateKey(ctx, "user-pii", "u-1", 1, encDEK, sysKeyID); err != nil {
		t.Fatal(err)
	}

	enc := envelope.NewEncryptor(keyring, store, c)
	return pii.NewAdapter[userID](enc, "user-pii")
}

func TestAdapter_EncryptDecryptRoundtrip(t *testing.T) {
	adapter := setupPII(t)
	ctx := context.Background()

	encrypted, err := adapter.Encrypt(ctx, userID("u-1"), "alice@example.com")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if encrypted.IsEmpty() {
		t.Fatal("encrypted value should not be empty")
	}

	plaintext, err := adapter.Decrypt(ctx, userID("u-1"), encrypted)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if plaintext != "alice@example.com" {
		t.Fatalf("got %q, want %q", plaintext, "alice@example.com")
	}
}

func TestAdapter_EncryptDifferentCiphertexts(t *testing.T) {
	adapter := setupPII(t)
	ctx := context.Background()

	a, err := adapter.Encrypt(ctx, userID("u-1"), "same-value")
	if err != nil {
		t.Fatal(err)
	}
	b, err := adapter.Encrypt(ctx, userID("u-1"), "same-value")
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("two encryptions of the same plaintext should produce different ciphertexts")
	}
}

func TestAdapter_DecryptUnknownSubject(t *testing.T) {
	adapter := setupPII(t)
	ctx := context.Background()

	_, err := adapter.Decrypt(ctx, userID("unknown"), pii.EncryptedValue("bogus"))
	if !errors.Is(err, encryption.ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound, got %v", err)
	}
}

func TestAdapter_EncryptUnknownSubject(t *testing.T) {
	adapter := setupPII(t)
	ctx := context.Background()

	_, err := adapter.Encrypt(ctx, userID("no-key"), "data")
	if !errors.Is(err, encryption.ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound, got %v", err)
	}
}
