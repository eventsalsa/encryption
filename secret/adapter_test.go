package secret_test

import (
	"context"
	"errors"
	"testing"

	encryption "github.com/eventsalsa/encryption"
	"github.com/eventsalsa/encryption/cipher/aesgcm"
	"github.com/eventsalsa/encryption/envelope"
	"github.com/eventsalsa/encryption/keymanager"
	"github.com/eventsalsa/encryption/secret"
	"github.com/eventsalsa/encryption/testutil"
)

func setupSecret(t *testing.T) (*secret.Adapter, *keymanager.Manager) {
	t.Helper()
	ctx := context.Background()

	keyring := testutil.NewTestKeyring()
	store := testutil.NewInMemoryKeyStore()
	c := aesgcm.New()

	mgr := keymanager.New(keyring, store, c)
	if _, err := mgr.CreateKey(ctx, "integration", "stripe"); err != nil {
		t.Fatal(err)
	}

	enc := envelope.NewEncryptor(keyring, store, c)
	return secret.NewAdapter(enc), mgr
}

func TestSecretAdapter_EncryptDecryptRoundtrip(t *testing.T) {
	adapter, _ := setupSecret(t)
	ctx := context.Background()

	encrypted, err := adapter.Encrypt(ctx, "integration", "stripe", "sk_live_xxx")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if encrypted.IsEmpty() {
		t.Fatal("encrypted value should not be empty")
	}
	if encrypted.KeyVersion != 1 {
		t.Fatalf("expected key version 1, got %d", encrypted.KeyVersion)
	}

	plaintext, err := adapter.Decrypt(ctx, "integration", "stripe", encrypted)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if plaintext != "sk_live_xxx" {
		t.Fatalf("got %q, want %q", plaintext, "sk_live_xxx")
	}
}

func TestSecretAdapter_KeyVersionAfterRotation(t *testing.T) {
	adapter, mgr := setupSecret(t)
	ctx := context.Background()

	// Encrypt with v1.
	v1, err := adapter.Encrypt(ctx, "integration", "stripe", "old-secret")
	if err != nil {
		t.Fatal(err)
	}

	// Rotate → v2.
	newVer, err := mgr.RotateKey(ctx, "integration", "stripe")
	if err != nil {
		t.Fatal(err)
	}
	if newVer != 2 {
		t.Fatalf("expected rotated version 2, got %d", newVer)
	}

	// Encrypt with v2.
	v2, err := adapter.Encrypt(ctx, "integration", "stripe", "new-secret")
	if err != nil {
		t.Fatal(err)
	}
	if v2.KeyVersion != 2 {
		t.Fatalf("expected key version 2 after rotation, got %d", v2.KeyVersion)
	}

	// Both versions should still decrypt.
	if p, err := adapter.Decrypt(ctx, "integration", "stripe", v1); err != nil || p != "old-secret" {
		t.Fatalf("v1 decrypt: got %q, err %v", p, err)
	}
	if p, err := adapter.Decrypt(ctx, "integration", "stripe", v2); err != nil || p != "new-secret" {
		t.Fatalf("v2 decrypt: got %q, err %v", p, err)
	}
}

func TestSecretAdapter_EncryptUnknownScope(t *testing.T) {
	adapter, _ := setupSecret(t)
	ctx := context.Background()

	_, err := adapter.Encrypt(ctx, "unknown", "nope", "data")
	if !errors.Is(err, encryption.ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound, got %v", err)
	}
}

func TestSecretAdapter_DecryptUnknownScope(t *testing.T) {
	adapter, _ := setupSecret(t)
	ctx := context.Background()

	_, err := adapter.Decrypt(ctx, "unknown", "nope", secret.New("bogus", 1))
	if !errors.Is(err, encryption.ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound, got %v", err)
	}
}
