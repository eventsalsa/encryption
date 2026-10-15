package local_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/eventsalsa/encryption"
	"github.com/eventsalsa/encryption/kek/local"
)

func writeKeyFile(t *testing.T, dir, name string, content []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestWrapperRoundtripAndClose(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	rawKey := make([]byte, 32)
	if _, err := rand.Read(rawKey); err != nil {
		t.Fatal(err)
	}

	w, err := local.NewWrapper("k1", rawKey)
	if err != nil {
		t.Fatalf("NewWrapper: %v", err)
	}

	// Mutating caller's rawKey slice must not affect Wrapper (defensive copy).
	encryption.ZeroBytes(rawKey)

	dek := []byte("0123456789abcdef0123456789abcdef")
	aad := []byte("scope:user:1")

	encDEK, err := w.Wrap(ctx, dek, aad)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	// Wrong AAD must fail
	if _, err := w.Unwrap(ctx, encDEK, []byte("wrong-aad")); !errors.Is(err, encryption.ErrDecryption) {
		t.Fatalf("Unwrap with wrong AAD: err = %v, want ErrDecryption", err)
	}

	got, err := w.Unwrap(ctx, encDEK, aad)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Fatalf("Unwrap = %x, want %x", got, dek)
	}

	w.Close()
	if _, err := w.Wrap(ctx, dek, aad); !errors.Is(err, encryption.ErrSessionClosed) {
		t.Fatalf("Wrap after Close: err = %v, want ErrSessionClosed", err)
	}
	if _, err := w.Unwrap(ctx, encDEK, aad); !errors.Is(err, encryption.ErrSessionClosed) {
		t.Fatalf("Unwrap after Close: err = %v, want ErrSessionClosed", err)
	}
}

func TestNewKeyringFromFiles(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dir := t.TempDir()

	rawKey := make([]byte, 32)
	if _, err := rand.Read(rawKey); err != nil {
		t.Fatal(err)
	}
	encoded := base64.StdEncoding.EncodeToString(rawKey) + "\n"
	keyPath := writeKeyFile(t, dir, "key1.b64", []byte(encoded))

	kr, err := local.NewKeyringFromFiles(local.FileConfig{
		KeyPaths:    map[string]string{"key-1": keyPath},
		ActiveKeyID: "key-1",
	})
	if err != nil {
		t.Fatalf("NewKeyringFromFiles: %v", err)
	}

	dek := []byte("0123456789abcdef0123456789abcdef")
	kekID, encDEK, err := kr.Wrap(ctx, dek, []byte("aad"))
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if kekID != "key-1" {
		t.Fatalf("kekID = %q, want key-1", kekID)
	}

	got, err := kr.Unwrap(ctx, "key-1", encDEK, []byte("aad"))
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Fatalf("got %x, want %x", got, dek)
	}
}

func TestNewKeyringFromFiles_Errors(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	// Empty config
	if _, err := local.NewKeyringFromFiles(local.FileConfig{}); !errors.Is(err, encryption.ErrInvalidConfig) {
		t.Fatalf("empty FileConfig: err = %v, want ErrInvalidConfig", err)
	}

	// Missing file
	if _, err := local.NewKeyringFromFiles(local.FileConfig{
		KeyPaths:    map[string]string{"k1": filepath.Join(dir, "nope.key")},
		ActiveKeyID: "k1",
	}); err == nil {
		t.Fatal("expected error for missing file")
	}

	// Invalid base64
	badB64 := writeKeyFile(t, dir, "bad.b64", []byte("not-valid-base64!!!"))
	if _, err := local.NewKeyringFromFiles(local.FileConfig{
		KeyPaths:    map[string]string{"k1": badB64},
		ActiveKeyID: "k1",
	}); err == nil {
		t.Fatal("expected error for invalid base64")
	}

	// Wrong key size (16 bytes instead of 32)
	shortPath := writeKeyFile(t, dir, "short.b64", []byte(base64.StdEncoding.EncodeToString(make([]byte, 16))))
	if _, err := local.NewKeyringFromFiles(local.FileConfig{
		KeyPaths:    map[string]string{"k1": shortPath},
		ActiveKeyID: "k1",
	}); !errors.Is(err, encryption.ErrInvalidKeySize) {
		t.Fatalf("wrong key size: err = %v, want ErrInvalidKeySize", err)
	}
}
