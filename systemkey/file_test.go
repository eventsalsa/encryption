package systemkey

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/eventsalsa/encryption/encerr"
)

func writeKeyFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestNewKeyringFromFiles_Success(t *testing.T) {
	dir := t.TempDir()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	encoded := []byte(base64.StdEncoding.EncodeToString(key))
	p := writeKeyFile(t, dir, "key1", encoded)

	kr, err := NewKeyringFromFiles(FileKeyConfig{
		KeyPaths:    map[string]string{"k1": p},
		ActiveKeyID: "k1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, id := kr.ActiveKey()
	if id != "k1" {
		t.Fatalf("ActiveKey() keyID = %q, want %q", id, "k1")
	}
	if len(got) != 32 {
		t.Fatalf("ActiveKey() key length = %d, want 32", len(got))
	}
}

func TestNewKeyringFromFiles_MissingFile(t *testing.T) {
	_, err := NewKeyringFromFiles(FileKeyConfig{
		KeyPaths:    map[string]string{"k1": "/nonexistent/path"},
		ActiveKeyID: "k1",
	})
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestNewKeyringFromFiles_InvalidBase64(t *testing.T) {
	dir := t.TempDir()
	p := writeKeyFile(t, dir, "bad", []byte("not-valid-base64!!!"))

	_, err := NewKeyringFromFiles(FileKeyConfig{
		KeyPaths:    map[string]string{"k1": p},
		ActiveKeyID: "k1",
	})
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestNewKeyringFromFiles_WrongKeySize(t *testing.T) {
	dir := t.TempDir()
	short := base64.StdEncoding.EncodeToString([]byte("tooshort"))
	p := writeKeyFile(t, dir, "short", []byte(short))

	_, err := NewKeyringFromFiles(FileKeyConfig{
		KeyPaths:    map[string]string{"k1": p},
		ActiveKeyID: "k1",
	})
	if err == nil {
		t.Fatal("expected error for wrong key size")
	}
	if !errors.Is(err, encerr.ErrInvalidKeySize) {
		t.Fatalf("error = %v, want %v", err, encerr.ErrInvalidKeySize)
	}
}
