package aesgcm

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/eventsalsa/encryption"
)

func validKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return key
}

func TestRoundtrip(t *testing.T) {
	c := New()
	key := validKey(t)
	plaintext := []byte("hello, envelope encryption!")

	ciphertext, err := c.Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	got, err := c.Decrypt(key, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if !bytes.Equal(got, plaintext) {
		t.Errorf("Decrypt = %q, want %q", got, plaintext)
	}
}

func TestRoundtripEmptyPlaintext(t *testing.T) {
	c := New()
	key := validKey(t)

	ciphertext, err := c.Encrypt(key, []byte{})
	if err != nil {
		t.Fatalf("Encrypt empty: %v", err)
	}

	got, err := c.Decrypt(key, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt empty: %v", err)
	}

	if len(got) != 0 {
		t.Errorf("Decrypt empty = %q, want empty", got)
	}
}

func TestKeyIsolation(t *testing.T) {
	c := New()
	key1 := validKey(t)
	key2 := validKey(t)
	plaintext := []byte("secret data")

	ciphertext, err := c.Encrypt(key1, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	_, err = c.Decrypt(key2, ciphertext)
	if err == nil {
		t.Fatal("Decrypt with wrong key should fail")
	}
	if !errors.Is(err, encryption.ErrDecryption) {
		t.Errorf("err = %v, want ErrDecryption", err)
	}
}

func TestEncryptInvalidKeySize(t *testing.T) {
	c := New()
	for _, size := range []int{0, 15, 16, 24, 31, 33, 64} {
		key := make([]byte, size)
		_, err := c.Encrypt(key, []byte("data"))
		if !errors.Is(err, encryption.ErrInvalidKeySize) {
			t.Errorf("Encrypt(key len %d): err = %v, want ErrInvalidKeySize", size, err)
		}
	}
}

func TestDecryptInvalidKeySize(t *testing.T) {
	c := New()
	for _, size := range []int{0, 16, 31, 33} {
		key := make([]byte, size)
		_, err := c.Decrypt(key, make([]byte, 100))
		if !errors.Is(err, encryption.ErrInvalidKeySize) {
			t.Errorf("Decrypt(key len %d): err = %v, want ErrInvalidKeySize", size, err)
		}
	}
}

func TestDecryptShortCiphertext(t *testing.T) {
	c := New()
	key := validKey(t)

	// Less than nonce (12) + tag (16) = 28 bytes
	for _, size := range []int{0, 1, 12, 27} {
		_, err := c.Decrypt(key, make([]byte, size))
		if !errors.Is(err, encryption.ErrDecryption) {
			t.Errorf("Decrypt(ciphertext len %d): err = %v, want ErrDecryption", size, err)
		}
	}
}

func TestDecryptTamperedCiphertext(t *testing.T) {
	c := New()
	key := validKey(t)

	ciphertext, err := c.Encrypt(key, []byte("sensitive"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Flip a byte in the ciphertext (after the nonce)
	tampered := make([]byte, len(ciphertext))
	copy(tampered, ciphertext)
	tampered[len(tampered)-1] ^= 0xFF

	_, err = c.Decrypt(key, tampered)
	if !errors.Is(err, encryption.ErrDecryption) {
		t.Errorf("Decrypt tampered: err = %v, want ErrDecryption", err)
	}
}

func TestUniqueNonces(t *testing.T) {
	c := New()
	key := validKey(t)
	plaintext := []byte("same plaintext")

	ct1, _ := c.Encrypt(key, plaintext)
	ct2, _ := c.Encrypt(key, plaintext)

	// Nonces are the first 12 bytes — they must differ
	if bytes.Equal(ct1[:12], ct2[:12]) {
		t.Error("two encryptions produced identical nonces")
	}
}

func TestKeySize(t *testing.T) {
	c := New()
	if got := c.KeySize(); got != 32 {
		t.Errorf("KeySize() = %d, want 32", got)
	}
}
