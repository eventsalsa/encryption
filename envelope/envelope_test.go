package envelope_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/eventsalsa/encryption/cipher/aesgcm"
	"github.com/eventsalsa/encryption/envelope"
	"github.com/eventsalsa/encryption/systemkey"
)

func setupTestEnvelope(t *testing.T) (env *envelope.Envelope, keyID string, sysKey []byte) {
	t.Helper()

	c := aesgcm.New()
	sysKey = make([]byte, c.KeySize())
	if _, err := rand.Read(sysKey); err != nil {
		t.Fatalf("generate sysKey: %v", err)
	}

	keyID = "sys-key-1"
	keyring := systemkey.NewKeyring(map[string][]byte{keyID: sysKey}, keyID)
	env = envelope.New(keyring, c)

	return env, keyID, sysKey
}

func TestEnvelopeEncryptDecryptRoundtrip(t *testing.T) {
	env, keyID, _ := setupTestEnvelope(t)

	dek, err := env.GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK: %v", err)
	}

	encDEK, err := env.WrapDEK(keyID, dek)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}

	plaintext := "Hello, pure in-memory envelope encryption!"
	ciphertext, err := env.Encrypt(keyID, encDEK, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	decrypted, err := env.Decrypt(keyID, encDEK, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if decrypted != plaintext {
		t.Fatalf("roundtrip failed: got %q, want %q", decrypted, plaintext)
	}
}

func TestEnvelopeWrapUnwrapDEKRoundtrip(t *testing.T) {
	env, keyID, _ := setupTestEnvelope(t)

	dek, err := env.GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK: %v", err)
	}

	encDEK, err := env.WrapDEK(keyID, dek)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}

	unwrapped, err := env.UnwrapDEK(keyID, encDEK)
	if err != nil {
		t.Fatalf("UnwrapDEK: %v", err)
	}

	if !bytes.Equal(unwrapped, dek) {
		t.Fatal("unwrapped DEK does not match original DEK")
	}
}

func TestEnvelopeUnknownSystemKey(t *testing.T) {
	env, _, _ := setupTestEnvelope(t)

	dek, err := env.GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK: %v", err)
	}

	_, err = env.WrapDEK("non-existent-key", dek)
	if err == nil {
		t.Fatal("expected error wrapping with non-existent system key")
	}

	_, err = env.Encrypt("non-existent-key", []byte("dummy-enc-dek"), "plaintext")
	if err == nil {
		t.Fatal("expected error encrypting with non-existent system key")
	}

	_, err = env.Decrypt("non-existent-key", []byte("dummy-enc-dek"), "ciphertext")
	if err == nil {
		t.Fatal("expected error decrypting with non-existent system key")
	}
}

func TestEnvelopeTamperedCiphertext(t *testing.T) {
	env, keyID, _ := setupTestEnvelope(t)

	dek, err := env.GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK: %v", err)
	}

	encDEK, err := env.WrapDEK(keyID, dek)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}

	ciphertext, err := env.Encrypt(keyID, encDEK, "my confidential data")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Tamper with ciphertext by flipping a character
	tampered := []byte(ciphertext)
	tampered[len(tampered)/2] ^= 0xff

	_, err = env.Decrypt(keyID, encDEK, string(tampered))
	if err == nil {
		t.Fatal("expected error decrypting tampered ciphertext")
	}
}

func TestEnvelopeTamperedEncryptedDEK(t *testing.T) {
	env, keyID, _ := setupTestEnvelope(t)

	dek, err := env.GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK: %v", err)
	}

	encDEK, err := env.WrapDEK(keyID, dek)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}

	ciphertext, err := env.Encrypt(keyID, encDEK, "my confidential data")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Tamper with encDEK
	tamperedDEK := make([]byte, len(encDEK))
	copy(tamperedDEK, encDEK)
	tamperedDEK[len(tamperedDEK)/2] ^= 0xff

	_, err = env.Decrypt(keyID, tamperedDEK, ciphertext)
	if err == nil {
		t.Fatal("expected error decrypting with tampered encrypted DEK")
	}
}

func TestEnvelopeActiveKeyID(t *testing.T) {
	env, keyID, _ := setupTestEnvelope(t)

	if got := env.ActiveKeyID(); got != keyID {
		t.Fatalf("ActiveKeyID: got %q, want %q", got, keyID)
	}
}
