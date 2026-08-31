// Package envelope implements pure in-memory envelope encryption using a two-tier
// key hierarchy: system keys (KEKs) protect data encryption keys (DEKs), and DEKs
// protect application data.
package envelope

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"

	"github.com/eventsalsa/encryption/cipher"
	encryption "github.com/eventsalsa/encryption/encerr"
	"github.com/eventsalsa/encryption/systemkey"
)

// Envelope performs in-memory envelope encrypt/decrypt and DEK wrapping/unwrapping.
// It is safe for concurrent use and has zero storage or database dependencies.
type Envelope struct {
	keyring systemkey.Keyring
	cipher  cipher.Cipher
}

// New returns an Envelope wired to the given keyring and symmetric cipher.
func New(keyring systemkey.Keyring, c cipher.Cipher) *Envelope {
	return &Envelope{keyring: keyring, cipher: c}
}

// Encrypt unwraps the encrypted DEK using the specified system key, then encrypts
// the plaintext with the DEK and returns base64-encoded ciphertext.
func (e *Envelope) Encrypt(systemKeyID string, encryptedDEK []byte, plaintext string) (string, error) {
	dek, err := e.UnwrapDEK(systemKeyID, encryptedDEK)
	if err != nil {
		return "", fmt.Errorf("envelope encrypt: %w", err)
	}
	defer encryption.ZeroBytes(dek)

	ct, err := e.cipher.Encrypt(dek, []byte(plaintext))
	if err != nil {
		return "", fmt.Errorf("envelope encrypt: %w", err)
	}

	return base64.StdEncoding.EncodeToString(ct), nil
}

// Decrypt unwraps the encrypted DEK using the specified system key, then decrypts
// the base64-encoded ciphertext using the DEK and returns the plaintext.
func (e *Envelope) Decrypt(systemKeyID string, encryptedDEK []byte, ciphertext string) (string, error) {
	dek, err := e.UnwrapDEK(systemKeyID, encryptedDEK)
	if err != nil {
		return "", fmt.Errorf("envelope decrypt: %w", err)
	}
	defer encryption.ZeroBytes(dek)

	raw, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("envelope decrypt: base64 decode: %w", err)
	}

	pt, err := e.cipher.Decrypt(dek, raw)
	if err != nil {
		return "", fmt.Errorf("envelope decrypt: %w", err)
	}

	return string(pt), nil
}

// WrapDEK encrypts a raw plaintext DEK using the specified system key.
func (e *Envelope) WrapDEK(systemKeyID string, dek []byte) ([]byte, error) {
	sysKey, err := e.keyring.Key(systemKeyID)
	if err != nil {
		return nil, fmt.Errorf("envelope wrap DEK: get system key %q: %w", systemKeyID, err)
	}

	encDEK, err := e.cipher.Encrypt(sysKey, dek)
	if err != nil {
		return nil, fmt.Errorf("envelope wrap DEK: %w", err)
	}

	return encDEK, nil
}

// UnwrapDEK decrypts an encrypted DEK using the specified system key and returns
// the raw plaintext DEK bytes. The caller is responsible for scrubbing memory with
// encryption.ZeroBytes(dek) when done.
func (e *Envelope) UnwrapDEK(systemKeyID string, encryptedDEK []byte) ([]byte, error) {
	sysKey, err := e.keyring.Key(systemKeyID)
	if err != nil {
		return nil, fmt.Errorf("envelope unwrap DEK: get system key %q: %w", systemKeyID, err)
	}

	dek, err := e.cipher.Decrypt(sysKey, encryptedDEK)
	if err != nil {
		return nil, fmt.Errorf("envelope unwrap DEK: %w", err)
	}

	return dek, nil
}

// GenerateDEK generates a new cryptographically secure random DEK matching the cipher's key size.
// The caller is responsible for scrubbing memory with encryption.ZeroBytes(dek) when done.
func (e *Envelope) GenerateDEK() ([]byte, error) {
	dek := make([]byte, e.cipher.KeySize())
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		encryption.ZeroBytes(dek)
		return nil, fmt.Errorf("envelope generate DEK: %w", err)
	}
	return dek, nil
}

// ActiveKeyID returns the active system key ID from the keyring.
func (e *Envelope) ActiveKeyID() string {
	_, id := e.keyring.ActiveKey()
	return id
}
