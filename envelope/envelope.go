// Package envelope implements KMS-native envelope encryption using a two-tier
// key hierarchy: Key Encryption Keys (KEKs) protect per-scope Data Encryption
// Keys (DEKs), and DEKs protect application data via local AEAD.
package envelope

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"

	"github.com/eventsalsa/encryption"
	"github.com/eventsalsa/encryption/cipher"
	"github.com/eventsalsa/encryption/kek"
)

// Envelope coordinates DEK generation, KEK-based wrapping/unwrapping/rewrapping
// with mandatory KeyScope AAD binding, and local AEAD data encryption/decryption.
// It is safe for concurrent use.
type Envelope struct {
	keyring kek.Keyring
	cipher  cipher.Cipher
}

// New returns an Envelope wired to the given KEK keyring and symmetric data cipher.
// It panics if keyring or c is nil.
func New(keyring kek.Keyring, c cipher.Cipher) *Envelope {
	if keyring == nil {
		panic("envelope: keyring is required")
	}
	if c == nil {
		panic("envelope: cipher is required")
	}
	return &Envelope{
		keyring: keyring,
		cipher:  c,
	}
}

// ActiveKEKID returns the active KEK identifier from the keyring.
func (e *Envelope) ActiveKEKID() string {
	return e.keyring.ActiveKeyID()
}

// GenerateDEK generates a new cryptographically secure random DEK matching the
// data cipher's key size.
// The caller is responsible for scrubbing memory with encryption.ZeroBytes(dek) when done.
func (e *Envelope) GenerateDEK() ([]byte, error) {
	dek := make([]byte, e.cipher.KeySize())
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		encryption.ZeroBytes(dek)
		return nil, fmt.Errorf("envelope generate DEK: %w", err)
	}
	return dek, nil
}

// WrapDEK encrypts a raw plaintext DEK using the keyring's active KEK,
// cryptographically binding it to scope.AAD().
func (e *Envelope) WrapDEK(ctx context.Context, scope encryption.KeyScope, dek []byte) (kekID string, encryptedDEK []byte, err error) {
	if err := scope.Validate(); err != nil {
		return "", nil, fmt.Errorf("envelope wrap DEK: %w", err)
	}
	if len(dek) != e.cipher.KeySize() {
		return "", nil, fmt.Errorf("envelope wrap DEK: got %d-byte DEK, want %d: %w", len(dek), e.cipher.KeySize(), encryption.ErrInvalidKeySize)
	}

	kekID, encDEK, err := e.keyring.Wrap(ctx, dek, scope.AAD())
	if err != nil {
		return "", nil, fmt.Errorf("envelope wrap DEK: %w", err)
	}
	return kekID, encDEK, nil
}

// UnwrapDEK decrypts an EncryptedKey's DEK using the KEK identified by key.KEKID,
// verifying the canonical KeyScope AAD.
// The caller is responsible for scrubbing the returned slice with encryption.ZeroBytes(dek) when done.
func (e *Envelope) UnwrapDEK(ctx context.Context, key *encryption.EncryptedKey) ([]byte, error) {
	if key == nil {
		return nil, fmt.Errorf("envelope unwrap DEK: key is nil: %w", encryption.ErrInvalidConfig)
	}
	scope := key.KeyScope()
	if err := scope.Validate(); err != nil {
		return nil, fmt.Errorf("envelope unwrap DEK: %w", err)
	}
	if key.KEKID == "" {
		return nil, fmt.Errorf("envelope unwrap DEK: KEK ID is required: %w", encryption.ErrInvalidConfig)
	}

	dek, err := e.keyring.Unwrap(ctx, key.KEKID, key.EncryptedDEK, scope.AAD())
	if err != nil {
		return nil, fmt.Errorf("envelope unwrap DEK: %w", err)
	}
	if len(dek) != e.cipher.KeySize() {
		encryption.ZeroBytes(dek)
		return nil, fmt.Errorf("envelope unwrap DEK: unwrapped DEK is %d bytes, want %d: %w", len(dek), e.cipher.KeySize(), encryption.ErrInvalidKeySize)
	}
	return dek, nil
}

// RewrapDEK re-encrypts a stored DEK from key.KEKID to targetKEKID, verifying
// and preserving the canonical KeyScope AAD.
func (e *Envelope) RewrapDEK(ctx context.Context, key *encryption.EncryptedKey, targetKEKID string) ([]byte, error) {
	if key == nil {
		return nil, fmt.Errorf("envelope rewrap DEK: key is nil: %w", encryption.ErrInvalidConfig)
	}
	scope := key.KeyScope()
	if err := scope.Validate(); err != nil {
		return nil, fmt.Errorf("envelope rewrap DEK: %w", err)
	}
	if key.KEKID == "" {
		return nil, fmt.Errorf("envelope rewrap DEK: source KEK ID is required: %w", encryption.ErrInvalidConfig)
	}
	if targetKEKID == "" {
		return nil, fmt.Errorf("envelope rewrap DEK: target KEK ID is required: %w", encryption.ErrInvalidConfig)
	}

	aad := scope.AAD()
	rewrapped, err := e.keyring.Rewrap(ctx, key.KEKID, targetKEKID, key.EncryptedDEK, aad, aad)
	if err != nil {
		return nil, fmt.Errorf("envelope rewrap DEK: %w", err)
	}
	return rewrapped, nil
}

// OpenSession unwraps key once and returns a reusable in-memory Session for
// high-throughput batch or stream encryption and decryption without repeated KMS calls.
// Callers must call defer session.Close() to scrub the plaintext DEK from memory.
func (e *Envelope) OpenSession(ctx context.Context, key *encryption.EncryptedKey) (*Session, error) {
	dek, err := e.UnwrapDEK(ctx, key)
	if err != nil {
		return nil, err
	}
	return &Session{
		dek:    dek,
		cipher: e.cipher,
	}, nil
}

// Encrypt unwraps key, encrypts plaintext with optional payload aad, and scrubs
// the plaintext DEK from memory before returning.
func (e *Envelope) Encrypt(ctx context.Context, key *encryption.EncryptedKey, plaintext, aad []byte) ([]byte, error) {
	session, err := e.OpenSession(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("envelope encrypt: %w", err)
	}
	defer session.Close()

	return session.Encrypt(plaintext, aad)
}

// Decrypt unwraps key, decrypts ciphertext verifying optional payload aad, and
// scrubs the plaintext DEK from memory before returning.
func (e *Envelope) Decrypt(ctx context.Context, key *encryption.EncryptedKey, ciphertext, aad []byte) ([]byte, error) {
	session, err := e.OpenSession(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("envelope decrypt: %w", err)
	}
	defer session.Close()

	return session.Decrypt(ciphertext, aad)
}

// EncryptString unwraps key, encrypts a UTF-8 plaintext string with optional
// payload aad, and returns base64-encoded ciphertext.
func (e *Envelope) EncryptString(ctx context.Context, key *encryption.EncryptedKey, plaintext string, aad []byte) (string, error) {
	session, err := e.OpenSession(ctx, key)
	if err != nil {
		return "", fmt.Errorf("envelope encrypt string: %w", err)
	}
	defer session.Close()

	return session.EncryptString(plaintext, aad)
}

// DecryptString unwraps key, decrypts base64-encoded ciphertext verifying
// optional payload aad, and returns the UTF-8 plaintext string.
func (e *Envelope) DecryptString(ctx context.Context, key *encryption.EncryptedKey, ciphertext string, aad []byte) (string, error) {
	session, err := e.OpenSession(ctx, key)
	if err != nil {
		return "", fmt.Errorf("envelope decrypt string: %w", err)
	}
	defer session.Close()

	return session.DecryptString(ciphertext, aad)
}
