package envelope

import (
	"encoding/base64"
	"fmt"
	"sync"

	"github.com/eventsalsa/encryption"
	"github.com/eventsalsa/encryption/cipher"
)

// Session holds an unwrapped DEK in memory for performing multiple local AEAD
// encrypt and decrypt operations without making repeated KMS unwrap calls.
//
// A Session is safe for concurrent use and must be closed via Close when the
// unit of work finishes to scrub the plaintext DEK from memory.
type Session struct {
	mu     sync.RWMutex
	dek    []byte
	cipher cipher.Cipher
	closed bool
}

// Encrypt encrypts plaintext with the session's DEK and binds it to optional aad.
func (s *Session) Encrypt(plaintext, aad []byte) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, encryption.ErrSessionClosed
	}

	ct, err := s.cipher.Encrypt(s.dek, plaintext, aad)
	if err != nil {
		return nil, fmt.Errorf("session encrypt: %w", err)
	}
	return ct, nil
}

// Decrypt decrypts ciphertext with the session's DEK and verifies optional aad.
func (s *Session) Decrypt(ciphertext, aad []byte) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, encryption.ErrSessionClosed
	}

	pt, err := s.cipher.Decrypt(s.dek, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("session decrypt: %w", err)
	}
	return pt, nil
}

// EncryptString encrypts a UTF-8 plaintext string and returns base64-encoded ciphertext.
func (s *Session) EncryptString(plaintext string, aad []byte) (string, error) {
	ct, err := s.Encrypt([]byte(plaintext), aad)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ct), nil
}

// DecryptString decodes base64-encoded ciphertext, decrypts it, and returns the UTF-8 plaintext string.
func (s *Session) DecryptString(ciphertext string, aad []byte) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("session decrypt string: base64 decode: %w: %w", err, encryption.ErrDecryption)
	}
	pt, err := s.Decrypt(raw, aad)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

// Close scrubs the plaintext DEK from memory and marks the session as closed.
// Subsequent calls to Close are no-ops.
func (s *Session) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.closed {
		encryption.ZeroBytes(s.dek)
		s.dek = nil
		s.closed = true
	}
}
