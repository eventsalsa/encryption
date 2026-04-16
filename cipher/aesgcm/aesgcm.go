// Package aesgcm provides an AES-256-GCM implementation of the cipher.Cipher interface.
package aesgcm

import (
	"crypto/aes"
	gcm "crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"

	"github.com/eventsalsa/encryption"
	"github.com/eventsalsa/encryption/cipher"
)

const (
	keySize   = 32 // AES-256
	nonceSize = 12 // GCM standard nonce
)

// Cipher implements cipher.Cipher using AES-256-GCM.
// Ciphertext format: [12-byte nonce][ciphertext][16-byte GCM auth tag].
// Safe for concurrent use.
type Cipher struct{}

func init() {
	encryption.DefaultCipherFactory = func() cipher.Cipher { return New() }
}

// New returns a new AES-256-GCM cipher.
func New() *Cipher {
	return &Cipher{}
}

// KeySize returns 32 (AES-256).
func (c *Cipher) KeySize() int {
	return keySize
}

// Encrypt encrypts plaintext with the given key using AES-256-GCM.
// The key must be exactly 32 bytes. A random 12-byte nonce is generated
// for each call. Returns [nonce][ciphertext][tag].
func (c *Cipher) Encrypt(key, plaintext []byte) ([]byte, error) {
	if len(key) != keySize {
		return nil, fmt.Errorf("aesgcm encrypt: expected %d-byte key, got %d: %w", keySize, len(key), encryption.ErrInvalidKeySize)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aesgcm encrypt: %w", encryption.ErrEncryption)
	}

	aead, err := gcm.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("aesgcm encrypt: %w", encryption.ErrEncryption)
	}

	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("aesgcm encrypt: generate nonce: %w", encryption.ErrEncryption)
	}

	ciphertext := aead.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts ciphertext with the given key using AES-256-GCM.
// The key must be exactly 32 bytes. Expects [nonce][ciphertext][tag] format.
func (c *Cipher) Decrypt(key, ciphertext []byte) ([]byte, error) {
	if len(key) != keySize {
		return nil, fmt.Errorf("aesgcm decrypt: expected %d-byte key, got %d: %w", keySize, len(key), encryption.ErrInvalidKeySize)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aesgcm decrypt: %w", encryption.ErrDecryption)
	}

	aead, err := gcm.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("aesgcm decrypt: %w", encryption.ErrDecryption)
	}

	// Minimum length: nonce + GCM tag (no plaintext)
	minLen := nonceSize + aead.Overhead()
	if len(ciphertext) < minLen {
		return nil, fmt.Errorf("aesgcm decrypt: ciphertext too short: %w", encryption.ErrDecryption)
	}

	nonce := ciphertext[:nonceSize]
	encrypted := ciphertext[nonceSize:]

	plaintext, err := aead.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return nil, fmt.Errorf("aesgcm decrypt: %w", encryption.ErrDecryption)
	}

	return plaintext, nil
}
