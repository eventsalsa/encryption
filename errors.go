// Package encryption provides envelope encryption for Go systems.
//
// This package defines shared sentinel errors used across all sub-packages.
package encryption

import "errors"

// Sentinel errors used across the encryption library.
var (
	ErrKeyNotFound    = errors.New("encryption key not found")
	ErrKeyExists      = errors.New("encryption key already exists")
	ErrEncryption     = errors.New("encryption failed")
	ErrDecryption     = errors.New("decryption failed")
	ErrInvalidKeySize = errors.New("invalid key size")
	ErrKeyRevoked     = errors.New("encryption key has been revoked")
	ErrKeyDestroyed   = errors.New("encryption key has been destroyed")
)
