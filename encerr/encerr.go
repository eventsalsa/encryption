// Package encerr provides shared sentinel errors and utilities used across the
// encryption library's sub-packages. It exists to break import cycles: the root
// encryption package re-exports everything defined here.
package encerr

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

// ZeroBytes overwrites a byte slice with zeros to clear sensitive key material
// from memory.
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
