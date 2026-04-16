// Package encryption provides envelope encryption for event-sourced systems.
//
// This package defines shared sentinel errors used across all sub-packages.
package encryption

import "github.com/eventsalsa/encryption/encerr"

// Sentinel errors re-exported from encerr for public use.
var (
	ErrKeyNotFound    = encerr.ErrKeyNotFound
	ErrKeyExists      = encerr.ErrKeyExists
	ErrEncryption     = encerr.ErrEncryption
	ErrDecryption     = encerr.ErrDecryption
	ErrInvalidKeySize = encerr.ErrInvalidKeySize
	ErrKeyRevoked     = encerr.ErrKeyRevoked
	ErrKeyDestroyed   = encerr.ErrKeyDestroyed
)
