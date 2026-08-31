// Package testutil provides test helpers for encryption testing.
package testutil

import (
	"crypto/rand"

	"github.com/eventsalsa/encryption/systemkey"
)

// NewTestKeyring creates an in-memory keyring with a random 32-byte test key.
// The active key ID is "test-key-1".
func NewTestKeyring() systemkey.Keyring {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic("testutil: generate random key: " + err.Error())
	}
	return systemkey.NewKeyring(map[string][]byte{"test-key-1": key}, "test-key-1")
}
