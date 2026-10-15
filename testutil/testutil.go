// Package testutil provides test helpers for encryption testing.
package testutil

import (
	"crypto/rand"

	"github.com/eventsalsa/encryption/kek"
	"github.com/eventsalsa/encryption/kek/local"
)

// NewTestKeyring creates an in-memory kek.Keyring with a random 32-byte test key.
// The active KEK ID is "test-key-1".
func NewTestKeyring() kek.Keyring {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic("testutil: generate random key: " + err.Error())
	}
	kr, err := local.NewKeyringFromMap(map[string][]byte{"test-key-1": key}, "test-key-1")
	if err != nil {
		panic("testutil: create keyring: " + err.Error())
	}
	return kr
}
