package systemkey

import (
	"fmt"

	"github.com/eventsalsa/encryption/encerr"
)

// Keyring provides access to system-level encryption keys.
type Keyring interface {
	// ActiveKey returns the current active key and its identifier.
	ActiveKey() (key []byte, keyID string)
	// Key returns the key for the given identifier.
	Key(keyID string) ([]byte, error)
}

type memoryKeyring struct {
	keys        map[string][]byte
	activeKeyID string
}

// NewKeyring creates a Keyring backed by the provided in-memory keys.
// It panics if activeKeyID is not present in keys.
func NewKeyring(keys map[string][]byte, activeKeyID string) Keyring {
	if _, ok := keys[activeKeyID]; !ok {
		panic(fmt.Sprintf("systemkey: active key ID %q not found in keys", activeKeyID))
	}
	// Copy the map to prevent external mutation.
	m := make(map[string][]byte, len(keys))
	for id, k := range keys {
		m[id] = k
	}
	return &memoryKeyring{keys: m, activeKeyID: activeKeyID}
}

func (r *memoryKeyring) ActiveKey() (key []byte, keyID string) {
	return r.keys[r.activeKeyID], r.activeKeyID
}

func (r *memoryKeyring) Key(keyID string) ([]byte, error) {
	k, ok := r.keys[keyID]
	if !ok {
		return nil, encerr.ErrKeyNotFound
	}
	return k, nil
}
