// Package local implements an in-process symmetric kek.Wrapper using a cipher.Cipher
// (AES-256-GCM by default) and provides in-memory and file-based KEK loaders.
package local

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/eventsalsa/encryption"
	"github.com/eventsalsa/encryption/cipher"
	"github.com/eventsalsa/encryption/cipher/aesgcm"
	"github.com/eventsalsa/encryption/kek"
)

// Option configures a local Wrapper.
type Option func(*Wrapper)

// WithCipher overrides the default AES-256-GCM cipher used to wrap/unwrap DEKs.
func WithCipher(c cipher.Cipher) Option {
	return func(w *Wrapper) {
		if c != nil {
			w.cipher = c
		}
	}
}

// Wrapper implements kek.Wrapper in-process using a symmetric key and cipher.Cipher.
// Safe for concurrent use.
type Wrapper struct {
	id     string
	cipher cipher.Cipher

	mu     sync.RWMutex
	key    []byte
	closed bool
}

// NewWrapper creates an in-process KEK Wrapper with a defensive copy of rawKey.
func NewWrapper(id string, rawKey []byte, opts ...Option) (*Wrapper, error) {
	if id == "" {
		return nil, fmt.Errorf("local kek: key ID is required: %w", encryption.ErrInvalidConfig)
	}

	w := &Wrapper{
		id:     id,
		cipher: aesgcm.New(),
	}
	for _, opt := range opts {
		opt(w)
	}

	if len(rawKey) != w.cipher.KeySize() {
		return nil, fmt.Errorf("local kek %q: key is %d bytes, want %d: %w", id, len(rawKey), w.cipher.KeySize(), encryption.ErrInvalidKeySize)
	}

	w.key = make([]byte, len(rawKey))
	copy(w.key, rawKey)
	return w, nil
}

// ID returns the unique identifier of this KEK.
func (w *Wrapper) ID() string {
	return w.id
}

// Wrap encrypts a plaintext DEK with the local KEK and binds it to aad.
func (w *Wrapper) Wrap(_ context.Context, dek, aad []byte) ([]byte, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()

	if w.closed {
		return nil, encryption.ErrSessionClosed
	}

	return w.cipher.Encrypt(w.key, dek, aad)
}

// Unwrap decrypts an encrypted DEK with the local KEK and verifies aad.
func (w *Wrapper) Unwrap(_ context.Context, encryptedDEK, aad []byte) ([]byte, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()

	if w.closed {
		return nil, encryption.ErrSessionClosed
	}

	return w.cipher.Decrypt(w.key, encryptedDEK, aad)
}

// Close scrubs the local KEK bytes from memory and marks the wrapper as closed.
func (w *Wrapper) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.closed {
		encryption.ZeroBytes(w.key)
		w.key = nil
		w.closed = true
	}
}

// NewKeyringFromMap constructs a kek.Keyring from a map of key IDs to raw key bytes.
func NewKeyringFromMap(keys map[string][]byte, activeKeyID string, opts ...Option) (kek.Keyring, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("local kek: keys map is empty: %w", encryption.ErrInvalidConfig)
	}

	wrappers := make([]kek.Wrapper, 0, len(keys))
	for id, rawKey := range keys {
		w, err := NewWrapper(id, rawKey, opts...)
		if err != nil {
			return nil, err
		}
		wrappers = append(wrappers, w)
	}

	return kek.NewKeyring(activeKeyID, wrappers...)
}

// FileConfig holds the configuration for loading local KEKs from files.
type FileConfig struct {
	// KeyPaths maps KEK IDs to file paths containing base64-encoded keys.
	KeyPaths    map[string]string
	ActiveKeyID string
}

// NewKeyringFromFiles reads base64-encoded keys from the configured file paths
// and returns a kek.Keyring.
func NewKeyringFromFiles(cfg FileConfig, opts ...Option) (kek.Keyring, error) {
	if len(cfg.KeyPaths) == 0 {
		return nil, fmt.Errorf("local kek: KeyPaths is empty: %w", encryption.ErrInvalidConfig)
	}

	keys := make(map[string][]byte, len(cfg.KeyPaths))
	defer func() {
		for _, k := range keys {
			encryption.ZeroBytes(k)
		}
	}()

	for id, path := range cfg.KeyPaths {
		data, err := os.ReadFile(path) //#nosec G304 -- KeyPaths are provided by trusted configuration, not user input //nolint:gosec
		if err != nil {
			return nil, fmt.Errorf("local kek: reading key %q: %w", id, err)
		}
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
		if err != nil {
			return nil, fmt.Errorf("local kek: decoding key %q: %w", id, err)
		}
		keys[id] = decoded
	}

	return NewKeyringFromMap(keys, cfg.ActiveKeyID, opts...)
}
