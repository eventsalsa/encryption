// Package kek defines Key Encryption Key (KEK) abstractions for wrapping,
// unwrapping, and rewrapping Data Encryption Keys (DEKs).
//
// Implementations may execute locally in memory (e.g., kek/local) or delegate
// cryptographic operations to remote cloud KMS / HSM services (e.g., kek/awskms,
// kek/gcpkms) where the KEK material never leaves the remote boundary.
package kek

import (
	"context"
	"errors"
	"fmt"

	"github.com/eventsalsa/encryption"
)

// Wrapper encrypts and decrypts Data Encryption Keys (DEKs) using a single KEK.
// Implementations must be safe for concurrent use.
type Wrapper interface {
	// ID returns the unique KEK identifier persisted alongside wrapped DEKs.
	ID() string

	// Wrap encrypts a plaintext DEK, cryptographically binding it to aad.
	Wrap(ctx context.Context, dek, aad []byte) (encryptedDEK []byte, err error)

	// Unwrap decrypts an encrypted DEK and verifies aad.
	// Callers must scrub the returned slice with encryption.ZeroBytes when done.
	Unwrap(ctx context.Context, encryptedDEK, aad []byte) (dek []byte, err error)
}

// Rewrapper is an optional interface implemented by KEK wrappers that support
// native server-side re-encryption (e.g., AWS KMS ReEncrypt) without exposing
// the plaintext DEK to application memory.
//
// If a Rewrapper cannot natively re-encrypt to the given target Wrapper (for
// example, when migrating across different KMS providers), it should return
// errors.ErrUnsupported so Keyring.Rewrap automatically falls back to Unwrap + Wrap.
type Rewrapper interface {
	Rewrap(ctx context.Context, target Wrapper, encryptedDEK, sourceAAD, targetAAD []byte) ([]byte, error)
}

// Keyring coordinates an active KEK Wrapper for new DEK wrapping and a set of
// historical KEK Wrappers for unwrapping and rewrapping existing DEKs.
type Keyring interface {
	// ActiveKeyID returns the ID of the KEK used for new Wrap operations.
	ActiveKeyID() string

	// Wrap encrypts a DEK using the active KEK, binding it to aad.
	Wrap(ctx context.Context, dek, aad []byte) (kekID string, encryptedDEK []byte, err error)

	// Unwrap decrypts an encrypted DEK using the KEK identified by kekID and verifies aad.
	// Callers must scrub the returned slice with encryption.ZeroBytes when done.
	Unwrap(ctx context.Context, kekID string, encryptedDEK, aad []byte) (dek []byte, err error)

	// Rewrap re-encrypts an encrypted DEK from fromKEKID to toKEKID, verifying
	// sourceAAD and binding targetAAD.
	Rewrap(ctx context.Context, fromKEKID, toKEKID string, encryptedDEK, sourceAAD, targetAAD []byte) ([]byte, error)
}

type standardKeyring struct {
	wrappers    map[string]Wrapper
	activeKeyID string
}

// NewKeyring constructs a Keyring from one or more Wrappers, designating
// activeKeyID as the active KEK for new Wrap operations.
func NewKeyring(activeKeyID string, wrappers ...Wrapper) (Keyring, error) {
	if activeKeyID == "" {
		return nil, fmt.Errorf("kek: active key ID is required: %w", encryption.ErrInvalidConfig)
	}
	if len(wrappers) == 0 {
		return nil, fmt.Errorf("kek: at least one wrapper is required: %w", encryption.ErrInvalidConfig)
	}

	m := make(map[string]Wrapper, len(wrappers))
	for _, w := range wrappers {
		if w == nil {
			return nil, fmt.Errorf("kek: wrapper is nil: %w", encryption.ErrInvalidConfig)
		}
		id := w.ID()
		if id == "" {
			return nil, fmt.Errorf("kek: wrapper ID must not be empty: %w", encryption.ErrInvalidConfig)
		}
		if _, exists := m[id]; exists {
			return nil, fmt.Errorf("kek: duplicate wrapper ID %q: %w", id, encryption.ErrInvalidConfig)
		}
		m[id] = w
	}

	if _, ok := m[activeKeyID]; !ok {
		return nil, fmt.Errorf("kek: active key ID %q not found in wrappers: %w", activeKeyID, encryption.ErrKeyNotFound)
	}

	return &standardKeyring{
		wrappers:    m,
		activeKeyID: activeKeyID,
	}, nil
}

func (r *standardKeyring) ActiveKeyID() string {
	return r.activeKeyID
}

func (r *standardKeyring) Wrap(ctx context.Context, dek, aad []byte) (kekID string, encryptedDEK []byte, err error) {
	w := r.wrappers[r.activeKeyID]
	encDEK, err := w.Wrap(ctx, dek, aad)
	if err != nil {
		return "", nil, fmt.Errorf("kek wrap with %q: %w", r.activeKeyID, err)
	}
	return r.activeKeyID, encDEK, nil
}

func (r *standardKeyring) Unwrap(ctx context.Context, kekID string, encryptedDEK, aad []byte) ([]byte, error) {
	w, ok := r.wrappers[kekID]
	if !ok {
		return nil, fmt.Errorf("kek unwrap: key %q: %w", kekID, encryption.ErrKeyNotFound)
	}
	dek, err := w.Unwrap(ctx, encryptedDEK, aad)
	if err != nil {
		return nil, fmt.Errorf("kek unwrap with %q: %w", kekID, err)
	}
	return dek, nil
}

func (r *standardKeyring) Rewrap(ctx context.Context, fromKEKID, toKEKID string, encryptedDEK, sourceAAD, targetAAD []byte) ([]byte, error) {
	source, ok := r.wrappers[fromKEKID]
	if !ok {
		return nil, fmt.Errorf("kek rewrap: source key %q: %w", fromKEKID, encryption.ErrKeyNotFound)
	}
	target, ok := r.wrappers[toKEKID]
	if !ok {
		return nil, fmt.Errorf("kek rewrap: target key %q: %w", toKEKID, encryption.ErrKeyNotFound)
	}

	if rewrapper, ok := source.(Rewrapper); ok {
		rewrapped, err := rewrapper.Rewrap(ctx, target, encryptedDEK, sourceAAD, targetAAD)
		if err == nil {
			return rewrapped, nil
		}
		if !errors.Is(err, errors.ErrUnsupported) {
			return nil, fmt.Errorf("kek native rewrap from %q to %q: %w", fromKEKID, toKEKID, err)
		}
	}

	dek, err := source.Unwrap(ctx, encryptedDEK, sourceAAD)
	if err != nil {
		return nil, fmt.Errorf("kek rewrap unwrap with %q: %w", fromKEKID, err)
	}
	defer encryption.ZeroBytes(dek)

	rewrapped, err := target.Wrap(ctx, dek, targetAAD)
	if err != nil {
		return nil, fmt.Errorf("kek rewrap wrap with %q: %w", toKEKID, err)
	}
	return rewrapped, nil
}
