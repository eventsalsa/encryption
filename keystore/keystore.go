package keystore

import (
	"context"
	"time"
)

// EncryptedKey represents a stored encrypted DEK.
type EncryptedKey struct {
	Scope        string
	ScopeID      string
	KeyVersion   int
	EncryptedDEK []byte
	SystemKeyID  string
	CreatedAt    time.Time
	RevokedAt    *time.Time
}

// KeyStore manages encrypted DEK storage and retrieval.
type KeyStore interface {
	GetActiveKey(ctx context.Context, scope, scopeID string) (*EncryptedKey, error)
	GetKey(ctx context.Context, scope, scopeID string, version int) (*EncryptedKey, error)
	CreateKey(ctx context.Context, scope, scopeID string, version int, encryptedDEK []byte, systemKeyID string) error
	// RevokeKeys revokes all keys for the scope except the highest version.
	RevokeKeys(ctx context.Context, scope, scopeID string) error
	DestroyKeys(ctx context.Context, scope, scopeID string) error
}
