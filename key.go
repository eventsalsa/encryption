package encryption

import (
	"fmt"
	"strconv"
	"time"
)

// KeyScope uniquely identifies a versioned DEK within a logical namespace.
type KeyScope struct {
	Scope      string
	ScopeID    string
	KeyVersion int
}

// Validate checks that the KeyScope has non-empty Scope, ScopeID, and a positive KeyVersion.
func (s KeyScope) Validate() error {
	if s.Scope == "" {
		return fmt.Errorf("scope is required: %w", ErrInvalidConfig)
	}
	if s.ScopeID == "" {
		return fmt.Errorf("scope ID is required: %w", ErrInvalidConfig)
	}
	if s.KeyVersion <= 0 {
		return fmt.Errorf("key version must be positive, got %d: %w", s.KeyVersion, ErrInvalidConfig)
	}
	return nil
}

// AAD returns a canonical, unambiguous length-prefixed representation of the
// KeyScope ("<len(Scope)>:<Scope>|<len(ScopeID)>:<ScopeID>|<KeyVersion>") used
// as Additional Authenticated Data (AAD) when wrapping, unwrapping, or
// rewrapping a DEK.
func (s KeyScope) AAD() []byte {
	buf := make([]byte, 0, len(s.Scope)+len(s.ScopeID)+24)
	buf = strconv.AppendInt(buf, int64(len(s.Scope)), 10)
	buf = append(buf, ':')
	buf = append(buf, s.Scope...)
	buf = append(buf, '|')
	buf = strconv.AppendInt(buf, int64(len(s.ScopeID)), 10)
	buf = append(buf, ':')
	buf = append(buf, s.ScopeID...)
	buf = append(buf, '|')
	buf = strconv.AppendInt(buf, int64(s.KeyVersion), 10)
	return buf
}

// EncryptedKey represents a wrapped DEK and its lifecycle metadata.
type EncryptedKey struct {
	Scope        string
	ScopeID      string
	KeyVersion   int
	EncryptedDEK []byte
	KEKID        string
	CreatedAt    time.Time
	RevokedAt    *time.Time
}

// KeyScope returns the key's identifying scope tuple.
func (k *EncryptedKey) KeyScope() KeyScope {
	if k == nil {
		return KeyScope{}
	}
	return KeyScope{
		Scope:      k.Scope,
		ScopeID:    k.ScopeID,
		KeyVersion: k.KeyVersion,
	}
}
