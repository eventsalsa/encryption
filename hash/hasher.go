package hash //nolint:revive // intentional name matching domain concept

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// Hasher defines the interface for hashing plaintext strings.
type Hasher interface {
	Hash(plaintext string) string
}

// HMACHasher implements Hasher using HMAC-SHA256.
type HMACHasher struct {
	key []byte
}

// NewHMACHasher returns an HMACHasher keyed with the given secret.
func NewHMACHasher(key []byte) *HMACHasher {
	return &HMACHasher{key: key}
}

// Hash returns the HMAC-SHA256 hex digest of plaintext.
func (h *HMACHasher) Hash(plaintext string) string {
	mac := hmac.New(sha256.New, h.key)
	mac.Write([]byte(plaintext))
	return hex.EncodeToString(mac.Sum(nil))
}
