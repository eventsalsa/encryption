package hash //nolint:revive // intentional name matching domain concept

import (
	"encoding/hex"
	"testing"
)

func TestHMACHasher_Determinism(t *testing.T) {
	key := []byte("test-key")
	h := NewHMACHasher(key)

	tests := []struct {
		name  string
		input string
	}{
		{"empty string", ""},
		{"simple text", "hello"},
		{"longer text", "the quick brown fox jumps over the lazy dog"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash1 := h.Hash(tt.input)
			hash2 := h.Hash(tt.input)
			if hash1 != hash2 {
				t.Errorf("Hash is not deterministic: got %q and %q", hash1, hash2)
			}
		})
	}
}

func TestHMACHasher_DifferentInputs(t *testing.T) {
	key := []byte("test-key")
	h := NewHMACHasher(key)

	tests := []struct {
		name   string
		inputA string
		inputB string
	}{
		{"distinct words", "hello", "world"},
		{"empty vs non-empty", "", "a"},
		{"similar strings", "abc", "abd"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hashA := h.Hash(tt.inputA)
			hashB := h.Hash(tt.inputB)
			if hashA == hashB {
				t.Errorf("Different inputs produced same hash: %q", hashA)
			}
		})
	}
}

func TestHMACHasher_DifferentKeys(t *testing.T) {
	tests := []struct {
		name string
		keyA []byte
		keyB []byte
	}{
		{"distinct keys", []byte("key-one"), []byte("key-two")},
		{"short vs long", []byte("a"), []byte("ab")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hA := NewHMACHasher(tt.keyA)
			hB := NewHMACHasher(tt.keyB)
			input := "same-input"
			hashA := hA.Hash(input)
			hashB := hB.Hash(input)
			if hashA == hashB {
				t.Errorf("Different keys produced same hash: %q", hashA)
			}
		})
	}
}

func TestHMACHasher_HexOutput(t *testing.T) {
	key := []byte("test-key")
	h := NewHMACHasher(key)

	// SHA-256 HMAC produces 32 bytes = 64 hex characters
	const expectedLen = 64

	tests := []struct {
		name  string
		input string
	}{
		{"empty string", ""},
		{"short string", "hi"},
		{"long string", "a]longer input string for testing purposes"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := h.Hash(tt.input)
			if len(result) != expectedLen {
				t.Errorf("Expected length %d, got %d", expectedLen, len(result))
			}
			if _, err := hex.DecodeString(result); err != nil {
				t.Errorf("Output is not valid hex: %q", result)
			}
		})
	}
}
