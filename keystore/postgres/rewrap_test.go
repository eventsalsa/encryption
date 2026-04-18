package postgres_test

import (
	"context"
	"strings"
	"testing"

	"github.com/eventsalsa/encryption/cipher"
	"github.com/eventsalsa/encryption/cipher/aesgcm"
	"github.com/eventsalsa/encryption/keystore/postgres"
	"github.com/eventsalsa/encryption/systemkey"
)

func TestRewrapSystemKeys_ValidatesOptions(t *testing.T) {
	store := postgres.NewStore(postgres.Config{}, nil)
	validKeyring := systemkey.NewKeyring(map[string][]byte{
		"old": makeSystemKey(1),
		"new": makeSystemKey(2),
	}, "new")
	validCipher := aesgcm.New()

	tests := []struct {
		name    string
		keyring systemkey.Keyring
		cipher  cipher.Cipher
		opts    postgres.RewrapSystemKeysOptions
		wantErr string
	}{
		{
			name:    "nil keyring",
			cipher:  validCipher,
			opts:    postgres.RewrapSystemKeysOptions{FromSystemKeyID: "old", ToSystemKeyID: "new"},
			wantErr: "keyring is nil",
		},
		{
			name:    "nil cipher",
			keyring: validKeyring,
			opts:    postgres.RewrapSystemKeysOptions{FromSystemKeyID: "old", ToSystemKeyID: "new"},
			wantErr: "cipher is nil",
		},
		{
			name:    "missing source key",
			keyring: validKeyring,
			cipher:  validCipher,
			opts:    postgres.RewrapSystemKeysOptions{ToSystemKeyID: "new"},
			wantErr: "source system key ID is required",
		},
		{
			name:    "missing target key",
			keyring: validKeyring,
			cipher:  validCipher,
			opts:    postgres.RewrapSystemKeysOptions{FromSystemKeyID: "old"},
			wantErr: "target system key ID is required",
		},
		{
			name:    "same source and target",
			keyring: validKeyring,
			cipher:  validCipher,
			opts:    postgres.RewrapSystemKeysOptions{FromSystemKeyID: "old", ToSystemKeyID: "old"},
			wantErr: "source and target system key IDs must differ",
		},
		{
			name:    "negative batch size",
			keyring: validKeyring,
			cipher:  validCipher,
			opts:    postgres.RewrapSystemKeysOptions{FromSystemKeyID: "old", ToSystemKeyID: "new", BatchSize: -1},
			wantErr: "batch size must be positive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := store.RewrapSystemKeys(context.Background(), tt.keyring, tt.cipher, tt.opts)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %q, want substring %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func makeSystemKey(seed byte) []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = seed + byte(i)
	}
	return key
}
