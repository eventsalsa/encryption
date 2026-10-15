package postgres_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/eventsalsa/encryption"
	"github.com/eventsalsa/encryption/cipher/aesgcm"
	"github.com/eventsalsa/encryption/envelope"
	"github.com/eventsalsa/encryption/kek/local"
	"github.com/eventsalsa/encryption/postgres"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestRewrapKeys_ValidatesOptions(t *testing.T) {
	t.Parallel()

	dummyPool := &pgxpool.Pool{}
	validKeyring, err := local.NewKeyringFromMap(map[string][]byte{
		"old": makeSystemKey(1),
		"new": makeSystemKey(2),
	}, "new")
	if err != nil {
		t.Fatal(err)
	}
	validEnv := envelope.New(validKeyring, aesgcm.New())

	tests := []struct {
		name    string
		pool    *pgxpool.Pool
		env     *envelope.Envelope
		opts    postgres.RewrapKeysOptions
		wantErr string
	}{
		{
			name:    "nil pool",
			pool:    nil,
			env:     validEnv,
			opts:    postgres.RewrapKeysOptions{FromKEKID: "old", ToKEKID: "new"},
			wantErr: "pool is nil",
		},
		{
			name:    "nil envelope",
			pool:    dummyPool,
			env:     nil,
			opts:    postgres.RewrapKeysOptions{FromKEKID: "old", ToKEKID: "new"},
			wantErr: "envelope is nil",
		},
		{
			name:    "missing source key",
			pool:    dummyPool,
			env:     validEnv,
			opts:    postgres.RewrapKeysOptions{ToKEKID: "new"},
			wantErr: "source KEK ID is required",
		},
		{
			name:    "missing target key",
			pool:    dummyPool,
			env:     validEnv,
			opts:    postgres.RewrapKeysOptions{FromKEKID: "old"},
			wantErr: "target KEK ID is required",
		},
		{
			name:    "same source and target",
			pool:    dummyPool,
			env:     validEnv,
			opts:    postgres.RewrapKeysOptions{FromKEKID: "old", ToKEKID: "old"},
			wantErr: "source and target KEK IDs must differ",
		},
		{
			name:    "negative batch size",
			pool:    dummyPool,
			env:     validEnv,
			opts:    postgres.RewrapKeysOptions{FromKEKID: "old", ToKEKID: "new", BatchSize: -1},
			wantErr: "batch size must be positive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := postgres.RewrapKeys(context.Background(), tt.pool, postgres.Config{}, tt.env, tt.opts)
			if !errors.Is(err, encryption.ErrInvalidConfig) {
				t.Fatalf("error = %v, want ErrInvalidConfig", err)
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
