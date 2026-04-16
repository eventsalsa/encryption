package systemkey

import (
	"bytes"
	"errors"
	"testing"

	"github.com/eventsalsa/encryption/encerr"
)

func TestActiveKey(t *testing.T) {
	keys := map[string][]byte{
		"k1": {1, 2, 3},
		"k2": {4, 5, 6},
	}
	kr := NewKeyring(keys, "k1")

	got, id := kr.ActiveKey()
	if id != "k1" {
		t.Fatalf("ActiveKey() keyID = %q, want %q", id, "k1")
	}
	if !bytes.Equal(got, keys["k1"]) {
		t.Fatalf("ActiveKey() key = %v, want %v", got, keys["k1"])
	}
}

func TestKey(t *testing.T) {
	keys := map[string][]byte{
		"k1": {1, 2, 3},
		"k2": {4, 5, 6},
	}
	kr := NewKeyring(keys, "k1")

	tests := []struct {
		name    string
		keyID   string
		want    []byte
		wantErr error
	}{
		{
			name:  "existing key",
			keyID: "k2",
			want:  []byte{4, 5, 6},
		},
		{
			name:    "missing key",
			keyID:   "k3",
			wantErr: encerr.ErrKeyNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := kr.Key(tt.keyID)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("Key(%q) error = %v, want %v", tt.keyID, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Key(%q) unexpected error: %v", tt.keyID, err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Fatalf("Key(%q) = %v, want %v", tt.keyID, got, tt.want)
			}
		})
	}
}

func TestNewKeyringPanicsOnMissingActiveKey(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("NewKeyring did not panic for missing activeKeyID")
		}
	}()
	NewKeyring(map[string][]byte{"k1": {1}}, "missing")
}
