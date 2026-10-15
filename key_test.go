package encryption

import (
	"bytes"
	"errors"
	"testing"
)

func TestKeyScopeValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		scope   KeyScope
		wantErr bool
	}{
		{
			name:    "valid",
			scope:   KeyScope{Scope: "user", ScopeID: "u-1", KeyVersion: 1},
			wantErr: false,
		},
		{
			name:    "empty scope",
			scope:   KeyScope{Scope: "", ScopeID: "u-1", KeyVersion: 1},
			wantErr: true,
		},
		{
			name:    "empty scope ID",
			scope:   KeyScope{Scope: "user", ScopeID: "", KeyVersion: 1},
			wantErr: true,
		},
		{
			name:    "zero version",
			scope:   KeyScope{Scope: "user", ScopeID: "u-1", KeyVersion: 0},
			wantErr: true,
		},
		{
			name:    "negative version",
			scope:   KeyScope{Scope: "user", ScopeID: "u-1", KeyVersion: -2},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.scope.Validate()
			if tt.wantErr && !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("Validate() error = %v, want ErrInvalidConfig", err)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("Validate() unexpected error: %v", err)
			}
		})
	}
}

func TestKeyScopeAAD_CanonicalAndCollisionFree(t *testing.T) {
	t.Parallel()

	s1 := KeyScope{Scope: "user", ScopeID: "u-123", KeyVersion: 1}
	if got, want := string(s1.AAD()), "4:user|5:u-123|1"; got != want {
		t.Fatalf("AAD() = %q, want %q", got, want)
	}

	// Ensure delimiter injection attempts produce distinct AAD bytes.
	a := KeyScope{Scope: "a|1:b", ScopeID: "c", KeyVersion: 1}
	b := KeyScope{Scope: "a", ScopeID: "b|1:c", KeyVersion: 1}
	if bytes.Equal(a.AAD(), b.AAD()) {
		t.Fatalf("collision between %+v and %+v: %q", a, b, a.AAD())
	}

	key := EncryptedKey{
		Scope:      "tenant",
		ScopeID:    "t-99",
		KeyVersion: 3,
	}
	if key.KeyScope() != (KeyScope{Scope: "tenant", ScopeID: "t-99", KeyVersion: 3}) {
		t.Fatalf("KeyScope() = %+v", key.KeyScope())
	}
}
