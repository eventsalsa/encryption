package envelope_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/eventsalsa/encryption"
	"github.com/eventsalsa/encryption/cipher/aesgcm"
	"github.com/eventsalsa/encryption/envelope"
	"github.com/eventsalsa/encryption/kek/local"
)

func setupTestEnvelope(t *testing.T) (env *envelope.Envelope, kekID string) {
	t.Helper()

	c := aesgcm.New()
	rawKEK := make([]byte, c.KeySize())
	if _, err := rand.Read(rawKEK); err != nil {
		t.Fatalf("generate KEK: %v", err)
	}

	kekID = "kek-1"
	keyring, err := local.NewKeyringFromMap(map[string][]byte{kekID: rawKEK}, kekID)
	if err != nil {
		t.Fatalf("NewKeyringFromMap: %v", err)
	}
	return envelope.New(keyring, c), kekID
}

func makeEncryptedKey(t *testing.T, env *envelope.Envelope, scope encryption.KeyScope) *encryption.EncryptedKey {
	t.Helper()
	ctx := context.Background()

	dek, err := env.GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK: %v", err)
	}
	defer encryption.ZeroBytes(dek)

	kekID, encDEK, err := env.WrapDEK(ctx, scope, dek)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}

	return &encryption.EncryptedKey{
		Scope:        scope.Scope,
		ScopeID:      scope.ScopeID,
		KeyVersion:   scope.KeyVersion,
		EncryptedDEK: encDEK,
		KEKID:        kekID,
	}
}

func TestEnvelopeBytesAndStringRoundtrip(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	env, _ := setupTestEnvelope(t)

	scope := encryption.KeyScope{Scope: "user-pii", ScopeID: "u-123", KeyVersion: 1}
	key := makeEncryptedKey(t, env, scope)

	payloadAAD := []byte("field:email")
	plaintext := []byte("alice@example.com")

	ct, err := env.Encrypt(ctx, key, plaintext, payloadAAD)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Mismatched payload AAD must fail
	if _, err := env.Decrypt(ctx, key, ct, []byte("field:phone")); !errors.Is(err, encryption.ErrDecryption) {
		t.Fatalf("Decrypt with wrong payload AAD: err = %v, want ErrDecryption", err)
	}

	pt, err := env.Decrypt(ctx, key, ct, payloadAAD)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("got %q, want %q", pt, plaintext)
	}

	// String roundtrip
	strCT, err := env.EncryptString(ctx, key, "hello string", payloadAAD)
	if err != nil {
		t.Fatalf("EncryptString: %v", err)
	}
	strPT, err := env.DecryptString(ctx, key, strCT, payloadAAD)
	if err != nil {
		t.Fatalf("DecryptString: %v", err)
	}
	if strPT != "hello string" {
		t.Fatalf("got %q, want %q", strPT, "hello string")
	}
}

func TestEnvelopeScopeAAD_PreventsCiphertextTransplant(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	env, _ := setupTestEnvelope(t)

	scopeA := encryption.KeyScope{Scope: "user", ScopeID: "alice", KeyVersion: 1}
	keyA := makeEncryptedKey(t, env, scopeA)

	// Simulate an attacker transplanting Alice's EncryptedDEK onto Bob's row or a different version.
	transplantedScopeID := *keyA
	transplantedScopeID.ScopeID = "bob"
	if _, err := env.UnwrapDEK(ctx, &transplantedScopeID); !errors.Is(err, encryption.ErrDecryption) {
		t.Fatalf("expected ErrDecryption when ScopeID is transplanted, got %v", err)
	}

	transplantedScope := *keyA
	transplantedScope.Scope = "admin"
	if _, err := env.UnwrapDEK(ctx, &transplantedScope); !errors.Is(err, encryption.ErrDecryption) {
		t.Fatalf("expected ErrDecryption when Scope is transplanted, got %v", err)
	}

	transplantedVersion := *keyA
	transplantedVersion.KeyVersion = 2
	if _, err := env.UnwrapDEK(ctx, &transplantedVersion); !errors.Is(err, encryption.ErrDecryption) {
		t.Fatalf("expected ErrDecryption when KeyVersion is transplanted, got %v", err)
	}
}

func TestEnvelopeSessionLifecycle(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	env, _ := setupTestEnvelope(t)

	key := makeEncryptedKey(t, env, encryption.KeyScope{Scope: "stream", ScopeID: "s-1", KeyVersion: 1})

	session, err := env.OpenSession(ctx, key)
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}

	ct1, err := session.Encrypt([]byte("event-1"), []byte("seq:1"))
	if err != nil {
		t.Fatalf("session.Encrypt 1: %v", err)
	}
	ct2, err := session.EncryptString("event-2", []byte("seq:2"))
	if err != nil {
		t.Fatalf("session.EncryptString 2: %v", err)
	}

	pt1, err := session.Decrypt(ct1, []byte("seq:1"))
	if err != nil {
		t.Fatalf("session.Decrypt 1: %v", err)
	}
	if string(pt1) != "event-1" {
		t.Fatalf("got %q, want event-1", pt1)
	}

	pt2, err := session.DecryptString(ct2, []byte("seq:2"))
	if err != nil {
		t.Fatalf("session.DecryptString 2: %v", err)
	}
	if pt2 != "event-2" {
		t.Fatalf("got %q, want event-2", pt2)
	}

	// Close scrubs the DEK and rejects any further use.
	session.Close()
	session.Close() // Idempotent

	if _, err := session.Encrypt([]byte("x"), nil); !errors.Is(err, encryption.ErrSessionClosed) {
		t.Fatalf("Encrypt after Close: err = %v, want ErrSessionClosed", err)
	}
	if _, err := session.Decrypt(ct1, []byte("seq:1")); !errors.Is(err, encryption.ErrSessionClosed) {
		t.Fatalf("Decrypt after Close: err = %v, want ErrSessionClosed", err)
	}
}

func TestEnvelopeRewrapDEK(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	c := aesgcm.New()
	k1 := make([]byte, 32)
	k2 := make([]byte, 32)
	_, _ = rand.Read(k1)
	_, _ = rand.Read(k2)

	kr, err := local.NewKeyringFromMap(map[string][]byte{
		"kek-1": k1,
		"kek-2": k2,
	}, "kek-1")
	if err != nil {
		t.Fatal(err)
	}
	env := envelope.New(kr, c)

	scope := encryption.KeyScope{Scope: "user", ScopeID: "u-1", KeyVersion: 1}
	key := makeEncryptedKey(t, env, scope)

	ct, err := env.EncryptString(ctx, key, "secret-payload", nil)
	if err != nil {
		t.Fatal(err)
	}

	rewrappedDEK, err := env.RewrapDEK(ctx, key, "kek-2")
	if err != nil {
		t.Fatalf("RewrapDEK: %v", err)
	}

	rewrappedKey := *key
	rewrappedKey.KEKID = "kek-2"
	rewrappedKey.EncryptedDEK = rewrappedDEK

	pt, err := env.DecryptString(ctx, &rewrappedKey, ct, nil)
	if err != nil {
		t.Fatalf("DecryptString after RewrapDEK: %v", err)
	}
	if pt != "secret-payload" {
		t.Fatalf("got %q, want secret-payload", pt)
	}
}

func TestEnvelopeUnknownKEK(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	env, _ := setupTestEnvelope(t)

	key := &encryption.EncryptedKey{
		Scope:        "user",
		ScopeID:      "u-1",
		KeyVersion:   1,
		EncryptedDEK: []byte("dummy"),
		KEKID:        "unknown-kek",
	}

	if _, err := env.Encrypt(ctx, key, []byte("data"), nil); !errors.Is(err, encryption.ErrKeyNotFound) {
		t.Fatalf("Encrypt unknown KEK: err = %v, want ErrKeyNotFound", err)
	}
	if _, err := env.Decrypt(ctx, key, []byte("data"), nil); !errors.Is(err, encryption.ErrKeyNotFound) {
		t.Fatalf("Decrypt unknown KEK: err = %v, want ErrKeyNotFound", err)
	}
}

func TestEnvelopeActiveKEKID(t *testing.T) {
	t.Parallel()
	env, kekID := setupTestEnvelope(t)

	if got := env.ActiveKEKID(); got != kekID {
		t.Fatalf("ActiveKEKID: got %q, want %q", got, kekID)
	}
}
