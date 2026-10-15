package kek_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/eventsalsa/encryption"
	"github.com/eventsalsa/encryption/kek"
	"github.com/eventsalsa/encryption/kek/local"
)

type nativeRewrapWrapper struct {
	kek.Wrapper
	rewrappedCount *int
	failNative     error
}

func (n *nativeRewrapWrapper) Rewrap(ctx context.Context, target kek.Wrapper, encryptedDEK, sourceAAD, targetAAD []byte) ([]byte, error) {
	if n.failNative != nil {
		return nil, n.failNative
	}
	*n.rewrappedCount++
	dek, err := n.Unwrap(ctx, encryptedDEK, sourceAAD)
	if err != nil {
		return nil, err
	}
	defer encryption.ZeroBytes(dek)
	return target.Wrap(ctx, dek, targetAAD)
}

func makeRawKey(seed byte) []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = seed + byte(i)
	}
	return k
}

func TestNewKeyringValidation(t *testing.T) {
	t.Parallel()

	w1, err := local.NewWrapper("k1", makeRawKey(1))
	if err != nil {
		t.Fatal(err)
	}
	w1Dup, err := local.NewWrapper("k1", makeRawKey(2))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := kek.NewKeyring("", w1); !errors.Is(err, encryption.ErrInvalidConfig) {
		t.Fatalf("empty activeKeyID: err = %v, want ErrInvalidConfig", err)
	}
	if _, err := kek.NewKeyring("k1"); !errors.Is(err, encryption.ErrInvalidConfig) {
		t.Fatalf("no wrappers: err = %v, want ErrInvalidConfig", err)
	}
	if _, err := kek.NewKeyring("k1", nil); !errors.Is(err, encryption.ErrInvalidConfig) {
		t.Fatalf("nil wrapper: err = %v, want ErrInvalidConfig", err)
	}
	if _, err := kek.NewKeyring("k1", w1, w1Dup); !errors.Is(err, encryption.ErrInvalidConfig) {
		t.Fatalf("duplicate wrapper ID: err = %v, want ErrInvalidConfig", err)
	}
	if _, err := kek.NewKeyring("missing", w1); !errors.Is(err, encryption.ErrKeyNotFound) {
		t.Fatalf("missing activeKeyID: err = %v, want ErrKeyNotFound", err)
	}
}

func TestKeyringWrapUnwrapAndRewrapFallback(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	w1, _ := local.NewWrapper("k1", makeRawKey(10))
	w2, _ := local.NewWrapper("k2", makeRawKey(20))

	kr, err := kek.NewKeyring("k1", w1, w2)
	if err != nil {
		t.Fatalf("NewKeyring: %v", err)
	}
	if got := kr.ActiveKeyID(); got != "k1" {
		t.Fatalf("ActiveKeyID() = %q, want k1", got)
	}

	dek := []byte("0123456789abcdef0123456789abcdef")
	aad := []byte("scope:s1:1")

	kekID, encDEK, err := kr.Wrap(ctx, dek, aad)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if kekID != "k1" {
		t.Fatalf("Wrap returned kekID %q, want k1", kekID)
	}

	gotDEK, err := kr.Unwrap(ctx, "k1", encDEK, aad)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if !bytes.Equal(gotDEK, dek) {
		t.Fatalf("Unwrap = %x, want %x", gotDEK, dek)
	}

	// Fallback rewrap (local.Wrapper does not implement Rewrapper)
	targetAAD := []byte("scope:s1:1")
	rewrapped, err := kr.Rewrap(ctx, "k1", "k2", encDEK, aad, targetAAD)
	if err != nil {
		t.Fatalf("Rewrap: %v", err)
	}

	gotFromK2, err := kr.Unwrap(ctx, "k2", rewrapped, targetAAD)
	if err != nil {
		t.Fatalf("Unwrap with k2: %v", err)
	}
	if !bytes.Equal(gotFromK2, dek) {
		t.Fatalf("Unwrap after rewrap = %x, want %x", gotFromK2, dek)
	}
}

func TestKeyringNativeRewrapperAndUnsupportedFallback(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	base1, _ := local.NewWrapper("k1", makeRawKey(1))
	base2, _ := local.NewWrapper("k2", makeRawKey(2))

	nativeCount := 0
	native1 := &nativeRewrapWrapper{
		Wrapper:        base1,
		rewrappedCount: &nativeCount,
	}

	kr, err := kek.NewKeyring("k2", native1, base2)
	if err != nil {
		t.Fatal(err)
	}

	dek := []byte("0123456789abcdef0123456789abcdef")
	aad := []byte("aad")
	encDEK, err := native1.Wrap(ctx, dek, aad)
	if err != nil {
		t.Fatal(err)
	}

	rewrapped, err := kr.Rewrap(ctx, "k1", "k2", encDEK, aad, aad)
	if err != nil {
		t.Fatalf("Rewrap native: %v", err)
	}
	if nativeCount != 1 {
		t.Fatalf("nativeCount = %d, want 1", nativeCount)
	}

	unwrapped, err := kr.Unwrap(ctx, "k2", rewrapped, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(unwrapped, dek) {
		t.Fatal("DEK mismatch after native rewrap")
	}

	// When Rewrapper returns errors.ErrUnsupported, Keyring falls back to Unwrap + Wrap.
	native1.failNative = errors.ErrUnsupported
	rewrappedFallback, err := kr.Rewrap(ctx, "k1", "k2", encDEK, aad, aad)
	if err != nil {
		t.Fatalf("Rewrap fallback on ErrUnsupported: %v", err)
	}
	unwrappedFallback, err := kr.Unwrap(ctx, "k2", rewrappedFallback, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(unwrappedFallback, dek) {
		t.Fatal("DEK mismatch after fallback rewrap")
	}
}
