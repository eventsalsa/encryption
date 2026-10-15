package kek

import (
	"bytes"
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eventsalsa/encryption"
)

type countingKeyring struct {
	activeID    string
	wrapCalls   atomic.Int32
	unwrapCalls atomic.Int32
}

func (k *countingKeyring) ActiveKeyID() string {
	return k.activeID
}

func (k *countingKeyring) Wrap(_ context.Context, dek, aad []byte) (kekID string, encryptedDEK []byte, err error) {
	k.wrapCalls.Add(1)
	out := make([]byte, 0, len(dek)+len(aad))
	out = append(out, dek...)
	out = append(out, aad...)
	return k.activeID, out, nil
}

func (k *countingKeyring) Unwrap(_ context.Context, kekID string, encryptedDEK, aad []byte) ([]byte, error) {
	k.unwrapCalls.Add(1)
	if kekID != k.activeID {
		return nil, encryption.ErrKeyNotFound
	}
	if len(encryptedDEK) < len(aad) || !bytes.Equal(encryptedDEK[len(encryptedDEK)-len(aad):], aad) {
		return nil, encryption.ErrDecryption
	}
	out := make([]byte, len(encryptedDEK)-len(aad))
	copy(out, encryptedDEK[:len(encryptedDEK)-len(aad)])
	return out, nil
}

func (k *countingKeyring) Rewrap(ctx context.Context, fromKEKID, toKEKID string, encryptedDEK, sourceAAD, targetAAD []byte) ([]byte, error) {
	dek, err := k.Unwrap(ctx, fromKEKID, encryptedDEK, sourceAAD)
	if err != nil {
		return nil, err
	}
	_, out, err := k.Wrap(ctx, dek, targetAAD)
	return out, err
}

func TestCachingKeyringValidation(t *testing.T) {
	t.Parallel()

	inner := &countingKeyring{activeID: "k1"}
	if _, err := NewCachingKeyring(nil, CacheConfig{TTL: time.Minute, MaxEntries: 10}); !errors.Is(err, encryption.ErrInvalidConfig) {
		t.Fatalf("nil inner: err = %v, want ErrInvalidConfig", err)
	}
	if _, err := NewCachingKeyring(inner, CacheConfig{TTL: 0, MaxEntries: 10}); !errors.Is(err, encryption.ErrInvalidConfig) {
		t.Fatalf("zero TTL: err = %v, want ErrInvalidConfig", err)
	}
	if _, err := NewCachingKeyring(inner, CacheConfig{TTL: time.Minute, MaxEntries: 0}); !errors.Is(err, encryption.ErrInvalidConfig) {
		t.Fatalf("zero MaxEntries: err = %v, want ErrInvalidConfig", err)
	}
}

func TestCachingKeyringHitMissAndDefensiveCopy(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	inner := &countingKeyring{activeID: "k1"}
	cache, err := NewCachingKeyring(inner, CacheConfig{TTL: 5 * time.Minute, MaxEntries: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Close()

	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	cache.now = func() time.Time { return now }

	dek := []byte("0123456789abcdef0123456789abcdef")
	aad := []byte("user:u-1:1")

	// Wrap populates the cache.
	kekID, encDEK, err := cache.Wrap(ctx, dek, aad)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if kekID != "k1" {
		t.Fatalf("kekID = %q, want k1", kekID)
	}

	// First Unwrap hits the cache (0 inner unwrap calls).
	got1, err := cache.Unwrap(ctx, "k1", encDEK, aad)
	if err != nil {
		t.Fatalf("Unwrap 1: %v", err)
	}
	if inner.unwrapCalls.Load() != 0 {
		t.Fatalf("unwrapCalls = %d, want 0 (cache hit from Wrap)", inner.unwrapCalls.Load())
	}

	// Scrubbing the returned slice must NOT corrupt the cached copy!
	encryption.ZeroBytes(got1)

	got2, err := cache.Unwrap(ctx, "k1", encDEK, aad)
	if err != nil {
		t.Fatalf("Unwrap 2: %v", err)
	}
	if !bytes.Equal(got2, dek) {
		t.Fatalf("cached DEK was corrupted by caller ZeroBytes: got %x, want %x", got2, dek)
	}

	// Advance clock past TTL -> cache miss triggers inner.Unwrap.
	now = now.Add(6 * time.Minute)
	got3, err := cache.Unwrap(ctx, "k1", encDEK, aad)
	if err != nil {
		t.Fatalf("Unwrap after TTL expiry: %v", err)
	}
	if inner.unwrapCalls.Load() != 1 {
		t.Fatalf("unwrapCalls = %d, want 1 after TTL expiry", inner.unwrapCalls.Load())
	}
	if !bytes.Equal(got3, dek) {
		t.Fatalf("got %x, want %x", got3, dek)
	}
}

func TestCachingKeyringLRUEvictionAndClose(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	inner := &countingKeyring{activeID: "k1"}
	cache, err := NewCachingKeyring(inner, CacheConfig{TTL: time.Hour, MaxEntries: 2})
	if err != nil {
		t.Fatal(err)
	}

	dek1 := []byte("11111111111111111111111111111111")
	dek2 := []byte("22222222222222222222222222222222")
	dek3 := []byte("33333333333333333333333333333333")
	aad := []byte("aad")

	_, enc1, _ := cache.Wrap(ctx, dek1, aad)
	_, enc2, _ := cache.Wrap(ctx, dek2, aad)

	// Touch enc1 so enc2 becomes the least-recently-used.
	_, _ = cache.Unwrap(ctx, "k1", enc1, aad)

	// Wrapping dek3 evicts enc2.
	_, _, _ = cache.Wrap(ctx, dek3, aad)

	// enc1 should still be cached (0 inner unwraps).
	_, _ = cache.Unwrap(ctx, "k1", enc1, aad)
	if inner.unwrapCalls.Load() != 0 {
		t.Fatalf("enc1 should be a cache hit, got %d inner unwraps", inner.unwrapCalls.Load())
	}

	// enc2 was evicted (triggers 1 inner unwrap).
	_, _ = cache.Unwrap(ctx, "k1", enc2, aad)
	if inner.unwrapCalls.Load() != 1 {
		t.Fatalf("enc2 should be a cache miss, got %d inner unwraps", inner.unwrapCalls.Load())
	}

	cache.Invalidate()
	_, _ = cache.Unwrap(ctx, "k1", enc1, aad)
	if inner.unwrapCalls.Load() != 2 {
		t.Fatalf("after Invalidate, enc1 should miss, got %d inner unwraps", inner.unwrapCalls.Load())
	}

	cache.Close()
	if _, err := cache.Unwrap(ctx, "k1", enc1, aad); !errors.Is(err, encryption.ErrSessionClosed) {
		t.Fatalf("Unwrap after Close: err = %v, want ErrSessionClosed", err)
	}
	if _, _, err := cache.Wrap(ctx, dek1, aad); !errors.Is(err, encryption.ErrSessionClosed) {
		t.Fatalf("Wrap after Close: err = %v, want ErrSessionClosed", err)
	}
}
