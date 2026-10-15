package kek

import (
	"container/list"
	"context"
	"crypto/sha256"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/eventsalsa/encryption"
)

// CacheConfig configures a CachingKeyring.
type CacheConfig struct {
	// TTL is the maximum duration a decrypted DEK remains valid in the cache.
	// Must be positive.
	TTL time.Duration

	// MaxEntries is the maximum number of decrypted DEKs held in memory at once.
	// When exceeded, the least-recently-used entry is evicted and zeroed.
	// Must be positive.
	MaxEntries int
}

type cacheEntry struct {
	key       [32]byte
	dek       []byte
	expiresAt time.Time
}

// CachingKeyring decorates a Keyring with a bounded, TTL-expiring LRU cache of
// unwrapped DEKs to minimize remote KMS RPC latency, costs, and rate limits.
//
// All cached DEK slices are defensive copies and are scrubbed from memory via
// encryption.ZeroBytes upon TTL expiration, LRU eviction, Invalidate, or Close.
type CachingKeyring struct {
	inner      Keyring
	ttl        time.Duration
	maxEntries int
	now        func() time.Time

	mu     sync.Mutex
	items  map[[32]byte]*list.Element
	order  *list.List
	closed bool
}

// NewCachingKeyring wraps inner with an in-memory LRU DEK cache.
func NewCachingKeyring(inner Keyring, cfg CacheConfig) (*CachingKeyring, error) {
	if inner == nil {
		return nil, fmt.Errorf("kek cache: inner keyring is nil: %w", encryption.ErrInvalidConfig)
	}
	if cfg.TTL <= 0 {
		return nil, fmt.Errorf("kek cache: TTL must be positive: %w", encryption.ErrInvalidConfig)
	}
	if cfg.MaxEntries <= 0 {
		return nil, fmt.Errorf("kek cache: MaxEntries must be positive: %w", encryption.ErrInvalidConfig)
	}

	return &CachingKeyring{
		inner:      inner,
		ttl:        cfg.TTL,
		maxEntries: cfg.MaxEntries,
		now:        time.Now,
		items:      make(map[[32]byte]*list.Element),
		order:      list.New(),
	}, nil
}

// ActiveKeyID returns the active KEK identifier from the underlying keyring.
func (c *CachingKeyring) ActiveKeyID() string {
	return c.inner.ActiveKeyID()
}

// Wrap delegates DEK wrapping to the underlying keyring and populates the cache
// with a defensive copy of the plaintext DEK.
func (c *CachingKeyring) Wrap(ctx context.Context, dek, aad []byte) (kekID string, encryptedDEK []byte, err error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return "", nil, encryption.ErrSessionClosed
	}
	c.mu.Unlock()

	kekID, encryptedDEK, err = c.inner.Wrap(ctx, dek, aad)
	if err != nil {
		return "", nil, err
	}

	cacheKey := computeCacheKey(kekID, encryptedDEK, aad)
	c.put(cacheKey, dek)

	return kekID, encryptedDEK, nil
}

// Unwrap returns a defensive copy of the plaintext DEK from the cache on a hit,
// or delegates to the underlying keyring and caches the result on a miss.
func (c *CachingKeyring) Unwrap(ctx context.Context, kekID string, encryptedDEK, aad []byte) ([]byte, error) {
	cacheKey := computeCacheKey(kekID, encryptedDEK, aad)

	if dek, ok := c.get(cacheKey); ok {
		return dek, nil
	}

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, encryption.ErrSessionClosed
	}
	c.mu.Unlock()

	dek, err := c.inner.Unwrap(ctx, kekID, encryptedDEK, aad)
	if err != nil {
		return nil, err
	}

	c.put(cacheKey, dek)
	return dek, nil
}

// Rewrap delegates DEK rewrapping to the underlying keyring.
func (c *CachingKeyring) Rewrap(ctx context.Context, fromKEKID, toKEKID string, encryptedDEK, sourceAAD, targetAAD []byte) ([]byte, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, encryption.ErrSessionClosed
	}
	c.mu.Unlock()

	return c.inner.Rewrap(ctx, fromKEKID, toKEKID, encryptedDEK, sourceAAD, targetAAD)
}

// Invalidate scrubs and removes all currently cached DEKs from memory.
func (c *CachingKeyring) Invalidate() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.clearLocked()
}

// Close scrubs all cached DEKs from memory and marks the CachingKeyring as closed.
func (c *CachingKeyring) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.clearLocked()
	c.closed = true
}

func (c *CachingKeyring) get(key [32]byte) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil, false
	}

	elem, ok := c.items[key]
	if !ok {
		return nil, false
	}

	entry := elem.Value.(*cacheEntry)
	if !c.now().Before(entry.expiresAt) {
		c.removeElementLocked(elem)
		return nil, false
	}

	c.order.MoveToFront(elem)
	out := make([]byte, len(entry.dek))
	copy(out, entry.dek)
	return out, true
}

func (c *CachingKeyring) put(key [32]byte, dek []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return
	}

	now := c.now()

	if elem, ok := c.items[key]; ok {
		entry := elem.Value.(*cacheEntry)
		encryption.ZeroBytes(entry.dek)
		entry.dek = make([]byte, len(dek))
		copy(entry.dek, dek)
		entry.expiresAt = now.Add(c.ttl)
		c.order.MoveToFront(elem)
		return
	}

	// Evict expired entries first, then LRU if still at capacity.
	for c.order.Len() >= c.maxEntries {
		back := c.order.Back()
		if back == nil {
			break
		}
		c.removeElementLocked(back)
	}

	dekCopy := make([]byte, len(dek))
	copy(dekCopy, dek)

	entry := &cacheEntry{
		key:       key,
		dek:       dekCopy,
		expiresAt: now.Add(c.ttl),
	}
	elem := c.order.PushFront(entry)
	c.items[key] = elem
}

func (c *CachingKeyring) removeElementLocked(elem *list.Element) {
	c.order.Remove(elem)
	entry := elem.Value.(*cacheEntry)
	encryption.ZeroBytes(entry.dek)
	entry.dek = nil
	delete(c.items, entry.key)
}

func (c *CachingKeyring) clearLocked() {
	for elem := c.order.Front(); elem != nil; {
		next := elem.Next()
		c.removeElementLocked(elem)
		elem = next
	}
}

func computeCacheKey(kekID string, encryptedDEK, aad []byte) [32]byte {
	h := sha256.New()
	var lenBuf [24]byte
	h.Write(strconv.AppendInt(lenBuf[:0], int64(len(kekID)), 10))
	h.Write([]byte{':'})
	h.Write([]byte(kekID))
	h.Write([]byte{'|'})
	h.Write(strconv.AppendInt(lenBuf[:0], int64(len(aad)), 10))
	h.Write([]byte{':'})
	h.Write(aad)
	h.Write([]byte{'|'})
	h.Write(encryptedDEK)

	var sum [32]byte
	h.Sum(sum[:0])
	return sum
}
