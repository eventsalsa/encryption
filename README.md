# eventsalsa/encryption

Envelope encryption for Go systems — with stateless PostgreSQL key storage, pure in-memory encryption, and zero-downtime key rotation.

## Features

- **Envelope encryption** — two-tier key hierarchy (system KEK → per-scope DEK → data)
- **Decoupled in-memory engine** — pure cryptographic transformations (`envelope.Envelope`) without database or context entanglement
- **Stateless storage** — explicit connection passing for clean dependency injection and first-class SQL transaction participation (`*pgxpool.Pool`, `pgx.Tx`, `*pgx.Conn`)
- **GDPR crypto-shredding** — destroying keys (`store.DestroyKeys`) renders associated encrypted data permanently unreadable
- **Key rotation** — versioned keys (`store.RotateKey`) with seamless decryption of historical payloads
- **System KEK rewrapping** — batch migration function (`postgres.RewrapSystemKeys`) to retire old system keys in place without touching application ciphertexts
- **Pluggable cipher** — ships AES-256-GCM (`cipher/aesgcm`), bring your own `cipher.Cipher`
- **Migration CLI** — `cmd/migrate-gen` generates or prints the PostgreSQL keystore migration
- **Deterministic hashing** — HMAC-SHA256 (`hash.HMACHasher`) for generating deterministic aggregate IDs from sensitive data
- **Memory hygiene** — plaintext DEKs are immediately zeroed after use via `encryption.ZeroBytes`
- **Zero external runtime dependencies** — only Go standard library and `pgx/v5`

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Application                          │
│                                                             │
│         postgres.Store              envelope.Envelope       │
│          │          │                │             │        │
│          │          ▼                │             │        │
│          │     PostgreSQL            ▼             ▼        │
│          │   (pgx.Tx / Pool)     systemkey      cipher      │
│          │                       .Keyring      .Cipher      │
│          └───────────────────────────┐                      │
│                                      ▼                      │
│                                 AES-256-GCM                 │
└─────────────────────────────────────────────────────────────┘

Envelope encryption flow:

  Encrypt:
    1. Fetch active encrypted DEK from postgres.Store (via db pool or tx)
    2. envelope.Encrypt(sysKeyID, encDEK, plaintext)
       - Unwrap DEK using system KEK from Keyring
       - Encrypt plaintext using DEK
       - Zero plaintext DEK from memory

  Decrypt:
    1. Fetch encrypted DEK for specific key version from postgres.Store
    2. envelope.Decrypt(sysKeyID, encDEK, ciphertext)
       - Unwrap DEK using system KEK from Keyring
       - Decrypt ciphertext using DEK
       - Zero plaintext DEK from memory
```

### Package Overview

| Package | Role |
| :--- | :--- |
| `encryption` (root) | Sentinel errors (`ErrKeyNotFound`, `ErrKeyExists`, etc.) and `ZeroBytes` |
| `cipher` | `Cipher` interface for symmetric encrypt/decrypt |
| `cipher/aesgcm` | AES-256-GCM symmetric cipher implementation |
| `systemkey` | `Keyring` interface + in-memory and file-based loaders for system KEKs |
| `envelope` | `Envelope` — pure in-memory envelope encrypt/decrypt and DEK wrapping engine |
| `postgres` | Stateless PostgreSQL `Store` (create, rotate, revoke, destroy) and `RewrapSystemKeys` |
| `postgres/migrations`| Embedded PostgreSQL migration SQL and migration generator |
| `hash` | `Hasher` interface + HMAC-SHA256 implementation |
| `testutil` | Test helpers (`NewTestKeyring()`) |

---

## Getting Started

### 1. Generate Database Migration

Generate the PostgreSQL keystore migration using the CLI tool:

```bash
go run github.com/eventsalsa/encryption/cmd/migrate-gen -output migrations
# writes migrations/20260417123456_init_encryption_keys.sql
```

Or print the SQL directly:

```bash
go run github.com/eventsalsa/encryption/cmd/migrate-gen -stdout
go run github.com/eventsalsa/encryption/cmd/migrate-gen -schema custom_schema -table custom_keys -stdout
```

### 2. Basic Setup & Usage

```go
package main

import (
	"context"
	"log"

	"github.com/eventsalsa/encryption/cipher/aesgcm"
	"github.com/eventsalsa/encryption/envelope"
	"github.com/eventsalsa/encryption/postgres"
	"github.com/eventsalsa/encryption/systemkey"
	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	ctx := context.Background()

	pool, err := pgxpool.New(ctx, "postgres://localhost/myapp?sslmode=disable")
	if err != nil {
		log.Fatal(err)
	}

	// 1. Initialize Keyring & Cipher
	keyring := systemkey.NewKeyring(
		map[string][]byte{"key-1": loadKeyFromVault()}, // 32-byte AES key
		"key-1", // active key ID
	)
	c := aesgcm.New()

	// 2. Initialize in-memory Envelope & PostgreSQL Store
	env := envelope.New(keyring, c)
	store := postgres.NewStore(env, postgres.Config{})

	scope, scopeID := "user-pii", "user-123"

	// 3. Create a DEK for this scope (inserts version 1 into Postgres)
	version, err := store.CreateKey(ctx, pool, scope, scopeID)
	if err != nil {
		log.Fatal(err)
	}

	// 4. Fetch the active key from Postgres
	key, err := store.GetActiveKey(ctx, pool, scope, scopeID)
	if err != nil {
		log.Fatal(err)
	}

	// 5. Encrypt payload in-memory (no DB access)
	ciphertext, err := env.Encrypt(key.SystemKeyID, key.EncryptedDEK, "alice@example.com")
	if err != nil {
		log.Fatal(err)
	}

	// 6. Decrypt payload in-memory
	plaintext, err := env.Decrypt(key.SystemKeyID, key.EncryptedDEK, ciphertext)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Decrypted:", plaintext)
}
```

---

## Transaction Participation

In event-sourced systems, key creation and event persistence typically happen within the same SQL transaction. Because `postgres.Store` accepts any database executor (`*pgxpool.Pool`, `pgx.Tx`, `*pgx.Conn`), you can pass active transactions directly:

```go
tx, err := pool.Begin(ctx)
if err != nil {
	return err
}
defer tx.Rollback(ctx)

// 1. Key creation/retrieval executes inside the transaction:
key, err := store.GetActiveKey(ctx, tx, "user-pii", userID)
if errors.Is(err, encryption.ErrKeyNotFound) {
	_, err = store.CreateKey(ctx, tx, "user-pii", userID)
	if err != nil {
		return err
	}
	key, err = store.GetActiveKey(ctx, tx, "user-pii", userID)
}
if err != nil {
	return err
}

// 2. In-memory encryption requires zero database access:
ciphertext, err := env.Encrypt(key.SystemKeyID, key.EncryptedDEK, email)
if err != nil {
	return err
}

// 3. Persist the event in the same transaction:
_, err = tx.Exec(ctx, "INSERT INTO events (aggregate_id, payload) VALUES ($1, $2)", userID, ciphertext)
if err != nil {
	return err
}

return tx.Commit(ctx)
```

---

## Key Rotation

Rotate DEKs while preserving decryption of historical payloads:

```go
// Rotate to version 2 (generates new DEK, wraps under active system key, revokes v1):
v2, err := store.RotateKey(ctx, pool, "integration", "stripe-key")

// Old ciphertexts (version 1) are decrypted by fetching key version 1:
k1, _ := store.GetKey(ctx, pool, "integration", "stripe-key", 1)
plain1, _ := env.Decrypt(k1.SystemKeyID, k1.EncryptedDEK, oldCiphertext)

// New ciphertexts use active key version 2:
k2, _ := store.GetActiveKey(ctx, pool, "integration", "stripe-key")
plain2, _ := env.Decrypt(k2.SystemKeyID, k2.EncryptedDEK, newCiphertext)
```

---

## GDPR Crypto-Shredding

In event-sourced systems, events are immutable. Crypto-shredding solves GDPR's "right to erasure" by destroying the encryption key instead of mutating event streams:

```go
// When a user requests deletion:
err := store.DestroyKeys(ctx, pool, "user-pii", userID)
```

After `DestroyKeys`:
1. The DEK rows are permanently deleted from PostgreSQL (`DELETE`, not soft-revoke).
2. All historical events containing that user's PII remain in the event store but are **permanently and mathematically undecryptable**.
3. Subsequent key retrieval returns `encryption.ErrKeyNotFound`.

---

## System KEK Rewrap

When retiring an old system key (KEK), use `postgres.RewrapSystemKeys` to re-encrypt stored DEKs in place:

```go
result, err := postgres.RewrapSystemKeys(ctx, pool, postgres.Config{}, keyring, c, postgres.RewrapSystemKeysOptions{
	FromSystemKeyID: "key-1",
	ToSystemKeyID:   "key-2",
	BatchSize:       500,
})
if err != nil {
	return err
}

log.Printf("rewrapped=%d remaining=%d batches=%d", result.RewrappedRows, result.RemainingRows, result.Batches)
```

---

## Build & Test

```bash
# Build all packages
go build ./...

# Run unit tests with race detector
go test -race ./...

# Run PostgreSQL integration tests (requires Docker)
go test -race -tags=integration ./postgres/...

# Run full local validation suite
make check
```
