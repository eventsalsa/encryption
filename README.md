# eventsalsa/encryption

Envelope encryption for Go systems — with stateless key storage, pure in-memory encryption, and secret key rotation.

## Features

- **Envelope encryption** — two-tier key hierarchy (system KEK → per-scope DEK → data)
- **Decoupled in-memory engine** — pure cryptographic transformations without database or context entanglement
- **Stateless storage** — explicit `pgxConn` passing for clean dependency injection and first-class SQL transaction participation
- **GDPR crypto-shredding** — destroy key (`DestroyKeys`) renders associated encrypted data permanently unreadable
- **Secret encryption & rotation** — versioned keys with rotation (`RotateKey`), preserving decryption of historical payloads
- **Pluggable cipher** — ships AES-256-GCM, bring your own `cipher.Cipher`
- **Pluggable key store** — ships PostgreSQL adapter, bring your own `keymanager.KeyStore`
- **Migration CLI** — `cmd/migrate-gen` generates or prints the PostgreSQL keystore migration
- **Deterministic hashing** — HMAC-SHA256 for generating aggregate IDs from sensitive data
- **Memory hygiene** — DEKs are zeroed after use via `ZeroBytes`
- **Zero external runtime dependencies** — only Go standard library and `pgx/v5`

## Getting Started

The library ships a PostgreSQL-backed key store (`keystore/postgres`). You need three things to get going: a system keyring (KEK), a PostgreSQL database with the migration applied, and the module wired together.

### Migration

Generate the PostgreSQL key-store migration through the stable CLI entrypoint:

```bash
go run github.com/eventsalsa/encryption/cmd/migrate-gen -output migrations
# writes migrations/20260417123456_init_encryption_keys.sql
```

You can print the SQL directly when piping into your own tooling:

```bash
go run github.com/eventsalsa/encryption/cmd/migrate-gen -stdout
go run github.com/eventsalsa/encryption/cmd/migrate-gen -schema custom_schema -table custom_keys -stdout
```

For advanced package-level usage, `keystore/postgres/migrations` can render the SQL directly with the same schema and table overrides used by `postgres.Config`:

```go
import (
	"github.com/eventsalsa/encryption/keystore/postgres"
	"github.com/eventsalsa/encryption/keystore/postgres/migrations"
)

sql, err := migrations.SQL(postgres.Config{
	Schema: "custom_schema",
	Table:  "custom_keys",
})
if err != nil {
	// handle error
}
```

The raw embedded default migration is also available:

```sql
CREATE TABLE IF NOT EXISTS infrastructure.encryption_keys (
    scope         TEXT        NOT NULL,
    scope_id      TEXT        NOT NULL,
    key_version   INT         NOT NULL,
    encrypted_key BYTEA       NOT NULL,
    system_key_id TEXT        NOT NULL DEFAULT 'default',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at    TIMESTAMPTZ,
    PRIMARY KEY (scope, scope_id, key_version)
);
```

Both the schema (`infrastructure`) and table name (`encryption_keys`) are configurable via `postgres.Config`.

### Wiring the Module

```go
package main

import (
	"context"
	"log"

	"github.com/eventsalsa/encryption"
	_ "github.com/eventsalsa/encryption/cipher/aesgcm"
	"github.com/eventsalsa/encryption/keystore/postgres"
	"github.com/eventsalsa/encryption/systemkey"
	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	ctx := context.Background()

	pool, err := pgxpool.New(ctx, "postgres://localhost/myapp?sslmode=disable")
	if err != nil {
		log.Fatal(err)
	}

	keyring := systemkey.NewKeyring(
		map[string][]byte{"key-1": loadKeyFromVault()}, // 32-byte AES key
		"key-1", // active key ID
	)

	store := postgres.NewStore(postgres.Config{}) // stateless store; defaults: schema "infrastructure", table "encryption_keys"

	m := encryption.New(encryption.Config{
		Keyring: keyring,
		Store:   store,
	})

	scope, scopeID := "user-pii", "user-123"

	// 1. Create a DEK for the scope.
	_, err = m.KeyManager.CreateKey(ctx, pool, scope, scopeID)
	if err != nil {
		log.Fatal(err)
	}

	// 2. Fetch active key.
	key, err := store.GetActiveKey(ctx, pool, scope, scopeID)
	if err != nil {
		log.Fatal(err)
	}

	// 3. Encrypt in-memory using Envelope.
	ciphertext, err := m.Envelope.Encrypt(key.SystemKeyID, key.EncryptedDEK, "alice@example.com")
	if err != nil {
		log.Fatal(err)
	}

	// 4. Decrypt in-memory.
	plaintext, err := m.Envelope.Decrypt(key.SystemKeyID, key.EncryptedDEK, ciphertext)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("decrypted:", plaintext)
}
```

### Transaction Participation

In event-sourced systems, key creation and event persistence typically happen within the same SQL transaction. Because `postgres.Store` accepts `postgres.PgxConn` (satisfied by `*pgxpool.Pool`, `pgx.Tx`, and `*pgx.Conn`), you can pass active transactions directly:

```go
tx, err := pool.Begin(ctx)
if err != nil {
	return err
}
defer tx.Rollback(ctx)

// Key creation executes inside the transaction:
_, err = m.KeyManager.CreateKey(ctx, tx, "user-pii", userID)
if err != nil {
	return err
}

key, err := store.GetActiveKey(ctx, tx, "user-pii", userID)
if err != nil {
	return err
}

// In-memory encryption requires no database access:
ciphertext, err := m.Envelope.Encrypt(key.SystemKeyID, key.EncryptedDEK, email)
if err != nil {
	return err
}

// Persist the aggregate event in the same transaction...

return tx.Commit(ctx)
```

### System-Key Rewrap

If you introduce a new system key and want to retire an old one, use the standalone administrative function `postgres.RewrapSystemKeys` to re-encrypt stored DEKs in place:

```go
import (
	"github.com/eventsalsa/encryption/cipher/aesgcm"
	"github.com/eventsalsa/encryption/keystore/postgres"
)

c := aesgcm.New()

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

This operation:

- re-encrypts the same stored DEK under a new system key
- preserves the existing `(scope, scope_id, key_version)` row identity
- covers historical revoked rows as well as active rows
- does **not** rotate DEKs or re-encrypt application ciphertext

Recommended sequence:

1. Load both the old and new system keys into the keyring.
2. Make the new system key active for new writes.
3. Run `RewrapSystemKeys` from the old key ID to the new key ID until `RemainingRows` is zero.
4. Verify the migration result, then retire the old system key.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    Application                      │
│                                                     │
│        keymanager.Manager       envelope.Envelope   │
│         │              │         │         │        │
│         ▼              │         ▼         ▼        │
│    postgres.Store      │     systemkey   cipher     │
│    (or KeyStore)       │     .Keyring   .Cipher     │
│         │              │                            │
│         ▼              └─────────┐                  │
│    PostgreSQL                    ▼                  │
│   (via pgxConn)             AES-256-GCM             │
└─────────────────────────────────────────────────────┘

Envelope encryption flow:

  Encrypt:
    1. Fetch encrypted DEK from KeyStore (via db pool or tx)
    2. Envelope.Encrypt(sysKeyID, encDEK, plaintext)
       - Decrypt DEK using system KEK from Keyring
       - Encrypt plaintext using DEK
       - Zero DEK from memory

  Decrypt:
    1. Fetch encrypted DEK for specific key version from KeyStore
    2. Envelope.Decrypt(sysKeyID, encDEK, ciphertext)
       - Decrypt DEK using system KEK from Keyring
       - Decrypt ciphertext using DEK
       - Zero DEK from memory
```

### Package Overview

| Package             | Role                                                                                |
|---------------------|-------------------------------------------------------------------------------------|
| `encryption`        | Top-level module wiring (`New`, `NewWithDefaults`, `Config`, `Module`)              |
| `cipher`            | `Cipher` interface for symmetric encrypt/decrypt                                    |
| `cipher/aesgcm`     | AES-256-GCM implementation (auto-registers as default on import)                    |
| `systemkey`         | `Keyring` interface + in-memory and file-based implementations for system KEKs      |
| `keystore`          | `EncryptedKey` data type definition                                                 |
| `keystore/postgres` | Stateless PostgreSQL-backed `Store` with `PgxConn` interface and migration generator|
| `keymanager`        | `Manager` — DEK lifecycle: create, rotate, revoke, destroy                          |
| `envelope`          | `Envelope` — pure in-memory envelope encrypt/decrypt and DEK wrapping engine        |
| `hash`              | `Hasher` interface + HMAC-SHA256 implementation                                     |
| `encerr`            | Shared sentinel errors and byte-zeroing utilities (re-exported by root package)     |
| `testutil`          | `NewTestKeyring()` + `InMemoryKeyStore` for testing                                 |

## GDPR Crypto-Shredding

In event-sourced systems, events are immutable — you cannot delete or modify them. Crypto-shredding solves GDPR's "right to be forgotten" by destroying the encryption key instead of the data:

```go
// When a user requests account deletion:
err := m.KeyManager.DestroyKeys(ctx, pool, "user-pii", userID)
```

After `DestroyKeys`:

1. The DEK is permanently deleted from the key store (`DELETE`, not soft-revoke)
2. All events containing that user's PII still exist but are **permanently undecryptable**
3. Any subsequent key retrieval returns `encryption.ErrKeyNotFound`
4. The event store remains intact — no immutability violation

## Secret Key Rotation

Rotate system keys while keeping historical ciphertext decryptable:

```go
// Rotate to version 2 (generates new DEK, wraps under active system key, revokes v1):
v2, err := m.KeyManager.RotateKey(ctx, pool, "integration", "stripe-key")

// Old secrets (version 1) are still decryptable by fetching key version 1:
k1, _ := store.GetKey(ctx, pool, "integration", "stripe-key", 1)
plain1, _ := m.Envelope.Decrypt(k1.SystemKeyID, k1.EncryptedDEK, oldCiphertext)

// New secrets use active key version 2:
k2, _ := store.GetActiveKey(ctx, pool, "integration", "stripe-key")
plain2, _ := m.Envelope.Decrypt(k2.SystemKeyID, k2.EncryptedDEK, newCiphertext)
```

## Testing

The `testutil` package provides in-memory implementations for integration tests and local development — no database required:

```go
import (
	"testing"

	"github.com/eventsalsa/encryption"
	"github.com/eventsalsa/encryption/testutil"
	_ "github.com/eventsalsa/encryption/cipher/aesgcm"
)

func TestMyFeature(t *testing.T) {
	m := encryption.New(encryption.Config{
		Keyring: testutil.NewTestKeyring(),       // random 32-byte key, ID "test-key-1"
		Store:   testutil.NewInMemoryKeyStore(),   // thread-safe in-memory store
	})

	// Use m.KeyManager, m.Envelope, etc.
}
```

`NewTestKeyring` generates a random key on each call, so tests are naturally isolated. `InMemoryKeyStore` is safe for concurrent use with `-race`.

## Build & Test

```bash
go build ./...
go test -race ./...
make check
```

