# encryption

Envelope encryption for event-sourced Go systems — with PII crypto-shredding and secret key rotation.

## Features

- **Envelope encryption** — two-tier key hierarchy (system KEK → per-scope DEK → data)
- **PII encryption** — per-subject keys with GDPR crypto-shredding (destroy key → data permanently unreadable)
- **Secret encryption** — versioned keys with rotation (old ciphertext stays decryptable)
- **Pluggable cipher** — ships AES-256-GCM, bring your own `cipher.Cipher`
- **Pluggable key store** — ships PostgreSQL adapter, bring your own `keystore.KeyStore`
- **Deterministic hashing** — HMAC-SHA256 for generating aggregate IDs from sensitive data
- **Memory hygiene** — DEKs are zeroed after use via `ZeroBytes`
- **Zero external dependencies** — only Go standard library

## Getting Started

The library ships a PostgreSQL-backed key store. You need three things to get going: a system keyring (KEK), a PostgreSQL database with the migration applied, and the module wired together.

### Migration

The `keystore/postgres/migrations` package embeds the SQL migration. Apply it to your database before using the store — either by executing it directly or by feeding it to your migration tool:

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

The full migration (with indexes and constraints) is embedded in `migrations.FS` and can be read at runtime:

```go
import "github.com/eventsalsa/encryption/keystore/postgres/migrations"

data, _ := migrations.FS.ReadFile("001_encryption_keys.sql")
```

Both the schema (`infrastructure`) and table name (`encryption_keys`) are configurable via `postgres.Config`.

### Wiring the Module

```go
package main

import (
	"context"
	"database/sql"
	"log"

	"github.com/eventsalsa/encryption"
	_ "github.com/eventsalsa/encryption/cipher/aesgcm"
	"github.com/eventsalsa/encryption/keystore/postgres"
	"github.com/eventsalsa/encryption/systemkey"
)

func main() {
	ctx := context.Background()

	db, err := sql.Open("postgres", "postgres://localhost/myapp?sslmode=disable")
	if err != nil {
		log.Fatal(err)
	}

	keyring := systemkey.NewKeyring(
		map[string][]byte{"key-1": loadKeyFromVault()}, // 32-byte AES key
		"key-1", // active key ID
	)

	store := postgres.NewStore(postgres.Config{}, db) // defaults: schema "infrastructure", table "encryption_keys"

	m := encryption.New(encryption.Config{
		Keyring: keyring,
		Store:   store,
	})

	// Create a DEK, encrypt, and decrypt.
	_, err = m.KeyManager.CreateKey(ctx, "user-pii", "user-123")
	if err != nil {
		log.Fatal(err)
	}

	ciphertext, version, err := m.Envelope.Encrypt(ctx, "user-pii", "user-123", "alice@example.com")
	if err != nil {
		log.Fatal(err)
	}

	plaintext, err := m.Envelope.Decrypt(ctx, "user-pii", "user-123", ciphertext, version)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("decrypted:", plaintext)
}
```

By default, all operations go through the `*sql.DB` connection pool — no transaction required for simple use cases.

### Transaction Participation

In event-sourced systems you typically want key creation and event persistence to happen atomically. Use `keystore.WithTx` to attach an existing `*sql.Tx` to the context — all key store operations within that context will use the transaction instead of the pool:

```go
import "github.com/eventsalsa/encryption/keystore"

tx, err := db.BeginTx(ctx, nil)
if err != nil {
	return err
}
defer tx.Rollback()

ctx = keystore.WithTx(ctx, tx)

// Both the key creation and the encrypt happen inside the transaction.
_, err = m.KeyManager.CreateKey(ctx, "user-pii", userID)
if err != nil {
	return err
}

ciphertext, version, err := m.Envelope.Encrypt(ctx, "user-pii", userID, email)
if err != nil {
	return err
}

// Persist the aggregate event in the same transaction...

return tx.Commit()
```

### Custom Transaction Extractor

If your application already propagates transactions through its own context key (e.g., a Unit of Work or CQRS middleware), use `NewStoreWithTxExtractor` so the key store picks up your transaction automatically:

```go
store := postgres.NewStoreWithTxExtractor(postgres.Config{}, db,
	func(ctx context.Context) *sql.Tx {
		return myuow.TxFromContext(ctx)
	},
)
```

Resolution order: custom extractor → `keystore.TxFromContext` → `*sql.DB` fallback.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    Application                      │
│                                                     │
│   pii.Adapter[ID]          secret.Adapter           │
│       │                        │                    │
│       └────────┬───────────────┘                    │
│                ▼                                    │
│        envelope.Encryptor                           │
│         │          │        │                       │
│         ▼          ▼        ▼                       │
│   systemkey     keystore   cipher                   │
│   .Keyring      .KeyStore  .Cipher                  │
│                                                     │
│   ┌────────┐  ┌──────────┐  ┌──────────────┐        │
│   │ KEK(s) │  │ Encrypted│  │ AES-256-GCM  │        │
│   │ in mem │  │ DEKs in  │  │ (or custom)  │        │
│   │        │  │ Postgres │  │              │        │
│   └────────┘  └──────────┘  └──────────────┘        │
└─────────────────────────────────────────────────────┘

Envelope encryption flow:

  Encrypt:
    1. Fetch encrypted DEK from KeyStore (by scope + scopeID)
    2. Decrypt DEK with system KEK from Keyring
    3. Encrypt plaintext with DEK using Cipher
    4. Return base64-encoded ciphertext + key version

  Decrypt:
    1. Fetch encrypted DEK for specific key version
    2. Decrypt DEK with system KEK from Keyring
    3. Decrypt ciphertext with DEK using Cipher
    4. Return plaintext
```

### Package Overview

| Package             | Role                                                                                |
|---------------------|-------------------------------------------------------------------------------------|
| `encryption`        | Top-level module wiring (`New`, `NewWithDefaults`, `Config`, `Module`)              |
| `cipher`            | `Cipher` interface for symmetric encrypt/decrypt                                    |
| `cipher/aesgcm`     | AES-256-GCM implementation (auto-registers as default on import)                    |
| `systemkey`         | `Keyring` interface + in-memory and file-based implementations for system KEKs      |
| `keystore`          | `KeyStore` interface, `EncryptedKey` type, `WithTx`/`TxFromContext` context helpers |
| `keystore/postgres` | PostgreSQL-backed `KeyStore` with configurable schema/table and tx extraction       |
| `keymanager`        | `Manager` — DEK lifecycle: create, rotate, revoke, destroy                          |
| `envelope`          | `Encryptor` — envelope encrypt/decrypt engine                                       |
| `pii`               | `EncryptedValue`, generic `Encryptor[ID]`/`Decryptor[ID]` interfaces, `Adapter`     |
| `secret`            | `EncryptedValue` (with `KeyVersion`), `Encryptor`/`Decryptor` interfaces, `Adapter` |
| `hash`              | `Hasher` interface + HMAC-SHA256 implementation                                     |
| `encerr`            | Shared sentinel errors (re-exported by root package)                                |
| `testutil`          | `NewTestKeyring()` + `InMemoryKeyStore` for testing                                 |

## PII vs Secrets

The library provides two domain adapters on top of the envelope engine. Choose based on your use case:

|                      | PII                                    | Secret                                             |
|----------------------|----------------------------------------|----------------------------------------------------|
| **Value type**       | `pii.EncryptedValue` (opaque `string`) | `secret.EncryptedValue` (`Content` + `KeyVersion`) |
| **Key version**      | Always 1 (hardcoded)                   | Versioned, increments on rotation                  |
| **Key rotation**     | ✗ Not supported                        | ✓ `keymanager.RotateKey`                           |
| **Crypto-shredding** | ✓ Primary use case                     | ✓ Supported                                        |
| **Key revocation**   | ✗ Not applicable                       | ✓ `keymanager.RevokeKeys`                          |
| **Subject scoping**  | Generic `ID fmt.Stringer` per subject  | Scope + ScopeID strings                            |
| **Use cases**        | User emails, names, addresses          | API keys, tokens, credentials                      |

### PII Adapter

The PII adapter is generic over the subject ID type. It hardcodes key version to 1 (no rotation) — the intended lifecycle is create once, then crypto-shred on deletion:

```go
type UserID string
func (id UserID) String() string { return string(id) }

adapter := pii.NewAdapter[UserID](m.Envelope, "user-pii")

encrypted, err := adapter.Encrypt(ctx, UserID("user-123"), "alice@example.com")
plaintext, err := adapter.Decrypt(ctx, UserID("user-123"), encrypted)
```

### Secret Adapter

The secret adapter tracks key versions, allowing rotation while keeping old ciphertext decryptable:

```go
adapter := secret.NewAdapter(m.Envelope)

encrypted, err := adapter.Encrypt(ctx, "integration", "stripe-key", "sk_live_xxx")
plaintext, err := adapter.Decrypt(ctx, "integration", "stripe-key", encrypted)
```

## GDPR Crypto-Shredding

In event-sourced systems, events are immutable — you cannot delete or modify them. Crypto-shredding solves GDPR's "right to be forgotten" by destroying the encryption key instead of the data:

```go
// When a user requests account deletion:
err := m.KeyManager.DestroyKeys(ctx, "user-pii", userID.String())
```

After `DestroyKeys`:

1. The DEK is permanently deleted from the key store (`DELETE`, not soft-revoke)
2. All events containing that user's PII still exist but are **permanently undecryptable**
3. Any `Decrypt` call returns `encryption.ErrKeyNotFound`
4. The event store remains intact — no immutability violation

## Custom Implementations

### Custom Cipher

Implement `cipher.Cipher` to use a different encryption algorithm:

```go
package chacha

import "github.com/eventsalsa/encryption/cipher"

type ChaCha20 struct{}

func (c *ChaCha20) Encrypt(key, plaintext []byte) ([]byte, error) { /* ... */ }
func (c *ChaCha20) Decrypt(key, ciphertext []byte) ([]byte, error) { /* ... */ }
func (c *ChaCha20) KeySize() int { return 32 }

var _ cipher.Cipher = (*ChaCha20)(nil)
```

Pass it to the module:

```go
m := encryption.New(encryption.Config{
	Keyring: keyring,
	Store:   store,
	Cipher:  &chacha.ChaCha20{},
})
```

### Custom KeyStore

Implement `keystore.KeyStore` to use a different storage backend. The interface is storage-agnostic — no SQL types in the signatures:

```go
package dynamo

import (
	"context"
	"github.com/eventsalsa/encryption/keystore"
)

type Store struct{ /* ... */ }

func (s *Store) GetActiveKey(ctx context.Context, scope, scopeID string) (*keystore.EncryptedKey, error) { /* ... */ }
func (s *Store) GetKey(ctx context.Context, scope, scopeID string, version int) (*keystore.EncryptedKey, error) { /* ... */ }
func (s *Store) CreateKey(ctx context.Context, scope, scopeID string, version int, encryptedDEK []byte, systemKeyID string) error { /* ... */ }
func (s *Store) RevokeKeys(ctx context.Context, scope, scopeID string) error { /* ... */ }
func (s *Store) DestroyKeys(ctx context.Context, scope, scopeID string) error { /* ... */ }

var _ keystore.KeyStore = (*Store)(nil)
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

	// Use m.KeyManager, m.Envelope, pii.NewAdapter, etc.
}
```

`NewTestKeyring` generates a random key on each call, so tests are naturally isolated. `InMemoryKeyStore` is safe for concurrent use with `-race`.

## Build & Test

```bash
go build ./...
go test -race ./...
go vet ./...
```
