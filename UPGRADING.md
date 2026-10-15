# Upgrading Guide

## Upgrading from `v0.0.5` to `v0.0.6`

`v0.0.6` redesigns `github.com/eventsalsa/encryption` for KMS-native Key Encryption Key (KEK) providers (`kek/local`, `kek/awskms`, `kek/gcpkms`), introduces mandatory Additional Authenticated Data (AAD) scope binding on wrapped Data Encryption Keys (DEKs), and refines the PostgreSQL keystore schema.

Because the library is still in the pre-`0.1.0` (`0.0.*`) series, the maintainers chose to update the initial database migration ([`postgres/migrations/001_encryption_keys.sql`](postgres/migrations/001_encryption_keys.sql)) in place rather than accumulating a second incremental migration file. If you have an existing `v0.0.5` deployment, follow the steps below to migrate your schema, re-bind existing DEKs with scope AAD, and update your Go code.

---

### Step 1: Upgrade the PostgreSQL Schema In Place

Run the following SQL transaction against your database (replace `infrastructure.encryption_keys` if you configured a custom schema or table name):

```sql
BEGIN;

-- 1. Rename columns and remove the implicit 'default' KEK ID fallback
ALTER TABLE infrastructure.encryption_keys
    RENAME COLUMN encrypted_key TO encrypted_dek;

ALTER TABLE infrastructure.encryption_keys
    RENAME COLUMN system_key_id TO kek_id;

ALTER TABLE infrastructure.encryption_keys
    ALTER COLUMN kek_id DROP DEFAULT;

-- 2. Rename existing CHECK constraints and add timestamp ordering check
ALTER TABLE infrastructure.encryption_keys
    RENAME CONSTRAINT encrypted_key_not_empty TO encrypted_dek_not_empty;

ALTER TABLE infrastructure.encryption_keys
    RENAME CONSTRAINT system_key_id_not_empty TO kek_id_not_empty;

ALTER TABLE infrastructure.encryption_keys
    ADD CONSTRAINT revoked_after_created
    CHECK (revoked_at IS NULL OR revoked_at >= created_at);

-- 3. Replace v0.0.5 indexes with v0.0.6 indexes
DROP INDEX IF EXISTS infrastructure.idx_encryption_keys_active;
DROP INDEX IF EXISTS infrastructure.idx_encryption_keys_system_key_id;
DROP INDEX IF EXISTS infrastructure.idx_encryption_keys_scope;

-- Enforce at most one active (unrevoked) key per (scope, scope_id)
CREATE UNIQUE INDEX idx_encryption_keys_active
    ON infrastructure.encryption_keys(scope, scope_id)
    WHERE revoked_at IS NULL;

-- Composite index for zero-sort batch scans during RewrapKeys
CREATE INDEX idx_encryption_keys_kek_id
    ON infrastructure.encryption_keys(kek_id, scope, scope_id, key_version);

COMMIT;
```

> **Note:** Before creating the unique partial index `idx_encryption_keys_active`, ensure no `(scope, scope_id)` pair has multiple rows with `revoked_at IS NULL`. If any exist, soft-revoke the older versions first:
> ```sql
> UPDATE infrastructure.encryption_keys ek
> SET revoked_at = NOW()
> WHERE revoked_at IS NULL
>   AND key_version < (
>       SELECT MAX(key_version)
>       FROM infrastructure.encryption_keys sub
>       WHERE sub.scope = ek.scope AND sub.scope_id = ek.scope_id
>   );
> ```

---

### Step 2: Re-Bind Existing `v0.0.5` DEKs with Scope AAD

In `v0.0.5`, DEKs stored in `encryption_keys` were wrapped using AES-256-GCM with `nil` AAD. In `v0.0.6`, [`envelope.Envelope`](envelope/envelope.go) binds every wrapped DEK to its canonical [`encryption.KeyScope{Scope, ScopeID, KeyVersion}.AAD()`](key.go) value so that a wrapped DEK cannot be transplanted into another scope or version row.

**Application ciphertexts (events, PII, secrets) do not need to be re-encrypted.** Because [`kek/local.Wrapper`](kek/local/local.go) uses the same AES-256-GCM wire format as `v0.0.5`, you can unwrap each `v0.0.5` DEK in place by passing `nil` AAD to `Unwrap`, and immediately re-wrap the exact same 32-byte DEK with `KeyScope.AAD()` using only `v0.0.6` packages:

```go
package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"os"

	"github.com/eventsalsa/encryption"
	"github.com/eventsalsa/encryption/kek"
	"github.com/eventsalsa/encryption/kek/local"
	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	ctx := context.Background()

	pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatalf("connect postgres: %v", err)
	}
	defer pool.Close()

	// Initialize your v0.0.5 local KEKs using v0.0.6's kek/local package.
	rawKEK, err := base64.StdEncoding.DecodeString(os.Getenv("KEK_1_BASE64"))
	if err != nil {
		log.Fatalf("decode KEK: %v", err)
	}
	defer encryption.ZeroBytes(rawKEK)

	keyring, err := local.NewKeyringFromMap(map[string][]byte{
		"kek-1": rawKEK,
	}, "kek-1")
	if err != nil {
		log.Fatalf("init keyring: %v", err)
	}

	if err := migrateDEKsToScopedAAD(ctx, pool, keyring); err != nil {
		log.Fatalf("migrate DEKs: %v", err)
	}
	fmt.Println("Successfully re-bound all DEKs with v0.0.6 KeyScope AAD.")
}

func migrateDEKsToScopedAAD(ctx context.Context, pool *pgxpool.Pool, keyring kek.Keyring) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	rows, err := tx.Query(ctx, `
		SELECT scope, scope_id, key_version, encrypted_dek, kek_id
		FROM infrastructure.encryption_keys
		FOR UPDATE
	`)
	if err != nil {
		return err
	}

	var keys []encryption.EncryptedKey
	for rows.Next() {
		var k encryption.EncryptedKey
		if err := rows.Scan(&k.Scope, &k.ScopeID, &k.KeyVersion, &k.EncryptedDEK, &k.KEKID); err != nil {
			rows.Close()
			return err
		}
		keys = append(keys, k)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	for _, k := range keys {
		wrapper, err := keyring.Get(k.KEKID)
		if err != nil {
			return fmt.Errorf("get KEK %q for (%s/%s/v%d): %w", k.KEKID, k.Scope, k.ScopeID, k.KeyVersion, err)
		}

		// 1. Unwrap the v0.0.5 DEK using nil AAD.
		rawDEK, err := wrapper.Unwrap(ctx, k.EncryptedDEK, nil)
		if err != nil {
			return fmt.Errorf("unwrap v0.0.5 DEK for (%s/%s/v%d): %w", k.Scope, k.ScopeID, k.KeyVersion, err)
		}

		// 2. Re-wrap the identical 32-byte DEK with v0.0.6 KeyScope AAD.
		rewrappedDEK, wrapErr := wrapper.Wrap(ctx, rawDEK, k.KeyScope().AAD())
		encryption.ZeroBytes(rawDEK)
		if wrapErr != nil {
			return fmt.Errorf("wrap v0.0.6 DEK for (%s/%s/v%d): %w", k.Scope, k.ScopeID, k.KeyVersion, wrapErr)
		}

		// 3. Persist the AAD-bound DEK back to the row.
		_, err = tx.Exec(ctx, `
			UPDATE infrastructure.encryption_keys
			SET encrypted_dek = $1
			WHERE scope = $2 AND scope_id = $3 AND key_version = $4
		`, rewrappedDEK, k.Scope, k.ScopeID, k.KeyVersion)
		if err != nil {
			return fmt.Errorf("update (%s/%s/v%d): %w", k.Scope, k.ScopeID, k.KeyVersion, err)
		}
	}

	return tx.Commit(ctx)
}
```

---

### Step 3: Update Go Code from `v0.0.5` to `v0.0.6`

#### 1. `systemkey` → `kek` and `kek/local`

The `systemkey` package has been replaced by [`kek`](kek/kek.go) (provider-agnostic `Wrapper`, `Rewrapper`, `Keyring`, and `CachingKeyring` interfaces) and [`kek/local`](kek/local/local.go) (in-process AES-256-GCM KEK implementation).

```go
// v0.0.5
keyring, err := systemkey.NewKeyringFromMap(map[string][]byte{"kek-1": rawKey}, "kek-1")

// v0.0.6
keyring, err := local.NewKeyringFromMap(map[string][]byte{"kek-1": rawKey}, "kek-1")
```

Constructor mapping:
- `systemkey.NewKeyringFromMap(keys, activeID)` → `local.NewKeyringFromMap(keys, activeID)`
- `systemkey.NewKeyringFromFiles(systemkey.FileConfig{...})` → `local.NewKeyringFromFiles(local.FileConfig{...})`
- Single key wrapper → `local.NewWrapper(id, rawKey)`

#### 2. `postgres.Store`: `CreateKey` and `RotateKey` Return `*encryption.EncryptedKey`

`CreateKey` and `RotateKey` now return the newly created `(*encryption.EncryptedKey, error)` directly via PostgreSQL `RETURNING` (avoiding a separate `GetActiveKey` round-trip), and `encryption.EncryptedKey` lives in the root `encryption` package:

```go
// v0.0.5
if err := store.CreateKey(ctx, pool, "user", userID); err != nil { ... }
key, err := store.GetActiveKey(ctx, pool, "user", userID)

// v0.0.6
key, err := store.CreateKey(ctx, pool, "user", userID)
```

Field renames on [`encryption.EncryptedKey`](key.go):
- `key.EncryptedKey` → `key.EncryptedDEK`
- `key.SystemKeyID` → `key.KEKID`

#### 3. `envelope.Envelope` & `envelope.Session`: Context, `*encryption.EncryptedKey`, and AAD

All envelope operations now accept `context.Context` (to support network-backed Cloud KMS providers), take `*encryption.EncryptedKey` (so `KeyScope` AAD is verified automatically when unwrapping the DEK), and accept an optional payload `aad []byte` parameter (pass `nil` if your existing application ciphertexts did not use payload AAD):

```go
// v0.0.5
ciphertext, err := env.Encrypt(key.EncryptedKey, key.SystemKeyID, plaintext)
plaintext, err := env.Decrypt(key.EncryptedKey, key.SystemKeyID, ciphertext)

// v0.0.6 (single-shot base64 string helpers)
ciphertext, err := env.EncryptString(ctx, key, plaintext, nil)
plaintext, err := env.DecryptString(ctx, key, ciphertext, nil)

// v0.0.6 (reusable session — unwraps the DEK once for multiple fields/events)
sess, err := env.OpenSession(ctx, key)
if err != nil {
    return err
}
defer sess.Close() // zeros the unwrapped DEK in RAM

ct1, err := sess.EncryptString(email, nil)
ct2, err := sess.EncryptString(phone, nil)
```

#### 4. `postgres.RewrapKeysOptions`

Field names on [`postgres.RewrapKeysOptions`](postgres/rewrap.go) were updated from `SystemKeyID` to `KEKID`:

```go
// v0.0.5
res, err := postgres.RewrapKeys(ctx, pool, cfg, env, postgres.RewrapKeysOptions{
    FromSystemKeyID: "old-kek",
    ToSystemKeyID:   "new-kek",
})

// v0.0.6
res, err := postgres.RewrapKeys(ctx, pool, cfg, env, postgres.RewrapKeysOptions{
    FromKEKID: "old-kek",
    ToKEKID:   "new-kek",
})
```
