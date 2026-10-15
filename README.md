# eventsalsa/encryption

KMS-native envelope encryption for Go systems — supporting **AWS KMS**, **Google Cloud KMS**, and **local symmetric KEKs**, with stateless PostgreSQL key storage, mandatory AAD scope binding, reusable in-memory sessions, and zero-downtime key rotation.

## Features

- **KMS-native envelope encryption** — two-tier key hierarchy (`kek.Keyring` KEK → per-scope DEK → application data) where KEK material never leaves the KMS boundary
- **Cloud & local KEK providers** — ships `kek/awskms` (AWS KMS SDK v2 with native `ReEncrypt`), `kek/gcpkms` (Google Cloud KMS with Castagnoli CRC32C verification), and `kek/local` (in-memory & file-based AES-256-GCM)
- **Confused-deputy protection via AAD** — every wrapped DEK is cryptographically bound to its `(scope, scope_id, key_version)` tuple via Additional Authenticated Data (`EncryptionContext` in AWS KMS, `AdditionalAuthenticatedData` in GCP KMS, GCM AAD locally)
- **High-throughput `Session` & `CachingKeyring`** — unwrap a DEK once via `env.OpenSession` to encrypt/decrypt entire event streams with zero network calls, or wrap any `Keyring` in `kek.NewCachingKeyring` (bounded TTL + LRU with automatic memory scrubbing)
- **Stateless PostgreSQL storage** — explicit connection passing (`*pgxpool.Pool`, `pgx.Tx`, `*pgx.Conn`) for clean SQL transaction participation and single-statement atomic key rotation
- **GDPR crypto-shredding** — `store.DestroyKeys` permanently deletes scope keys, rendering historical event ciphertexts mathematically unreadable
- **KEK rotation & cross-provider migration** — `postgres.RewrapKeys` migrates stored DEKs in batches (using server-side AWS KMS `ReEncrypt` when available or transparent `Unwrap` + `Wrap` across providers)
- **Isolated Go sub-modules** — root module has zero cloud SDK dependencies; install `kek/awskms` or `kek/gcpkms` only when needed

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                               Application                               │
│                                                                         │
│         postgres.Store                         envelope.Envelope        │
│          │          │                           │             │         │
│          │          ▼                           ▼             ▼         │
│          │     PostgreSQL                 kek.Keyring   envelope.Session│
│          │   (pgx.Tx / Pool)            (or CachingKR)        │         │
│          └──────────────────────────────────┐   │             ▼         │
│                                             │   │       cipher.Cipher   │
│                                             ▼   ▼       (AES-256-GCM)   │
│                                    ┌────────────────────┐               │
│                                    │  kek/local         │               │
│                                    │  kek/awskms (KMS)  │               │
│                                    │  kek/gcpkms (KMS)  │               │
│                                    └────────────────────┘               │
└─────────────────────────────────────────────────────────────────────────┘
```

### Package Overview

| Package | Module | Role |
| :--- | :--- | :--- |
| `encryption` (root) | `github.com/eventsalsa/encryption` | Sentinel errors, `EncryptedKey`, `KeyScope` (canonical AAD), and `ZeroBytes` |
| `cipher` | `github.com/eventsalsa/encryption` | `Cipher` AEAD interface (`Encrypt`/`Decrypt` with `aad []byte`) |
| `cipher/aesgcm` | `github.com/eventsalsa/encryption` | AES-256-GCM AEAD implementation |
| `kek` | `github.com/eventsalsa/encryption` | `Wrapper`, `Rewrapper`, `Keyring`, and `CachingKeyring` |
| `kek/local` | `github.com/eventsalsa/encryption` | In-process AES-256-GCM KEK wrapper + map and file loaders |
| `kek/awskms` | `github.com/eventsalsa/encryption/kek/awskms` | AWS KMS `Wrapper` & native server-side `Rewrapper` (`ReEncrypt`) |
| `kek/gcpkms` | `github.com/eventsalsa/encryption/kek/gcpkms` | Google Cloud KMS `Wrapper` with end-to-end CRC32C verification |
| `envelope` | `github.com/eventsalsa/encryption` | `Envelope` and `Session` for DEK lifecycle and payload encryption |
| `postgres` | `github.com/eventsalsa/encryption` | Stateless PostgreSQL `Store` and batch `RewrapKeys` |
| `postgres/migrations` | `github.com/eventsalsa/encryption` | Embedded PostgreSQL migration SQL and generator |
| `hash` | `github.com/eventsalsa/encryption` | `Hasher` interface + HMAC-SHA256 blind indexing |
| `testutil` | `github.com/eventsalsa/encryption` | Test helpers (`NewTestKeyring()`) |

---

## Getting Started

### 1. Generate Database Migration

```bash
go run github.com/eventsalsa/encryption/cmd/migrate-gen -output migrations
# Or print directly to stdout:
go run github.com/eventsalsa/encryption/cmd/migrate-gen -stdout
```

### 2. Configure a KEK Keyring (AWS KMS, GCP KMS, or Local)

```go
// Option A: AWS KMS (github.com/eventsalsa/encryption/kek/awskms)
awsWrapper, err := awskms.NewWrapper(kmsClient, "arn:aws:kms:eu-west-1:123456789012:key/mrk-1234")
keyring, err := kek.NewKeyring(awsWrapper.ID(), awsWrapper)

// Option B: Google Cloud KMS (github.com/eventsalsa/encryption/kek/gcpkms)
gcpWrapper, err := gcpkms.NewWrapper(gcpClient, "projects/my-proj/locations/global/keyRings/kr/cryptoKeys/kek-1")
keyring, err := kek.NewKeyring(gcpWrapper.ID(), gcpWrapper)

// Option C: Local 32-byte KEK (in-memory or from files)
keyring, err := local.NewKeyringFromMap(map[string][]byte{"local-v1": raw32ByteKey}, "local-v1")

// Optional: Decorate with an in-memory TTL + LRU cache to avoid repeated KMS RPCs
cachedKeyring, err := kek.NewCachingKeyring(keyring, kek.CacheConfig{
	TTL:        5 * time.Minute,
	MaxEntries: 1000,
})
defer cachedKeyring.Close()
```

### 3. Encrypt & Decrypt (Single-Shot and Reusable Sessions)

```go
env := envelope.New(cachedKeyring, aesgcm.New())
store := postgres.NewStore(env, postgres.Config{})

// 1. Create or fetch the active key for a scope
key, err := store.CreateKey(ctx, pool, "user-pii", "user-123")
if errors.Is(err, encryption.ErrKeyExists) {
	key, err = store.GetActiveKey(ctx, pool, "user-pii", "user-123")
}

// 2. Single-shot encryption/decryption (with optional payload AAD)
ct, err := env.EncryptString(ctx, key, "alice@example.com", []byte("field:email"))
pt, err := env.DecryptString(ctx, key, ct, []byte("field:email"))

// 3. Batch / event-stream session (unwraps DEK once, encrypts/decrypts in RAM)
session, err := env.OpenSession(ctx, key)
if err != nil {
	return err
}
defer session.Close() // Scrubs plaintext DEK from RAM

emailCT, err := session.Encrypt([]byte("alice@example.com"), []byte("field:email"))
phoneCT, err := session.Encrypt([]byte("+15550100"), []byte("field:phone"))
```

---

## KEK Rotation & Cross-Provider Rewrapping

When rotating KEKs or migrating from local keys to Cloud KMS, register both the old and new wrappers in `kek.Keyring` and run `postgres.RewrapKeys`:

```go
result, err := postgres.RewrapKeys(ctx, pool, postgres.Config{}, env, postgres.RewrapKeysOptions{
	FromKEKID: "local-v1",
	ToKEKID:   awsWrapper.ID(),
	BatchSize: 500,
})
```

---

## Build & Test

```bash
# Run the full validation suite (fmt, vet, golangci-lint, test, integration, gosec, govulncheck)
make check
```
