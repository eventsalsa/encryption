# Copilot Instructions — eventsalsa/encryption

## Build & Test

```bash
make check
go build ./...
go test -race ./...
go test -race ./cipher/aesgcm/                 # single package
go test -race -run TestRoundtrip ./envelope/    # single test
go vet ./...
```

> If a session changes any source file, it must end by running the full local validation suite. `make check` is the canonical entrypoint and must cover the checks mirrored by `.github/workflows/ci.yml` and the locally runnable parts of `.github/workflows/security.yml`: `gofmt -l .`, `go vet ./...`, `golangci-lint run --timeout=5m`, `go test -race -count=1 -coverprofile=... ./...`, `go build ./...`, `go test -race -count=1 -tags=integration ./...`, `gosec`, and `govulncheck`. Also call out the GitHub-only CodeQL analysis explicitly if it was not run locally.

Go 1.24+. Zero external dependencies — only Go standard library (`crypto/*`, `database/sql`, `encoding/base64`). The PostgreSQL keystore adapter uses `database/sql`; consumers bring their own driver.

## Commits

- Use **Conventional Commits** for every commit (for example, `feat:`, `fix:`, `docs:`, `test:`, `chore:`).
- Every commit message must include a **descriptive body** after the subject line that explains the meaningful change, not just a one-line summary.

## Architecture

This is an **envelope encryption** library for event-sourced systems. It handles two distinct encryption categories:

- **PII** (`pii/`): Per-subject encryption keys with no rotation. Supports GDPR crypto-shredding — destroying the key makes the data permanently unreadable without mutating immutable events.
- **Secrets** (`secret/`): Versioned encryption keys with rotation support. Old ciphertext remains decryptable via stored key versions.

**Data flow:** Plaintext → `envelope.Encryptor` → fetches encrypted DEK from `KeyStore` → decrypts DEK with system key from `Keyring` → encrypts plaintext with DEK via `Cipher` → returns base64 ciphertext.

**Layered components:**

| Layer | Package | Role |
|-------|---------|------|
| Shared Errors | `encerr/` | Sentinel errors and `ZeroBytes` (breaks import cycles) |
| Cipher | `cipher/`, `cipher/aesgcm/` | Symmetric encrypt/decrypt (default: AES-256-GCM) |
| System Keys (KEK) | `systemkey/` | Root key management (in-memory or file-based) |
| Key Storage (DEK) | `keystore/`, `keystore/postgres/` | Encrypted DEK persistence |
| Key Lifecycle | `keymanager/` | Create, rotate, revoke, destroy keys |
| Encryption Engine | `envelope/` | Envelope encrypt/decrypt orchestration |
| Domain Types | `pii/`, `secret/` | Value types and adapters with category-specific semantics |
| Hashing | `hash/` | Deterministic HMAC-SHA256 for uniqueness checks |
| Top-Level API | `encryption.go` | `New()` and `NewWithDefaults()` convenience constructors |

## Key Conventions

- **Import cycle avoidance**: Sentinel errors and `ZeroBytes` live in `encerr/`. Sub-packages import `encerr`, not the root `encryption` package. The root re-exports everything from `encerr` for public API consumers. Test files in sub-packages that root imports (e.g., `systemkey`) must also use `encerr`.
- **Interface-first design**: Every major component is fronted by an interface (`Cipher`, `KeyStore`, `Keyring`, `Hasher`). Implementations live in sub-packages (e.g., `cipher/aesgcm/`, `keystore/postgres/`).
- **PII keys are always version 1** — the `pii.Adapter` hardcodes this. Secret keys track versions for rotation.
- **Memory hygiene**: DEKs must be zeroed after use with `defer encryption.ZeroBytes(dek)` (or `encerr.ZeroBytes` in sub-packages). Never leave plaintext key material in memory.
- **Sentinel errors**: Use errors from `encerr` package in sub-packages, or from root `encryption` in consumer code. Wrap with `fmt.Errorf("context: %w", err)`.
- **Context-based transaction participation**: The `KeyStore` interface is storage-agnostic (no SQL types). The PostgreSQL implementation resolves DB handles via `keystore.WithTx(ctx, tx)` context helper or falls back to `*sql.DB`. For UoW consumers, `postgres.NewStoreWithTxExtractor` accepts a custom extractor function.
- **Generic subject IDs**: PII interfaces use `[ID fmt.Stringer]` generics for type-safe subject IDs without coupling to domain types.
- **Scope/ScopeID pattern**: Keys are organized by `(scope, scopeID)` pairs — scope identifies the category (e.g., `"user_pii"`), scopeID identifies the entity.
- **Default cipher via init()**: `cipher/aesgcm` registers itself as `DefaultCipherFactory` on import. `encryption.New()` uses this when no cipher is provided.
- **PostgreSQL migrations**: Embedded via `embed.FS` in `keystore/postgres/migrations/`. Default schema is `infrastructure`, table is `encryption_keys` — both configurable.
- **Testing**: stdlib `testing` only — no testify. Table-driven tests with `t.Run()`. Always use `-race` flag. The `testutil` package exports `NewTestKeyring()` and `InMemoryKeyStore` for consumer testing.
