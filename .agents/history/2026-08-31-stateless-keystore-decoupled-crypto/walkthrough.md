# Refactor: Decouple Envelope Crypto Engine & Stateless Keystore

## Summary

This refactor decouples envelope encryption from persistent storage and converts `keystore/postgres` into a stateless adapter.

Key architectural improvements:
1. **Decoupled Crypto Engine (`envelope.Envelope`)**: Pure in-memory cryptographic transformations (`Encrypt`, `Decrypt`, `WrapDEK`, `UnwrapDEK`, `GenerateDEK`, `ActiveKeyID`) with zero storage or context dependencies.
2. **Stateless `postgres.Store`**: Holds only configuration (`Config`). All CRUD operations (`CreateKey`, `GetActiveKey`, `GetKey`, `RevokeKeys`, `DestroyKeys`) take an explicit `conn postgres.PgxConn` parameter (`*pgxpool.Pool`, `pgx.Tx`, `*pgx.Conn`).
3. **Clean Dependency Injection & First-Class Transactions**: Eliminates the stateful fallback mechanism (`*pgxpool.Pool` embedded in store) and context pollution (`keystore.WithTx` / `keystore.context.go`). Consumers can inject standard singleton stores into their DI graphs and pass transactions directly into method invocations.
4. **Standalone Admin Function (`postgres.RewrapSystemKeys`)**: Decoupled from `Store` instance methods into a standalone administrative migration function operating on `*pgxpool.Pool`.
5. **Removed Obsolete Domain Fluff**: Removed `pii` and `secret` domain wrapper packages in favor of pure envelope primitives and `keymanager` operations.

---

## Changes

### 1. `envelope` Package
- Replaced `envelope.Encryptor` with `envelope.Envelope`.
- Removed database dependencies and context from `Encrypt` and `Decrypt`.
- Signatures:
  - `Encrypt(sysKeyID string, encDEK []byte, plaintext string) (string, error)`
  - `Decrypt(sysKeyID string, encDEK []byte, ciphertext string) (string, error)`
  - `WrapDEK(sysKeyID string, dek []byte) ([]byte, error)`
  - `UnwrapDEK(sysKeyID string, encDEK []byte) ([]byte, error)`
  - `GenerateDEK() ([]byte, error)`
  - `ActiveKeyID() string`

### 2. `keystore/postgres` Package
- Removed `db *pgxpool.Pool` and `extractor TxExtractor` from `Store`.
- Added `PgxConn` interface satisfied by `*pgxpool.Pool`, `pgx.Tx`, and `*pgx.Conn`.
- Updated all store CRUD methods to accept `conn PgxConn`.
- Converted `RewrapSystemKeys` to standalone admin function:
  `RewrapSystemKeys(ctx, pool, cfg, keyring, cipher, opts)`.
- Deleted `keystore/context.go` and `keystore/context_test.go`.

### 3. `keymanager` Package
- `Manager` now holds `store KeyStore` and `env *envelope.Envelope`.
- All methods accept `conn postgres.PgxConn` and coordinate DEK generation/wrapping via `env`.

### 4. Domain Packages
- Deleted `pii/` and `secret/` packages.

### 5. Documentation & Examples
- Updated `encryption.go` composition root.
- Updated `examples/basic`, `examples/pii`, and `examples/secrets`.
- Updated `README.md`, `doc.go`, and `AGENTS.md`.

---

## Verification Results

### Unit Tests
```bash
go test -race ./...
```
All unit tests pass with zero race conditions.

### Integration Tests
```bash
go test -race -tags=integration ./keystore/postgres/...
```
All 13 testcontainers PostgreSQL integration tests pass (CRUD, concurrency, idempotency, isolation, transaction rollback/commit, rewrapping).

### Linter & Security
```bash
golangci-lint run --timeout=5m
go vet ./...
gosec ./...
```
Passed with 0 issues.
