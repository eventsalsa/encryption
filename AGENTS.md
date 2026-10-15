# Developer Agent Instructions — eventsalsa/encryption

This document contains rules, architecture guidelines, and workflows for developer agents contributing to the `eventsalsa/encryption` project.

---

## 1. Git Workflow & Commit Conventions

To maintain a clean and trace-friendly repository history, adhere strictly to the following Git conventions:

### Branch Management
- **No Direct Commits to Main**: Never commit or push directly to `main`.
- **Branch Naming**: Always work on a separate branch. Branches must use the following prefix formats:
  - `feat/<description>` for new features
  - `fix/<description>` for bug fixes
  - `docs/<description>` for documentation changes
  - `chore/<description>` for maintenance and refactoring
- **Transitioning from Main**: If the current active branch is `main`, checkout a new branch before modifying any codebase files:
  ```bash
  git checkout -b chore/migrate-to-agent-setup
  ```

### Commit Messages
- **Conventional Commits**: Every commit message must start with a standard prefix (e.g., `feat:`, `fix:`, `docs:`, `test:`, `chore:`).
- **Extended Body Required**: Commits must include a descriptive body detailing what changed and why, rather than a single-line summary.
- **Commit Formatting**: When committing from the CLI, do not use literal newline characters (`\n`). Instead, specify multiple `-m` flags to structure the subject line and descriptive body separately:
  ```bash
  git commit -m "feat: integrate envelope encryptor with pgx store" -m "This change wraps the postgres keystore to extract transactions from context during encryption, satisfying the transaction-propagation requirements without leaking driver details."
  ```

---

## 2. Build & Validation Suite

Before completing any coding task, execute the full local validation suite. All checks must pass without warnings or errors.

```bash
# Canonical local check entrypoint (root module + KMS sub-modules)
make check

# Build the root module and sub-modules
make build

# Run the test suite with race detection
make test
```

The validation suite requires Go 1.24+ and keeps the root module free of cloud SDK dependencies. Cloud KMS adapters (`kek/awskms`, `kek/gcpkms`) are isolated in their own Go sub-modules.

---

## 3. Architecture & Core Layout

This repository provides a KMS-native envelope encryption library for event-sourced systems.

### Package Structure

| Directory | Package | Role / Description |
|-----------|---------|--------------------|
| [errors.go](errors.go) / [key.go](key.go) / [zerobytes.go](zerobytes.go) | `encryption` | Root package defining sentinel errors, shared `EncryptedKey` / `KeyScope` domain types, and memory zeroing utilities. |
| [cipher/](cipher) | `cipher` | Pluggable AEAD symmetric encryption interface with AAD support and implementations (default: `cipher/aesgcm` AES-256-GCM). |
| [kek/](kek) | `kek` | Key Encryption Key (KEK) abstractions (`Wrapper`, `Rewrapper`, `Keyring`), `CachingKeyring` decorator, and local/cloud KMS providers (`kek/local`, `kek/awskms`, `kek/gcpkms`). |
| [envelope/](envelope) | `envelope` | Envelope encryption engine coordinating KEK-based DEK wrapping/unwrapping/rewrapping with `KeyScope` AAD binding and reusable in-memory `Session` handles. |
| [postgres/](postgres) | `postgres` | Stateless PostgreSQL keystore and key lifecycle management (`CreateKey`, `RotateKey`, `GetActiveKey`, `GetKey`, `RevokeKeys`, `DestroyKeys`, `RewrapKeys`). |
| [postgres/migrations/](postgres/migrations) | `migrations` | Embedded PostgreSQL migration SQL and migration generator. |
| [hash/](hash) | `hash` | Deterministic blind indexing (HMAC-SHA256). |

---

## 4. Key Coding Conventions

- **Acyclic Dependencies**: The root `encryption` package has zero internal imports and defines sentinel errors, `EncryptedKey`, `KeyScope`, and `ZeroBytes`. Internal packages import `encryption` directly.
- **KMS-Native KEK Boundary**: KEKs never cross interface boundaries as raw byte slices. All KEK operations flow through `kek.Wrapper` and `kek.Keyring` with `context.Context` and mandatory `KeyScope` AAD.
- **Stateless Storage**: `postgres.Store` is stateless configuration only; all operations accept an unexported `conn pgxConn` interface satisfied by `*pgxpool.Pool`, `pgx.Tx`, and `*pgx.Conn`.
- **Memory Hygiene**: Always scrub plaintext keys (DEKs) from memory when finished. Defer `encryption.ZeroBytes` or `session.Close()` immediately after unwrapping or opening a session.
- **Scope Namespacing & AAD Binding**: Keys are grouped by `(scope, scopeID, keyVersion)` tuples and cryptographically bound to their scope via AAD to prevent confused-deputy / ciphertext-transplant attacks.
