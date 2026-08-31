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
# Canonical local check entrypoint
make check

# Build the module
go build ./...

# Run the test suite with race detection
go test -race ./...
```

The validation suite requires Go 1.24+ and is designed with zero external runtime dependencies. The postgres store adapter requires a database driver supplied by the consumer.

---

## 3. Architecture & Core Layout

This repository provides an envelope encryption library for event-sourced systems.

### Package Structure

| Directory | Package | Role / Description |
|-----------|---------|--------------------|
| [errors.go](errors.go) / [zerobytes.go](zerobytes.go) | `encryption` | Root package defining sentinel errors (`ErrKeyNotFound`, etc.) and memory zeroing utilities. |
| [cipher/](cipher) | `cipher` | Pluggable symmetric encryption interface and implementations (default: `cipher/aesgcm` AES-256-GCM). |
| [systemkey/](systemkey) | `systemkey` | KEK (Key Encrypting Key) management abstractions and filesystem loaders. |
| [envelope/](envelope) | `envelope` | Pure in-memory envelope encryption engine (DEK wrapping/unwrapping & data encrypt/decrypt). |
| [postgres/](postgres) | `postgres` | Stateless PostgreSQL keystore and key lifecycle management (`CreateKey`, `RotateKey`, `GetActiveKey`, `GetKey`, `RevokeKeys`, `DestroyKeys`, `RewrapSystemKeys`). |
| [postgres/migrations/](postgres/migrations) | `migrations` | Embedded PostgreSQL migration SQL and migration generator. |
| [hash/](hash) | `hash` | Deterministic blind indexing (HMAC-SHA256). |

---

## 4. Key Coding Conventions

- **Acyclic Dependencies**: The root `encryption` package has zero internal imports and defines sentinel errors and `ZeroBytes`. Internal packages import `encryption` directly.
- **Decoupled In-Memory Crypto**: `envelope.Envelope` is a pure in-memory engine with zero storage or context dependencies.
- **Stateless Storage**: `postgres.Store` is stateless configuration only; all operations accept an unexported `conn pgxConn` interface satisfied by `*pgxpool.Pool`, `pgx.Tx`, and `*pgx.Conn`.
- **Memory Hygiene**: Always scrub plaintext keys (DEKs) from memory when finished. Defer `encryption.ZeroBytes` immediately after generation or unwrapping.
- **Scope Namespacing**: Keys are grouped by namespaces using `(scope, scopeID)` tuples to partition encryption scopes.

