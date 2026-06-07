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

This repository provides an envelope encryption library for event-sourced systems, handling two distinct categories of data:
1. **PII** (Personal Identifiable Information): Encrypted using per-subject keys. PII keys do not rotate. Deleting a key (crypto-shredding) renders the associated event payloads permanently unreadable.
2. **Secrets**: Versioned system keys that support rotation. Older versions are preserved to decrypt historic payloads.

### Package Structure

| Directory | Package | Role / Description |
|-----------|---------|--------------------|
| [encerr/](encerr) | `encerr` | Sentinel errors and memory zeroing utilities to prevent import cycles. |
| [cipher/](cipher) | `cipher` | Pluggable symmetric encryption interface and implementations (default: AES-256-GCM). |
| [systemkey/](systemkey) | `systemkey` | KEK (Key Encrypting Key) management abstractions. |
| [keystore/](keystore) | `keystore` | Persistent encrypted storage for DEKs (Data Encrypting Keys). |
| [keymanager/](keymanager) | `keymanager` | Core orchestration for key creation, rotation, and shredding. |
| [envelope/](envelope) | `envelope` | Main envelope encryption engine orchestrating DEK retrieval and encryption. |
| [pii/](pii) | `pii` | GDPR crypto-shredding value types and generic wrappers. |
| [secret/](secret) | `secret` | Versioned secret value types and rotation handling. |
| [hash/](hash) | `hash` | Deterministic hashing (HMAC-SHA256) for uniqueness assertions. |
| [encryption.go](encryption.go) | `encryption` | Main library entrypoint and package constructors. |

---

## 4. Key Coding Conventions

- **Circular Dependencies**: Avoid circular imports. Shared error sentinels and byte zeroing utilities live in [encerr/](encerr). Internal packages must import `encerr` directly. The root `encryption` package re-exports these public symbols for consumers.
- **Interfaces**: Code to interfaces (e.g., `Cipher`, `KeyStore`, `Keyring`). Concrete implementations reside in sub-packages (e.g., `cipher/aesgcm/`, `keystore/postgres/`).
- **Memory Hygiene**: Always scrub plaintext keys (DEKs) from memory when finished. Defer `encryption.ZeroBytes` or `encerr.ZeroBytes` immediately after instantiation.
- **Transaction Propagation**: The PostgreSQL store resolves database handles dynamically. Use `keystore.WithTx(ctx, tx)` to participate in an active SQL transaction or fallback to standard DB handle management.
- **Subject Generic Identifiers**: PII operations use type generics `[ID fmt.Stringer]` for safety without coupling identifiers to domain entities.
- **Scope Namespacing**: Keys are grouped by namespaces using `(scope, scopeID)` tuples to partition encryption scopes.

---

## 5. Specialized Skills

For specialized development workflows, reference and utilize the custom skills configured within this repository:

1. **DevOps & Workflows**: [go-devops](.agents/skills/go-devops/SKILL.md)
   - Configuration of GitHub Actions, golangci-lint, and dependency rules.
2. **Cryptographic Standards**: [secure-cryptography](.agents/skills/secure-cryptography/SKILL.md)
   - Nonce safety, key isolation rules, base64 layouts, and side-channel safety.
3. **Test Engineering**: [go-testing](.agents/skills/go-testing/SKILL.md)
   - Table-driven unit tests, memory verification patterns, and Docker-based PostgreSQL integration tests.

For command execution optimizations and token budget guidelines, see [antigravity-rtk-rules.md](.agents/rules/antigravity-rtk-rules.md).
