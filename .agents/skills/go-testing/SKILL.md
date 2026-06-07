---
name: go-testing
description: Standard Go testing practices, memory hygiene validation, and PostgreSQL integration testing using testcontainers-go.
---

# Go Testing & Integration Guidelines

Use this skill when writing or reviewing unit tests, mocking behaviors, testing transactions, or developing PostgreSQL integration tests with Docker containers.

## Running Tests

Run tests using standard Go tools with race detection:
```bash
# Run all unit tests (excludes PostgreSQL integration tests)
go test -race -count=1 ./...

# Run tests in a single package
go test -race ./keymanager/

# Run a specific test
go test -race -run TestRotateKey ./keymanager/

# Run PostgreSQL integration tests (requires Docker)
go test -race -tags=integration ./keystore/postgres/...
```

## Unit Testing

### Style & Structure
- **Standard Library Only**: Use only the standard `testing` package. Do not introduce testing frameworks (like `testify`) or assertion libraries.
- **Table-Driven Tests**: Group test cases into slices and execute them using `t.Run(name, func(t *testing.T) {...})`.
- **File Placement**: Place test files directly next to the source code being tested (e.g., `foo.go` and `foo_test.go`).
- **Black-Box Testing**: Use the `_test` package suffix (e.g., `package keymanager_test`) for testing the public API.
- **Naming Conventions**: Keep test names short and descriptive (e.g., `TestRotateKeyLeavesNewVersionActive`).

### Test Fakes & Mocking
- The `testutil` package provides shared fakes for testing:
  - `testutil.NewTestKeyring()`: Returns a keyring containing a random 32-byte key under ID `"test-key-1"`.
  - `testutil.NewInMemoryKeyStore()`: Returns a thread-safe, in-memory `KeyStore` implementation.
- If a package needs custom mock behavior (such as testing error injection), define the mock locally within that package's test files instead of adding it to the shared `testutil` package.

### Sentinel Assertions
Verify expected sentinel errors using `errors.Is`:
```go
if !errors.Is(err, encryption.ErrKeyNotFound) {
    t.Fatalf("expected ErrKeyNotFound, got %v", err)
}
```
*Note: Sub-packages must import sentinel errors from the `encerr` package rather than the root `encryption` package to prevent circular dependencies.*

### Memory Hygiene Verification
Verify that sensitive key material (such as DEKs) has been successfully zeroed after use:
```go
defer encryption.ZeroBytes(dek)
// ... use dek ...
for _, b := range dek {
    if b != 0 {
        t.Fatal("DEK was not zeroed in memory")
    }
}
```

## PostgreSQL Integration Testing

### Build Tags & Isolation
All database integration tests must be guarded by an integration build tag at the very top of the file:
```go
//go:build integration

package postgres_test
```
This isolates database tests from the standard unit test run. They will run only when `-tags=integration` is passed.

### Testcontainers Setup
Use `testcontainers-go` to spin up a PostgreSQL instance dynamically. Implement a setup helper in each test file:
```go
import (
    "context"
    "database/sql"
    "testing"

    "github.com/testcontainers/testcontainers-go"
    "github.com/testcontainers/testcontainers-go/modules/postgres"
    "github.com/testcontainers/testcontainers-go/wait"
    _ "github.com/lib/pq"
)

func setupPostgres(t *testing.T) *sql.DB {
    t.Helper()
    ctx := context.Background()

    ctr, err := postgres.Run(ctx, "postgres:16-alpine",
        postgres.WithDatabase("test_encryption"),
        postgres.WithUsername("test"),
        postgres.WithPassword("test"),
        testcontainers.WithWaitStrategy(
            wait.ForLog("database system is ready to accept connections").
                WithOccurrence(2),
        ),
    )
    if err != nil {
        t.Fatalf("failed to start postgres container: %v", err)
    }
    t.Cleanup(func() { ctr.Terminate(ctx) })

    connStr, err := ctr.ConnectionString(ctx, "sslmode=disable")
    if err != nil {
        t.Fatalf("failed to get connection string: %v", err)
    }

    db, err := sql.Open("postgres", connStr)
    if err != nil {
        t.Fatalf("failed to open database: %v", err)
    }
    t.Cleanup(func() { db.Close() })

    // Apply database migrations
    migration, err := migrations.FS.ReadFile("001_encryption_keys.sql")
    if err != nil {
        t.Fatalf("failed to read migration file: %v", err)
    }
    if _, err := db.ExecContext(ctx, string(migration)); err != nil {
        t.Fatalf("failed to apply migration: %v", err)
    }

    return db
}
```

### Integration Scope
Integration tests must focus on database-specific operations:
- **Query Verification**: Verify database queries (parameterized syntax, NULL values, and subqueries).
- **Constraints**: Verify primary key constraints, CHECK constraints, and NOT NULL rules.
- **Transaction Rollbacks**: Verify transaction support via `keystore.WithTx(ctx, tx)`:
  ```go
  func TestPostgresStore_WithTxRollback(t *testing.T) {
      db := setupPostgres(t)
      store := postgres.NewStore(postgres.Config{}, db)
      ctx := context.Background()

      tx, err := db.BeginTx(ctx, nil)
      if err != nil {
          t.Fatal(err)
      }

      txCtx := keystore.WithTx(ctx, tx)
      _ = store.CreateKey(txCtx, "user", "u-1", 1, []byte("dek"), "sk-1")
      tx.Rollback()

      // Key must not exist after rolling back the transaction
      _, err = store.GetActiveKey(ctx, "user", "u-1")
      if !errors.Is(err, encryption.ErrKeyNotFound) {
          t.Fatalf("expected ErrKeyNotFound, got %v", err)
      }
  }
  ```
- **Active Key Filters**: Verify that key revocation updates active versions properly (e.g. subquery validation).
- **Concurrency**: Run concurrent routines inserting/rotating keys under different scopes to ensure no deadlocks.
- **Migration Idempotency**: Ensure table structures and indexes are safe when migrations run multiple times.

### Test Environment Rules
- **No Shared Containers**: Create a dedicated container instance (`setupPostgres`) per test file to prevent test interference and allow clean parallel executions.
- **Dynamic Ports**: Let Testcontainers bind ports dynamically to avoid port conflicts in parallel or CI environments.
- **Unique Scopes**: Use unique scopes/scopeIDs across different tests to prevent tests from modifying each other's data.
