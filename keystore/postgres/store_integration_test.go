//go:build integration

package postgres_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	encryption "github.com/eventsalsa/encryption/encerr"
	"github.com/eventsalsa/encryption/keystore"
	"github.com/eventsalsa/encryption/keystore/postgres"
	"github.com/eventsalsa/encryption/keystore/postgres/migrations"

	_ "github.com/lib/pq"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

func setupPostgres(t *testing.T) *sql.DB {
	t.Helper()
	ctx := context.Background()

	ctr, err := tcpostgres.Run(ctx, "postgres:16-alpine",
		tcpostgres.WithDatabase("test_encryption"),
		tcpostgres.WithUsername("test"),
		tcpostgres.WithPassword("test"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("start postgres container: %v", err)
	}
	t.Cleanup(func() {
		if err := ctr.Terminate(ctx); err != nil {
			t.Logf("terminate container: %v", err)
		}
	})

	connStr, err := ctr.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("connection string: %v", err)
	}

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	// Create schema and apply migration.
	if _, err := db.ExecContext(ctx, "CREATE SCHEMA IF NOT EXISTS infrastructure"); err != nil {
		t.Fatalf("create schema: %v", err)
	}

	migration, err := migrations.FS.ReadFile("001_encryption_keys.sql")
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	if _, err := db.ExecContext(ctx, string(migration)); err != nil {
		t.Fatalf("apply migration: %v", err)
	}

	return db
}

// ---------------------------------------------------------------------------
// Basic CRUD
// ---------------------------------------------------------------------------

func TestCreateAndGetActiveKey(t *testing.T) {
	db := setupPostgres(t)
	store := postgres.NewStore(postgres.Config{}, db)
	ctx := context.Background()

	err := store.CreateKey(ctx, "user", "u-1", 1, []byte("enc-dek-1"), "sys-key-1")
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	key, err := store.GetActiveKey(ctx, "user", "u-1")
	if err != nil {
		t.Fatalf("GetActiveKey: %v", err)
	}
	if key.KeyVersion != 1 {
		t.Fatalf("expected version 1, got %d", key.KeyVersion)
	}
	if string(key.EncryptedDEK) != "enc-dek-1" {
		t.Fatalf("expected enc-dek-1, got %s", key.EncryptedDEK)
	}
	if key.SystemKeyID != "sys-key-1" {
		t.Fatalf("expected sys-key-1, got %s", key.SystemKeyID)
	}
	if key.RevokedAt != nil {
		t.Fatal("new key should not be revoked")
	}
}

func TestGetKeyByVersion(t *testing.T) {
	db := setupPostgres(t)
	store := postgres.NewStore(postgres.Config{}, db)
	ctx := context.Background()

	_ = store.CreateKey(ctx, "s", "id", 1, []byte("v1"), "sk")
	_ = store.CreateKey(ctx, "s", "id", 2, []byte("v2"), "sk")

	k1, err := store.GetKey(ctx, "s", "id", 1)
	if err != nil {
		t.Fatalf("GetKey v1: %v", err)
	}
	if string(k1.EncryptedDEK) != "v1" {
		t.Fatalf("v1 DEK mismatch: %s", k1.EncryptedDEK)
	}

	k2, err := store.GetKey(ctx, "s", "id", 2)
	if err != nil {
		t.Fatalf("GetKey v2: %v", err)
	}
	if string(k2.EncryptedDEK) != "v2" {
		t.Fatalf("v2 DEK mismatch: %s", k2.EncryptedDEK)
	}
}

func TestGetActiveKey_NotFound(t *testing.T) {
	db := setupPostgres(t)
	store := postgres.NewStore(postgres.Config{}, db)
	ctx := context.Background()

	_, err := store.GetActiveKey(ctx, "no", "key")
	if !errors.Is(err, encryption.ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound, got %v", err)
	}
}

func TestGetKey_NotFound(t *testing.T) {
	db := setupPostgres(t)
	store := postgres.NewStore(postgres.Config{}, db)
	ctx := context.Background()

	_, err := store.GetKey(ctx, "no", "key", 1)
	if !errors.Is(err, encryption.ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound, got %v", err)
	}
}

func TestGetActiveKey_ReturnsHighestVersion(t *testing.T) {
	db := setupPostgres(t)
	store := postgres.NewStore(postgres.Config{}, db)
	ctx := context.Background()

	_ = store.CreateKey(ctx, "s", "id", 1, []byte("v1"), "sk")
	_ = store.CreateKey(ctx, "s", "id", 2, []byte("v2"), "sk")
	_ = store.CreateKey(ctx, "s", "id", 3, []byte("v3"), "sk")

	key, err := store.GetActiveKey(ctx, "s", "id")
	if err != nil {
		t.Fatal(err)
	}
	if key.KeyVersion != 3 {
		t.Fatalf("expected version 3, got %d", key.KeyVersion)
	}
}

// ---------------------------------------------------------------------------
// RevokeKeys — the bug-fix scenario
// ---------------------------------------------------------------------------

func TestRevokeKeys_PreservesHighestVersion(t *testing.T) {
	db := setupPostgres(t)
	store := postgres.NewStore(postgres.Config{}, db)
	ctx := context.Background()

	_ = store.CreateKey(ctx, "s", "id", 1, []byte("v1"), "sk")
	_ = store.CreateKey(ctx, "s", "id", 2, []byte("v2"), "sk")
	_ = store.CreateKey(ctx, "s", "id", 3, []byte("v3"), "sk")

	if err := store.RevokeKeys(ctx, "s", "id"); err != nil {
		t.Fatalf("RevokeKeys: %v", err)
	}

	// Highest version should still be active.
	active, err := store.GetActiveKey(ctx, "s", "id")
	if err != nil {
		t.Fatalf("GetActiveKey after revoke: %v", err)
	}
	if active.KeyVersion != 3 {
		t.Fatalf("expected active version 3, got %d", active.KeyVersion)
	}

	// Older versions should be revoked.
	for _, v := range []int{1, 2} {
		k, err := store.GetKey(ctx, "s", "id", v)
		if err != nil {
			t.Fatalf("GetKey v%d: %v", v, err)
		}
		if k.RevokedAt == nil {
			t.Fatalf("version %d should be revoked", v)
		}
	}
}

func TestRevokeKeys_SingleKeyNotRevoked(t *testing.T) {
	db := setupPostgres(t)
	store := postgres.NewStore(postgres.Config{}, db)
	ctx := context.Background()

	_ = store.CreateKey(ctx, "s", "only", 1, []byte("v1"), "sk")

	if err := store.RevokeKeys(ctx, "s", "only"); err != nil {
		t.Fatalf("RevokeKeys: %v", err)
	}

	// Single key should remain active — there's nothing older to revoke.
	active, err := store.GetActiveKey(ctx, "s", "only")
	if err != nil {
		t.Fatalf("GetActiveKey: %v", err)
	}
	if active.KeyVersion != 1 {
		t.Fatalf("expected version 1, got %d", active.KeyVersion)
	}
}

func TestRevokeKeys_NoKeysIsNoop(t *testing.T) {
	db := setupPostgres(t)
	store := postgres.NewStore(postgres.Config{}, db)
	ctx := context.Background()

	// Should not error even if there are no keys.
	if err := store.RevokeKeys(ctx, "empty", "scope"); err != nil {
		t.Fatalf("RevokeKeys on empty scope: %v", err)
	}
}

// ---------------------------------------------------------------------------
// DestroyKeys
// ---------------------------------------------------------------------------

func TestDestroyKeys(t *testing.T) {
	db := setupPostgres(t)
	store := postgres.NewStore(postgres.Config{}, db)
	ctx := context.Background()

	_ = store.CreateKey(ctx, "s", "id", 1, []byte("v1"), "sk")
	_ = store.CreateKey(ctx, "s", "id", 2, []byte("v2"), "sk")

	if err := store.DestroyKeys(ctx, "s", "id"); err != nil {
		t.Fatalf("DestroyKeys: %v", err)
	}

	_, err := store.GetActiveKey(ctx, "s", "id")
	if !errors.Is(err, encryption.ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound after destroy, got %v", err)
	}

	_, err = store.GetKey(ctx, "s", "id", 1)
	if !errors.Is(err, encryption.ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound for v1 after destroy, got %v", err)
	}
}

func TestDestroyKeys_NoKeysIsNoop(t *testing.T) {
	db := setupPostgres(t)
	store := postgres.NewStore(postgres.Config{}, db)
	ctx := context.Background()

	if err := store.DestroyKeys(ctx, "empty", "scope"); err != nil {
		t.Fatalf("DestroyKeys on empty scope: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Scope isolation
// ---------------------------------------------------------------------------

func TestScopeIsolation(t *testing.T) {
	db := setupPostgres(t)
	store := postgres.NewStore(postgres.Config{}, db)
	ctx := context.Background()

	_ = store.CreateKey(ctx, "scope-a", "id-1", 1, []byte("a1"), "sk")
	_ = store.CreateKey(ctx, "scope-b", "id-1", 1, []byte("b1"), "sk")

	a, _ := store.GetActiveKey(ctx, "scope-a", "id-1")
	b, _ := store.GetActiveKey(ctx, "scope-b", "id-1")

	if string(a.EncryptedDEK) != "a1" {
		t.Fatalf("scope-a DEK: %s", a.EncryptedDEK)
	}
	if string(b.EncryptedDEK) != "b1" {
		t.Fatalf("scope-b DEK: %s", b.EncryptedDEK)
	}

	// Destroying scope-a should not affect scope-b.
	_ = store.DestroyKeys(ctx, "scope-a", "id-1")
	_, err := store.GetActiveKey(ctx, "scope-a", "id-1")
	if !errors.Is(err, encryption.ErrKeyNotFound) {
		t.Fatalf("scope-a should be destroyed")
	}
	bAfter, err := store.GetActiveKey(ctx, "scope-b", "id-1")
	if err != nil {
		t.Fatalf("scope-b should still exist: %v", err)
	}
	if bAfter.KeyVersion != 1 {
		t.Fatal("scope-b key should be untouched")
	}
}

// ---------------------------------------------------------------------------
// Transaction participation
// ---------------------------------------------------------------------------

func TestWithTx_Commit(t *testing.T) {
	db := setupPostgres(t)
	store := postgres.NewStore(postgres.Config{}, db)
	ctx := context.Background()

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}

	txCtx := keystore.WithTx(ctx, tx)
	if err := store.CreateKey(txCtx, "tx", "commit", 1, []byte("dek"), "sk"); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	// Key should be visible outside the transaction.
	key, err := store.GetActiveKey(ctx, "tx", "commit")
	if err != nil {
		t.Fatalf("key should exist after commit: %v", err)
	}
	if key.KeyVersion != 1 {
		t.Fatalf("expected version 1, got %d", key.KeyVersion)
	}
}

func TestWithTx_Rollback(t *testing.T) {
	db := setupPostgres(t)
	store := postgres.NewStore(postgres.Config{}, db)
	ctx := context.Background()

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}

	txCtx := keystore.WithTx(ctx, tx)
	_ = store.CreateKey(txCtx, "tx", "rollback", 1, []byte("dek"), "sk")
	tx.Rollback()

	_, err = store.GetActiveKey(ctx, "tx", "rollback")
	if !errors.Is(err, encryption.ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound after rollback, got %v", err)
	}
}

func TestWithTx_MultipleOperationsAtomic(t *testing.T) {
	db := setupPostgres(t)
	store := postgres.NewStore(postgres.Config{}, db)
	ctx := context.Background()

	// Create initial key outside tx.
	_ = store.CreateKey(ctx, "tx", "atomic", 1, []byte("v1"), "sk")

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}

	txCtx := keystore.WithTx(ctx, tx)
	// Create v2 and revoke within same tx.
	if err := store.CreateKey(txCtx, "tx", "atomic", 2, []byte("v2"), "sk"); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := store.RevokeKeys(txCtx, "tx", "atomic"); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	tx.Rollback()

	// After rollback, only v1 should exist and be active.
	active, err := store.GetActiveKey(ctx, "tx", "atomic")
	if err != nil {
		t.Fatalf("GetActiveKey: %v", err)
	}
	if active.KeyVersion != 1 {
		t.Fatalf("expected version 1 after rollback, got %d", active.KeyVersion)
	}
}

// ---------------------------------------------------------------------------
// TxExtractor
// ---------------------------------------------------------------------------

type customTxKey struct{}

func TestTxExtractor(t *testing.T) {
	db := setupPostgres(t)
	ctx := context.Background()

	store := postgres.NewStoreWithTxExtractor(postgres.Config{}, db,
		func(ctx context.Context) *sql.Tx {
			tx, _ := ctx.Value(customTxKey{}).(*sql.Tx)
			return tx
		},
	)

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Use custom context key (not keystore.WithTx).
	txCtx := context.WithValue(ctx, customTxKey{}, tx)
	if err := store.CreateKey(txCtx, "ext", "custom", 1, []byte("dek"), "sk"); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	key, err := store.GetActiveKey(ctx, "ext", "custom")
	if err != nil {
		t.Fatalf("key should exist: %v", err)
	}
	if key.KeyVersion != 1 {
		t.Fatalf("expected version 1, got %d", key.KeyVersion)
	}
}

// ---------------------------------------------------------------------------
// Custom config
// ---------------------------------------------------------------------------

func TestCustomSchemaAndTable(t *testing.T) {
	db := setupPostgres(t)
	ctx := context.Background()

	// Create custom schema and table.
	if _, err := db.ExecContext(ctx, "CREATE SCHEMA IF NOT EXISTS custom_schema"); err != nil {
		t.Fatal(err)
	}
	migration, _ := migrations.FS.ReadFile("001_encryption_keys.sql")
	// Replace schema in migration.
	customMigration := "CREATE TABLE IF NOT EXISTS custom_schema.custom_keys (" +
		"scope TEXT NOT NULL, scope_id TEXT NOT NULL, key_version INT NOT NULL, " +
		"encrypted_key BYTEA NOT NULL, system_key_id TEXT NOT NULL DEFAULT 'default', " +
		"created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), revoked_at TIMESTAMPTZ, " +
		"PRIMARY KEY (scope, scope_id, key_version))"
	_ = migration // use our custom DDL
	if _, err := db.ExecContext(ctx, customMigration); err != nil {
		t.Fatal(err)
	}

	store := postgres.NewStore(postgres.Config{
		Schema: "custom_schema",
		Table:  "custom_keys",
	}, db)

	if err := store.CreateKey(ctx, "s", "id", 1, []byte("dek"), "sk"); err != nil {
		t.Fatalf("CreateKey with custom schema/table: %v", err)
	}

	key, err := store.GetActiveKey(ctx, "s", "id")
	if err != nil {
		t.Fatalf("GetActiveKey with custom schema/table: %v", err)
	}
	if key.KeyVersion != 1 {
		t.Fatalf("expected version 1, got %d", key.KeyVersion)
	}
}

// ---------------------------------------------------------------------------
// Duplicate key version (PK constraint)
// ---------------------------------------------------------------------------

func TestCreateKey_DuplicateVersionFails(t *testing.T) {
	db := setupPostgres(t)
	store := postgres.NewStore(postgres.Config{}, db)
	ctx := context.Background()

	_ = store.CreateKey(ctx, "s", "id", 1, []byte("dek"), "sk")
	err := store.CreateKey(ctx, "s", "id", 1, []byte("dek2"), "sk")
	if err == nil {
		t.Fatal("expected error for duplicate key version")
	}
}

// ---------------------------------------------------------------------------
// Concurrent access
// ---------------------------------------------------------------------------

func TestConcurrentCreateDifferentScopes(t *testing.T) {
	db := setupPostgres(t)
	store := postgres.NewStore(postgres.Config{}, db)
	ctx := context.Background()

	const n = 20
	var wg sync.WaitGroup
	errs := make([]error, n)

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			scopeID := fmt.Sprintf("concurrent-%d", i)
			errs[i] = store.CreateKey(ctx, "conc", scopeID, 1, []byte("dek"), "sk")
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: %v", i, err)
		}
	}

	// Verify all keys exist.
	for i := 0; i < n; i++ {
		scopeID := fmt.Sprintf("concurrent-%d", i)
		if _, err := store.GetActiveKey(ctx, "conc", scopeID); err != nil {
			t.Fatalf("missing key for %s: %v", scopeID, err)
		}
	}
}

// ---------------------------------------------------------------------------
// Migration idempotency
// ---------------------------------------------------------------------------

func TestMigrationIdempotent(t *testing.T) {
	db := setupPostgres(t)
	ctx := context.Background()

	migration, _ := migrations.FS.ReadFile("001_encryption_keys.sql")

	// Apply migration a second time — should not fail due to IF NOT EXISTS.
	if _, err := db.ExecContext(ctx, string(migration)); err != nil {
		t.Fatalf("re-applying migration should be idempotent: %v", err)
	}
}
