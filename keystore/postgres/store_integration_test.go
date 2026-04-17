//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/eventsalsa/encryption/cipher/aesgcm"
	encryption "github.com/eventsalsa/encryption/encerr"
	"github.com/eventsalsa/encryption/envelope"
	"github.com/eventsalsa/encryption/keystore"
	"github.com/eventsalsa/encryption/keystore/postgres"
	"github.com/eventsalsa/encryption/keystore/postgres/migrations"
	"github.com/eventsalsa/encryption/systemkey"

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

func mustStoreEncryptedKey(t *testing.T, store *postgres.Store, ctx context.Context, c *aesgcm.Cipher, systemKey []byte, systemKeyID, scope, scopeID string, version int, dek []byte) {
	t.Helper()

	encryptedDEK, err := c.Encrypt(systemKey, dek)
	if err != nil {
		t.Fatalf("encrypt DEK: %v", err)
	}
	if err := store.CreateKey(ctx, scope, scopeID, version, encryptedDEK, systemKeyID); err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
}

func mustDecryptDEK(t *testing.T, c *aesgcm.Cipher, systemKey []byte, encryptedDEK []byte) []byte {
	t.Helper()

	dek, err := c.Decrypt(systemKey, encryptedDEK)
	if err != nil {
		t.Fatalf("decrypt DEK: %v", err)
	}
	return dek
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

func TestRewrapSystemKeys_RewrapsMatchingRows(t *testing.T) {
	db := setupPostgres(t)
	store := postgres.NewStore(postgres.Config{}, db)
	ctx := context.Background()
	c := aesgcm.New()

	oldKey := makeSystemKey(10)
	newKey := makeSystemKey(100)
	keyring := systemkey.NewKeyring(map[string][]byte{
		"old": oldKey,
		"new": newKey,
	}, "new")

	oldActiveDEK := []byte("0123456789abcdef0123456789abcdef")
	oldRevokedDEK := []byte("abcdef0123456789abcdef0123456789")
	piiDEK := []byte("fedcba9876543210fedcba9876543210")
	alreadyNewDEK := []byte("00112233445566778899aabbccddeeff")

	mustStoreEncryptedKey(t, store, ctx, c, oldKey, "old", "secret", "stripe", 1, oldRevokedDEK)
	mustStoreEncryptedKey(t, store, ctx, c, oldKey, "old", "secret", "stripe", 2, oldActiveDEK)
	if err := store.RevokeKeys(ctx, "secret", "stripe"); err != nil {
		t.Fatalf("RevokeKeys: %v", err)
	}
	mustStoreEncryptedKey(t, store, ctx, c, oldKey, "old", "pii", "user-1", 1, piiDEK)
	mustStoreEncryptedKey(t, store, ctx, c, newKey, "new", "secret", "already-new", 1, alreadyNewDEK)

	unchangedBefore, err := store.GetKey(ctx, "secret", "already-new", 1)
	if err != nil {
		t.Fatalf("GetKey already-new before rewrap: %v", err)
	}

	result, err := store.RewrapSystemKeys(ctx, keyring, c, postgres.RewrapSystemKeysOptions{
		FromSystemKeyID: "old",
		ToSystemKeyID:   "new",
		BatchSize:       1,
	})
	if err != nil {
		t.Fatalf("RewrapSystemKeys: %v", err)
	}
	if result.MatchedRows != 3 {
		t.Fatalf("MatchedRows = %d, want 3", result.MatchedRows)
	}
	if result.RewrappedRows != 3 {
		t.Fatalf("RewrappedRows = %d, want 3", result.RewrappedRows)
	}
	if result.SkippedRows != 0 {
		t.Fatalf("SkippedRows = %d, want 0", result.SkippedRows)
	}
	if result.RemainingRows != 0 {
		t.Fatalf("RemainingRows = %d, want 0", result.RemainingRows)
	}
	if result.Batches != 3 {
		t.Fatalf("Batches = %d, want 3", result.Batches)
	}

	oldRevoked, err := store.GetKey(ctx, "secret", "stripe", 1)
	if err != nil {
		t.Fatalf("GetKey secret/stripe v1: %v", err)
	}
	if oldRevoked.SystemKeyID != "new" {
		t.Fatalf("system key v1 = %q, want %q", oldRevoked.SystemKeyID, "new")
	}
	if oldRevoked.RevokedAt == nil {
		t.Fatal("revoked key should remain revoked")
	}
	if got := mustDecryptDEK(t, c, newKey, oldRevoked.EncryptedDEK); !bytes.Equal(got, oldRevokedDEK) {
		t.Fatalf("v1 DEK mismatch: got %x want %x", got, oldRevokedDEK)
	}

	oldActive, err := store.GetKey(ctx, "secret", "stripe", 2)
	if err != nil {
		t.Fatalf("GetKey secret/stripe v2: %v", err)
	}
	if oldActive.SystemKeyID != "new" {
		t.Fatalf("system key v2 = %q, want %q", oldActive.SystemKeyID, "new")
	}
	if got := mustDecryptDEK(t, c, newKey, oldActive.EncryptedDEK); !bytes.Equal(got, oldActiveDEK) {
		t.Fatalf("v2 DEK mismatch: got %x want %x", got, oldActiveDEK)
	}

	piiKey, err := store.GetKey(ctx, "pii", "user-1", 1)
	if err != nil {
		t.Fatalf("GetKey pii/user-1 v1: %v", err)
	}
	if piiKey.SystemKeyID != "new" {
		t.Fatalf("pii system key = %q, want %q", piiKey.SystemKeyID, "new")
	}
	if got := mustDecryptDEK(t, c, newKey, piiKey.EncryptedDEK); !bytes.Equal(got, piiDEK) {
		t.Fatalf("pii DEK mismatch: got %x want %x", got, piiDEK)
	}

	unchangedAfter, err := store.GetKey(ctx, "secret", "already-new", 1)
	if err != nil {
		t.Fatalf("GetKey already-new after rewrap: %v", err)
	}
	if unchangedAfter.SystemKeyID != "new" {
		t.Fatalf("already-new system key = %q, want %q", unchangedAfter.SystemKeyID, "new")
	}
	if !bytes.Equal(unchangedAfter.EncryptedDEK, unchangedBefore.EncryptedDEK) {
		t.Fatal("already-new row should not be rewritten")
	}
}

func TestRewrapSystemKeys_DryRun(t *testing.T) {
	db := setupPostgres(t)
	store := postgres.NewStore(postgres.Config{}, db)
	ctx := context.Background()
	c := aesgcm.New()

	oldKey := makeSystemKey(20)
	newKey := makeSystemKey(120)
	keyring := systemkey.NewKeyring(map[string][]byte{
		"old": oldKey,
		"new": newKey,
	}, "new")

	dek := []byte("11223344556677889900aabbccddeeff")
	mustStoreEncryptedKey(t, store, ctx, c, oldKey, "old", "secret", "dry-run", 1, dek)

	before, err := store.GetKey(ctx, "secret", "dry-run", 1)
	if err != nil {
		t.Fatalf("GetKey before dry-run: %v", err)
	}

	result, err := store.RewrapSystemKeys(ctx, keyring, c, postgres.RewrapSystemKeysOptions{
		FromSystemKeyID: "old",
		ToSystemKeyID:   "new",
		DryRun:          true,
	})
	if err != nil {
		t.Fatalf("RewrapSystemKeys dry-run: %v", err)
	}
	if result.MatchedRows != 1 {
		t.Fatalf("MatchedRows = %d, want 1", result.MatchedRows)
	}
	if result.RewrappedRows != 0 {
		t.Fatalf("RewrappedRows = %d, want 0", result.RewrappedRows)
	}
	if result.RemainingRows != 1 {
		t.Fatalf("RemainingRows = %d, want 1", result.RemainingRows)
	}
	if result.Batches != 0 {
		t.Fatalf("Batches = %d, want 0", result.Batches)
	}

	after, err := store.GetKey(ctx, "secret", "dry-run", 1)
	if err != nil {
		t.Fatalf("GetKey after dry-run: %v", err)
	}
	if after.SystemKeyID != "old" {
		t.Fatalf("system key after dry-run = %q, want %q", after.SystemKeyID, "old")
	}
	if !bytes.Equal(after.EncryptedDEK, before.EncryptedDEK) {
		t.Fatal("dry-run should not modify ciphertext")
	}
}

func TestRewrapSystemKeys_Idempotent(t *testing.T) {
	db := setupPostgres(t)
	store := postgres.NewStore(postgres.Config{}, db)
	ctx := context.Background()
	c := aesgcm.New()

	oldKey := makeSystemKey(30)
	newKey := makeSystemKey(130)
	keyring := systemkey.NewKeyring(map[string][]byte{
		"old": oldKey,
		"new": newKey,
	}, "new")

	dek := []byte("ffeeddccbbaa00998877665544332211")
	mustStoreEncryptedKey(t, store, ctx, c, oldKey, "old", "secret", "idempotent", 1, dek)

	first, err := store.RewrapSystemKeys(ctx, keyring, c, postgres.RewrapSystemKeysOptions{
		FromSystemKeyID: "old",
		ToSystemKeyID:   "new",
	})
	if err != nil {
		t.Fatalf("first RewrapSystemKeys: %v", err)
	}
	if first.RewrappedRows != 1 {
		t.Fatalf("first RewrappedRows = %d, want 1", first.RewrappedRows)
	}
	if first.RemainingRows != 0 {
		t.Fatalf("first RemainingRows = %d, want 0", first.RemainingRows)
	}

	second, err := store.RewrapSystemKeys(ctx, keyring, c, postgres.RewrapSystemKeysOptions{
		FromSystemKeyID: "old",
		ToSystemKeyID:   "new",
	})
	if err != nil {
		t.Fatalf("second RewrapSystemKeys: %v", err)
	}
	if second.MatchedRows != 0 {
		t.Fatalf("second MatchedRows = %d, want 0", second.MatchedRows)
	}
	if second.RewrappedRows != 0 {
		t.Fatalf("second RewrappedRows = %d, want 0", second.RewrappedRows)
	}
	if second.RemainingRows != 0 {
		t.Fatalf("second RemainingRows = %d, want 0", second.RemainingRows)
	}
}

func TestRewrapSystemKeys_ConcurrentRuns(t *testing.T) {
	db := setupPostgres(t)
	store := postgres.NewStore(postgres.Config{}, db)
	ctx := context.Background()
	c := aesgcm.New()

	oldKey := makeSystemKey(40)
	newKey := makeSystemKey(140)
	keyring := systemkey.NewKeyring(map[string][]byte{
		"old": oldKey,
		"new": newKey,
	}, "new")

	for i := 0; i < 10; i++ {
		scopeID := fmt.Sprintf("concurrent-%d", i)
		dek := []byte(fmt.Sprintf("%032d", i))
		mustStoreEncryptedKey(t, store, ctx, c, oldKey, "old", "secret", scopeID, 1, dek)
	}

	results := make([]postgres.RewrapSystemKeysResult, 2)
	errs := make([]error, 2)
	var wg sync.WaitGroup

	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = store.RewrapSystemKeys(ctx, keyring, c, postgres.RewrapSystemKeysOptions{
				FromSystemKeyID: "old",
				ToSystemKeyID:   "new",
				BatchSize:       1,
			})
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
	}

	totalRewrapped := results[0].RewrappedRows + results[1].RewrappedRows
	if totalRewrapped != 10 {
		t.Fatalf("total rewrapped rows = %d, want 10", totalRewrapped)
	}

	for i := 0; i < 10; i++ {
		scopeID := fmt.Sprintf("concurrent-%d", i)
		key, err := store.GetKey(ctx, "secret", scopeID, 1)
		if err != nil {
			t.Fatalf("GetKey %s: %v", scopeID, err)
		}
		if key.SystemKeyID != "new" {
			t.Fatalf("%s system key = %q, want %q", scopeID, key.SystemKeyID, "new")
		}
	}
}

func TestRewrapSystemKeys_HistoricalCiphertextsRemainDecryptable(t *testing.T) {
	db := setupPostgres(t)
	store := postgres.NewStore(postgres.Config{}, db)
	ctx := context.Background()
	c := aesgcm.New()

	oldKey := makeSystemKey(50)
	newKey := makeSystemKey(150)
	oldOnly := systemkey.NewKeyring(map[string][]byte{
		"old": oldKey,
	}, "old")
	bothKeys := systemkey.NewKeyring(map[string][]byte{
		"old": oldKey,
		"new": newKey,
	}, "new")
	newOnly := systemkey.NewKeyring(map[string][]byte{
		"new": newKey,
	}, "new")

	mustStoreEncryptedKey(t, store, ctx, c, oldKey, "old", "secret", "history", 1, []byte("11111111111111111111111111111111"))
	oldEncryptor := envelope.NewEncryptor(oldOnly, store, c)

	ciphertextV1, versionV1, err := oldEncryptor.Encrypt(ctx, "secret", "history", "alpha")
	if err != nil {
		t.Fatalf("Encrypt v1: %v", err)
	}
	if versionV1 != 1 {
		t.Fatalf("versionV1 = %d, want 1", versionV1)
	}

	mustStoreEncryptedKey(t, store, ctx, c, oldKey, "old", "secret", "history", 2, []byte("22222222222222222222222222222222"))
	if err := store.RevokeKeys(ctx, "secret", "history"); err != nil {
		t.Fatalf("RevokeKeys: %v", err)
	}

	ciphertextV2, versionV2, err := oldEncryptor.Encrypt(ctx, "secret", "history", "beta")
	if err != nil {
		t.Fatalf("Encrypt v2: %v", err)
	}
	if versionV2 != 2 {
		t.Fatalf("versionV2 = %d, want 2", versionV2)
	}

	result, err := store.RewrapSystemKeys(ctx, bothKeys, c, postgres.RewrapSystemKeysOptions{
		FromSystemKeyID: "old",
		ToSystemKeyID:   "new",
	})
	if err != nil {
		t.Fatalf("RewrapSystemKeys: %v", err)
	}
	if result.RewrappedRows != 2 {
		t.Fatalf("RewrappedRows = %d, want 2", result.RewrappedRows)
	}

	newEncryptor := envelope.NewEncryptor(newOnly, store, c)

	plaintextV1, err := newEncryptor.Decrypt(ctx, "secret", "history", ciphertextV1, versionV1)
	if err != nil {
		t.Fatalf("Decrypt v1 with new key only: %v", err)
	}
	if plaintextV1 != "alpha" {
		t.Fatalf("plaintextV1 = %q, want %q", plaintextV1, "alpha")
	}

	plaintextV2, err := newEncryptor.Decrypt(ctx, "secret", "history", ciphertextV2, versionV2)
	if err != nil {
		t.Fatalf("Decrypt v2 with new key only: %v", err)
	}
	if plaintextV2 != "beta" {
		t.Fatalf("plaintextV2 = %q, want %q", plaintextV2, "beta")
	}
}
