//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eventsalsa/encryption"
	"github.com/eventsalsa/encryption/cipher/aesgcm"
	"github.com/eventsalsa/encryption/envelope"
	"github.com/eventsalsa/encryption/kek"
	"github.com/eventsalsa/encryption/kek/local"
	"github.com/eventsalsa/encryption/postgres"
	"github.com/eventsalsa/encryption/postgres/migrations"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

func setupPostgres(t *testing.T) *pgxpool.Pool {
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

	db, err := pgxpool.New(ctx, connStr)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	// Create schema and apply migration.
	if _, err := db.Exec(ctx, "CREATE SCHEMA IF NOT EXISTS infrastructure"); err != nil {
		t.Fatalf("create schema: %v", err)
	}

	migration, err := migrations.FS.ReadFile("001_encryption_keys.sql")
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	if _, err := db.Exec(ctx, string(migration)); err != nil {
		t.Fatalf("apply migration: %v", err)
	}

	return db
}

func setupTestStore(t *testing.T) (*postgres.Store, *envelope.Envelope) {
	t.Helper()
	c := aesgcm.New()
	key := makeSystemKey(1)
	keyring, err := local.NewKeyringFromMap(map[string][]byte{"kek-1": key}, "kek-1")
	if err != nil {
		t.Fatalf("NewKeyringFromMap: %v", err)
	}
	env := envelope.New(keyring, c)
	return postgres.NewStore(env, postgres.Config{}), env
}

func mustStoreRawEncryptedKey(t *testing.T, ctx context.Context, pool *pgxpool.Pool, c *aesgcm.Cipher, kekBytes []byte, kekID, scope, scopeID string, version int, dek []byte) {
	t.Helper()

	keyScope := encryption.KeyScope{Scope: scope, ScopeID: scopeID, KeyVersion: version}
	encryptedDEK, err := c.Encrypt(kekBytes, dek, keyScope.AAD())
	if err != nil {
		t.Fatalf("encrypt DEK: %v", err)
	}
	query := "INSERT INTO infrastructure.encryption_keys (scope, scope_id, key_version, encrypted_dek, kek_id) VALUES ($1, $2, $3, $4, $5)"
	if _, err := pool.Exec(ctx, query, scope, scopeID, version, encryptedDEK, kekID); err != nil {
		t.Fatalf("insert raw key fixture: %v", err)
	}
}

func mustDecryptDEK(t *testing.T, c *aesgcm.Cipher, kekBytes []byte, key *encryption.EncryptedKey) []byte {
	t.Helper()

	dek, err := c.Decrypt(kekBytes, key.EncryptedDEK, key.KeyScope().AAD())
	if err != nil {
		t.Fatalf("decrypt DEK: %v", err)
	}
	return dek
}

// ---------------------------------------------------------------------------
// Basic CRUD & Lifecycle
// ---------------------------------------------------------------------------

func TestCreateAndGetActiveKey(t *testing.T) {
	db := setupPostgres(t)
	store, env := setupTestStore(t)
	ctx := context.Background()

	created, err := store.CreateKey(ctx, db, "user", "u-1")
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	if created.KeyVersion != 1 {
		t.Fatalf("expected version 1, got %d", created.KeyVersion)
	}
	if created.KEKID != "kek-1" {
		t.Fatalf("expected kek-1, got %s", created.KEKID)
	}

	key, err := store.GetActiveKey(ctx, db, "user", "u-1")
	if err != nil {
		t.Fatalf("GetActiveKey: %v", err)
	}
	if key.KeyVersion != 1 {
		t.Fatalf("expected version 1, got %d", key.KeyVersion)
	}
	if key.KEKID != "kek-1" {
		t.Fatalf("expected kek-1, got %s", key.KEKID)
	}
	if key.RevokedAt != nil {
		t.Fatal("new key should not be revoked")
	}

	// Verify the DEK can be unwrapped and used by env
	ct, err := env.EncryptString(ctx, key, "hello world", []byte("greeting"))
	if err != nil {
		t.Fatalf("EncryptString with active key: %v", err)
	}
	pt, err := env.DecryptString(ctx, key, ct, []byte("greeting"))
	if err != nil {
		t.Fatalf("DecryptString: %v", err)
	}
	if pt != "hello world" {
		t.Fatalf("pt = %q, want %q", pt, "hello world")
	}
}

func TestRotateKey(t *testing.T) {
	db := setupPostgres(t)
	store, _ := setupTestStore(t)
	ctx := context.Background()

	v1, err := store.CreateKey(ctx, db, "secret", "s-1")
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	if v1.KeyVersion != 1 {
		t.Fatalf("expected version 1, got %d", v1.KeyVersion)
	}

	v2, err := store.RotateKey(ctx, db, "secret", "s-1")
	if err != nil {
		t.Fatalf("RotateKey: %v", err)
	}
	if v2.KeyVersion != 2 {
		t.Fatalf("expected version 2, got %d", v2.KeyVersion)
	}

	// Active key is v2
	active, err := store.GetActiveKey(ctx, db, "secret", "s-1")
	if err != nil {
		t.Fatalf("GetActiveKey: %v", err)
	}
	if active.KeyVersion != 2 {
		t.Fatalf("expected active version 2, got %d", active.KeyVersion)
	}

	// v1 is revoked
	k1, err := store.GetKey(ctx, db, "secret", "s-1", 1)
	if err != nil {
		t.Fatalf("GetKey v1: %v", err)
	}
	if k1.RevokedAt == nil {
		t.Fatal("v1 should be revoked")
	}
}

func TestGetKeyByVersion(t *testing.T) {
	db := setupPostgres(t)
	store, _ := setupTestStore(t)
	ctx := context.Background()

	_, _ = store.CreateKey(ctx, db, "s", "id")
	_, _ = store.RotateKey(ctx, db, "s", "id")

	k1, err := store.GetKey(ctx, db, "s", "id", 1)
	if err != nil {
		t.Fatalf("GetKey v1: %v", err)
	}
	if k1.KeyVersion != 1 {
		t.Fatalf("expected version 1, got %d", k1.KeyVersion)
	}

	k2, err := store.GetKey(ctx, db, "s", "id", 2)
	if err != nil {
		t.Fatalf("GetKey v2: %v", err)
	}
	if k2.KeyVersion != 2 {
		t.Fatalf("expected version 2, got %d", k2.KeyVersion)
	}
}

func TestGetActiveKey_NotFound(t *testing.T) {
	db := setupPostgres(t)
	store, _ := setupTestStore(t)
	ctx := context.Background()

	_, err := store.GetActiveKey(ctx, db, "no", "key")
	if !errors.Is(err, encryption.ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound, got %v", err)
	}
}

func TestGetKey_NotFound(t *testing.T) {
	db := setupPostgres(t)
	store, _ := setupTestStore(t)
	ctx := context.Background()

	_, err := store.GetKey(ctx, db, "no", "key", 1)
	if !errors.Is(err, encryption.ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound, got %v", err)
	}
}

func TestRevokeKeys_PreservesHighestVersion(t *testing.T) {
	db := setupPostgres(t)
	store, _ := setupTestStore(t)
	ctx := context.Background()

	_, _ = store.CreateKey(ctx, db, "s", "id")
	_, _ = store.RotateKey(ctx, db, "s", "id")
	_, _ = store.RotateKey(ctx, db, "s", "id")

	if err := store.RevokeKeys(ctx, db, "s", "id"); err != nil {
		t.Fatalf("RevokeKeys: %v", err)
	}

	// Highest version should still be active.
	active, err := store.GetActiveKey(ctx, db, "s", "id")
	if err != nil {
		t.Fatalf("GetActiveKey after revoke: %v", err)
	}
	if active.KeyVersion != 3 {
		t.Fatalf("expected active version 3, got %d", active.KeyVersion)
	}

	// Older versions should be revoked.
	for _, v := range []int{1, 2} {
		k, err := store.GetKey(ctx, db, "s", "id", v)
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
	store, _ := setupTestStore(t)
	ctx := context.Background()

	_, _ = store.CreateKey(ctx, db, "s", "only")

	if err := store.RevokeKeys(ctx, db, "s", "only"); err != nil {
		t.Fatalf("RevokeKeys: %v", err)
	}

	active, err := store.GetActiveKey(ctx, db, "s", "only")
	if err != nil {
		t.Fatalf("GetActiveKey: %v", err)
	}
	if active.KeyVersion != 1 {
		t.Fatalf("expected version 1, got %d", active.KeyVersion)
	}
}

func TestRevokeKeys_NoKeysIsNoop(t *testing.T) {
	db := setupPostgres(t)
	store, _ := setupTestStore(t)
	ctx := context.Background()

	if err := store.RevokeKeys(ctx, db, "empty", "scope"); err != nil {
		t.Fatalf("RevokeKeys on empty scope: %v", err)
	}
}

func TestDestroyKeys(t *testing.T) {
	db := setupPostgres(t)
	store, _ := setupTestStore(t)
	ctx := context.Background()

	_, _ = store.CreateKey(ctx, db, "s", "id")
	_, _ = store.RotateKey(ctx, db, "s", "id")

	if err := store.DestroyKeys(ctx, db, "s", "id"); err != nil {
		t.Fatalf("DestroyKeys: %v", err)
	}

	_, err := store.GetActiveKey(ctx, db, "s", "id")
	if !errors.Is(err, encryption.ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound after destroy, got %v", err)
	}

	_, err = store.GetKey(ctx, db, "s", "id", 1)
	if !errors.Is(err, encryption.ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound for v1 after destroy, got %v", err)
	}
}

func TestDestroyKeys_NoKeysIsNoop(t *testing.T) {
	db := setupPostgres(t)
	store, _ := setupTestStore(t)
	ctx := context.Background()

	if err := store.DestroyKeys(ctx, db, "empty", "scope"); err != nil {
		t.Fatalf("DestroyKeys on empty scope: %v", err)
	}
}

func TestScopeIsolation(t *testing.T) {
	db := setupPostgres(t)
	store, _ := setupTestStore(t)
	ctx := context.Background()

	_, _ = store.CreateKey(ctx, db, "scope-a", "id-1")
	_, _ = store.CreateKey(ctx, db, "scope-b", "id-1")

	a, _ := store.GetActiveKey(ctx, db, "scope-a", "id-1")
	b, _ := store.GetActiveKey(ctx, db, "scope-b", "id-1")

	if a.Scope != "scope-a" || b.Scope != "scope-b" {
		t.Fatalf("scopes mismatch: %s vs %s", a.Scope, b.Scope)
	}

	_ = store.DestroyKeys(ctx, db, "scope-a", "id-1")
	_, err := store.GetActiveKey(ctx, db, "scope-a", "id-1")
	if !errors.Is(err, encryption.ErrKeyNotFound) {
		t.Fatalf("scope-a should be destroyed")
	}
	bAfter, err := store.GetActiveKey(ctx, db, "scope-b", "id-1")
	if err != nil {
		t.Fatalf("scope-b should still exist: %v", err)
	}
	if bAfter.KeyVersion != 1 {
		t.Fatal("scope-b key should be untouched")
	}
}

func TestWithTx_Commit(t *testing.T) {
	db := setupPostgres(t)
	store, _ := setupTestStore(t)
	ctx := context.Background()

	tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := store.CreateKey(ctx, tx, "tx", "commit"); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	key, err := store.GetActiveKey(ctx, db, "tx", "commit")
	if err != nil {
		t.Fatalf("key should exist after commit: %v", err)
	}
	if key.KeyVersion != 1 {
		t.Fatalf("expected version 1, got %d", key.KeyVersion)
	}
}

func TestWithTx_Rollback(t *testing.T) {
	db := setupPostgres(t)
	store, _ := setupTestStore(t)
	ctx := context.Background()

	tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}

	_, _ = store.CreateKey(ctx, tx, "tx", "rollback")
	_ = tx.Rollback(ctx)

	_, err = store.GetActiveKey(ctx, db, "tx", "rollback")
	if !errors.Is(err, encryption.ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound after rollback, got %v", err)
	}
}

func TestWithTx_MultipleOperationsAtomic(t *testing.T) {
	db := setupPostgres(t)
	store, _ := setupTestStore(t)
	ctx := context.Background()

	_, _ = store.CreateKey(ctx, db, "tx", "atomic")

	tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := store.RotateKey(ctx, tx, "tx", "atomic"); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	_ = tx.Rollback(ctx)

	active, err := store.GetActiveKey(ctx, db, "tx", "atomic")
	if err != nil {
		t.Fatalf("GetActiveKey: %v", err)
	}
	if active.KeyVersion != 1 {
		t.Fatalf("expected version 1 after rollback, got %d", active.KeyVersion)
	}
}

func TestCustomSchemaAndTable(t *testing.T) {
	db := setupPostgres(t)
	ctx := context.Background()

	if _, err := db.Exec(ctx, "CREATE SCHEMA IF NOT EXISTS custom_schema"); err != nil {
		t.Fatal(err)
	}
	customSQL, err := migrations.SQL(postgres.Config{
		Schema: "custom_schema",
		Table:  "custom_keys",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, customSQL); err != nil {
		t.Fatal(err)
	}

	c := aesgcm.New()
	sysKey := makeSystemKey(1)
	keyring, err := local.NewKeyringFromMap(map[string][]byte{"kek-1": sysKey}, "kek-1")
	if err != nil {
		t.Fatal(err)
	}
	env := envelope.New(keyring, c)
	store := postgres.NewStore(env, postgres.Config{
		Schema: "custom_schema",
		Table:  "custom_keys",
	})

	if _, err := store.CreateKey(ctx, db, "s", "id"); err != nil {
		t.Fatalf("CreateKey with custom schema/table: %v", err)
	}

	key, err := store.GetActiveKey(ctx, db, "s", "id")
	if err != nil {
		t.Fatalf("GetActiveKey with custom schema/table: %v", err)
	}
	if key.KeyVersion != 1 {
		t.Fatalf("expected version 1, got %d", key.KeyVersion)
	}
}

func TestCreateKey_AlreadyExists(t *testing.T) {
	db := setupPostgres(t)
	store, _ := setupTestStore(t)
	ctx := context.Background()

	_, err := store.CreateKey(ctx, db, "s", "id")
	if err != nil {
		t.Fatalf("first CreateKey: %v", err)
	}

	_, err = store.CreateKey(ctx, db, "s", "id")
	if !errors.Is(err, encryption.ErrKeyExists) {
		t.Fatalf("expected ErrKeyExists on duplicate CreateKey, got %v", err)
	}
}

func TestConcurrentCreateDifferentScopes(t *testing.T) {
	db := setupPostgres(t)
	store, _ := setupTestStore(t)
	ctx := context.Background()

	const n = 20
	var wg sync.WaitGroup
	errs := make([]error, n)

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			scopeID := fmt.Sprintf("concurrent-%d", i)
			_, errs[i] = store.CreateKey(ctx, db, "conc", scopeID)
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: %v", i, err)
		}
	}

	for i := 0; i < n; i++ {
		scopeID := fmt.Sprintf("concurrent-%d", i)
		if _, err := store.GetActiveKey(ctx, db, "conc", scopeID); err != nil {
			t.Fatalf("missing key for %s: %v", scopeID, err)
		}
	}
}

func TestMigrationIdempotent(t *testing.T) {
	db := setupPostgres(t)
	ctx := context.Background()

	migration, _ := migrations.FS.ReadFile("001_encryption_keys.sql")

	if _, err := db.Exec(ctx, string(migration)); err != nil {
		t.Fatalf("re-applying migration should be idempotent: %v", err)
	}
}

func TestRewrapKeys_RewrapsMatchingRows(t *testing.T) {
	db := setupPostgres(t)
	store, _ := setupTestStore(t)
	ctx := context.Background()
	c := aesgcm.New()

	oldKey := makeSystemKey(10)
	newKey := makeSystemKey(100)
	keyring, err := local.NewKeyringFromMap(map[string][]byte{
		"old": oldKey,
		"new": newKey,
	}, "new")
	if err != nil {
		t.Fatal(err)
	}
	env := envelope.New(keyring, c)

	oldActiveDEK := []byte("0123456789abcdef0123456789abcdef")
	oldRevokedDEK := []byte("abcdef0123456789abcdef0123456789")
	piiDEK := []byte("fedcba9876543210fedcba9876543210")
	alreadyNewDEK := []byte("00112233445566778899aabbccddeeff")

	mustStoreRawEncryptedKey(t, ctx, db, c, oldKey, "old", "secret", "stripe", 1, oldRevokedDEK)
	if _, err := db.Exec(ctx, "UPDATE infrastructure.encryption_keys SET revoked_at = NOW() WHERE scope = 'secret' AND scope_id = 'stripe' AND key_version = 1"); err != nil {
		t.Fatal(err)
	}
	mustStoreRawEncryptedKey(t, ctx, db, c, oldKey, "old", "secret", "stripe", 2, oldActiveDEK)
	mustStoreRawEncryptedKey(t, ctx, db, c, oldKey, "old", "pii", "user-1", 1, piiDEK)
	mustStoreRawEncryptedKey(t, ctx, db, c, newKey, "new", "secret", "already-new", 1, alreadyNewDEK)

	unchangedBefore, err := store.GetKey(ctx, db, "secret", "already-new", 1)
	if err != nil {
		t.Fatalf("GetKey already-new before rewrap: %v", err)
	}

	result, err := postgres.RewrapKeys(ctx, db, postgres.Config{}, env, postgres.RewrapKeysOptions{
		FromKEKID: "old",
		ToKEKID:   "new",
		BatchSize: 1,
	})
	if err != nil {
		t.Fatalf("RewrapKeys: %v", err)
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

	oldRevoked, err := store.GetKey(ctx, db, "secret", "stripe", 1)
	if err != nil {
		t.Fatalf("GetKey secret/stripe v1: %v", err)
	}
	if oldRevoked.KEKID != "new" {
		t.Fatalf("KEK ID v1 = %q, want %q", oldRevoked.KEKID, "new")
	}
	if oldRevoked.RevokedAt == nil {
		t.Fatal("revoked key should remain revoked")
	}
	if got := mustDecryptDEK(t, c, newKey, oldRevoked); !bytes.Equal(got, oldRevokedDEK) {
		t.Fatalf("v1 DEK mismatch: got %x want %x", got, oldRevokedDEK)
	}

	oldActive, err := store.GetKey(ctx, db, "secret", "stripe", 2)
	if err != nil {
		t.Fatalf("GetKey secret/stripe v2: %v", err)
	}
	if oldActive.KEKID != "new" {
		t.Fatalf("KEK ID v2 = %q, want %q", oldActive.KEKID, "new")
	}
	if got := mustDecryptDEK(t, c, newKey, oldActive); !bytes.Equal(got, oldActiveDEK) {
		t.Fatalf("v2 DEK mismatch: got %x want %x", got, oldActiveDEK)
	}

	piiKey, err := store.GetKey(ctx, db, "pii", "user-1", 1)
	if err != nil {
		t.Fatalf("GetKey pii/user-1 v1: %v", err)
	}
	if piiKey.KEKID != "new" {
		t.Fatalf("pii KEK ID = %q, want %q", piiKey.KEKID, "new")
	}
	if got := mustDecryptDEK(t, c, newKey, piiKey); !bytes.Equal(got, piiDEK) {
		t.Fatalf("pii DEK mismatch: got %x want %x", got, piiDEK)
	}

	unchangedAfter, err := store.GetKey(ctx, db, "secret", "already-new", 1)
	if err != nil {
		t.Fatalf("GetKey already-new after rewrap: %v", err)
	}
	if unchangedAfter.KEKID != "new" {
		t.Fatalf("already-new KEK ID = %q, want %q", unchangedAfter.KEKID, "new")
	}
	if !bytes.Equal(unchangedAfter.EncryptedDEK, unchangedBefore.EncryptedDEK) {
		t.Fatal("already-new row should not be rewritten")
	}
}

func TestRewrapKeys_DryRun(t *testing.T) {
	db := setupPostgres(t)
	store, _ := setupTestStore(t)
	ctx := context.Background()
	c := aesgcm.New()

	oldKey := makeSystemKey(20)
	newKey := makeSystemKey(120)
	keyring, err := local.NewKeyringFromMap(map[string][]byte{
		"old": oldKey,
		"new": newKey,
	}, "new")
	if err != nil {
		t.Fatal(err)
	}
	env := envelope.New(keyring, c)

	dek := []byte("11223344556677889900aabbccddeeff")
	mustStoreRawEncryptedKey(t, ctx, db, c, oldKey, "old", "secret", "dry-run", 1, dek)

	before, err := store.GetKey(ctx, db, "secret", "dry-run", 1)
	if err != nil {
		t.Fatalf("GetKey before dry-run: %v", err)
	}

	result, err := postgres.RewrapKeys(ctx, db, postgres.Config{}, env, postgres.RewrapKeysOptions{
		FromKEKID: "old",
		ToKEKID:   "new",
		DryRun:    true,
	})
	if err != nil {
		t.Fatalf("RewrapKeys dry-run: %v", err)
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

	after, err := store.GetKey(ctx, db, "secret", "dry-run", 1)
	if err != nil {
		t.Fatalf("GetKey after dry-run: %v", err)
	}
	if after.KEKID != "old" {
		t.Fatalf("KEK ID after dry-run = %q, want %q", after.KEKID, "old")
	}
	if !bytes.Equal(after.EncryptedDEK, before.EncryptedDEK) {
		t.Fatal("dry-run should not modify ciphertext")
	}
}

func TestRewrapKeys_Idempotent(t *testing.T) {
	db := setupPostgres(t)
	ctx := context.Background()
	c := aesgcm.New()

	oldKey := makeSystemKey(30)
	newKey := makeSystemKey(130)
	keyring, err := local.NewKeyringFromMap(map[string][]byte{
		"old": oldKey,
		"new": newKey,
	}, "new")
	if err != nil {
		t.Fatal(err)
	}
	env := envelope.New(keyring, c)

	dek := []byte("ffeeddccbbaa00998877665544332211")
	mustStoreRawEncryptedKey(t, ctx, db, c, oldKey, "old", "secret", "idempotent", 1, dek)

	first, err := postgres.RewrapKeys(ctx, db, postgres.Config{}, env, postgres.RewrapKeysOptions{
		FromKEKID: "old",
		ToKEKID:   "new",
	})
	if err != nil {
		t.Fatalf("first RewrapKeys: %v", err)
	}
	if first.RewrappedRows != 1 {
		t.Fatalf("first RewrappedRows = %d, want 1", first.RewrappedRows)
	}
	if first.RemainingRows != 0 {
		t.Fatalf("first RemainingRows = %d, want 0", first.RemainingRows)
	}

	second, err := postgres.RewrapKeys(ctx, db, postgres.Config{}, env, postgres.RewrapKeysOptions{
		FromKEKID: "old",
		ToKEKID:   "new",
	})
	if err != nil {
		t.Fatalf("second RewrapKeys: %v", err)
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

func TestRewrapKeys_ConcurrentRuns(t *testing.T) {
	db := setupPostgres(t)
	store, _ := setupTestStore(t)
	ctx := context.Background()
	c := aesgcm.New()

	oldKey := makeSystemKey(40)
	newKey := makeSystemKey(140)
	keyring, err := local.NewKeyringFromMap(map[string][]byte{
		"old": oldKey,
		"new": newKey,
	}, "new")
	if err != nil {
		t.Fatal(err)
	}
	env := envelope.New(keyring, c)

	for i := 0; i < 10; i++ {
		scopeID := fmt.Sprintf("concurrent-%d", i)
		dek := []byte(fmt.Sprintf("%032d", i))
		mustStoreRawEncryptedKey(t, ctx, db, c, oldKey, "old", "secret", scopeID, 1, dek)
	}

	results := make([]postgres.RewrapKeysResult, 2)
	errs := make([]error, 2)
	var wg sync.WaitGroup

	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = postgres.RewrapKeys(ctx, db, postgres.Config{}, env, postgres.RewrapKeysOptions{
				FromKEKID: "old",
				ToKEKID:   "new",
				BatchSize: 1,
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
		key, err := store.GetKey(ctx, db, "secret", scopeID, 1)
		if err != nil {
			t.Fatalf("GetKey %s: %v", scopeID, err)
		}
		if key.KEKID != "new" {
			t.Fatalf("%s KEK ID = %q, want %q", scopeID, key.KEKID, "new")
		}
	}
}

func TestRewrapKeys_HistoricalCiphertextsRemainDecryptable(t *testing.T) {
	db := setupPostgres(t)
	store, _ := setupTestStore(t)
	ctx := context.Background()
	c := aesgcm.New()

	oldKey := makeSystemKey(50)
	newKey := makeSystemKey(150)
	oldOnly, err := local.NewKeyringFromMap(map[string][]byte{"old": oldKey}, "old")
	if err != nil {
		t.Fatal(err)
	}
	bothKeys, err := local.NewKeyringFromMap(map[string][]byte{"old": oldKey, "new": newKey}, "new")
	if err != nil {
		t.Fatal(err)
	}
	newOnly, err := local.NewKeyringFromMap(map[string][]byte{"new": newKey}, "new")
	if err != nil {
		t.Fatal(err)
	}

	mustStoreRawEncryptedKey(t, ctx, db, c, oldKey, "old", "secret", "history", 1, []byte("11111111111111111111111111111111"))
	oldEnv := envelope.New(oldOnly, c)

	keyV1Before, err := store.GetActiveKey(ctx, db, "secret", "history")
	if err != nil {
		t.Fatalf("GetActiveKey v1: %v", err)
	}
	ciphertextV1, err := oldEnv.EncryptString(ctx, keyV1Before, "alpha", nil)
	if err != nil {
		t.Fatalf("EncryptString v1: %v", err)
	}

	if _, err := db.Exec(ctx, "UPDATE infrastructure.encryption_keys SET revoked_at = NOW() WHERE scope = 'secret' AND scope_id = 'history' AND key_version = 1"); err != nil {
		t.Fatal(err)
	}
	mustStoreRawEncryptedKey(t, ctx, db, c, oldKey, "old", "secret", "history", 2, []byte("22222222222222222222222222222222"))

	keyV2Before, err := store.GetActiveKey(ctx, db, "secret", "history")
	if err != nil {
		t.Fatalf("GetActiveKey v2: %v", err)
	}
	ciphertextV2, err := oldEnv.EncryptString(ctx, keyV2Before, "beta", nil)
	if err != nil {
		t.Fatalf("EncryptString v2: %v", err)
	}

	bothEnv := envelope.New(bothKeys, c)
	result, err := postgres.RewrapKeys(ctx, db, postgres.Config{}, bothEnv, postgres.RewrapKeysOptions{
		FromKEKID: "old",
		ToKEKID:   "new",
	})
	if err != nil {
		t.Fatalf("RewrapKeys: %v", err)
	}
	if result.RewrappedRows != 2 {
		t.Fatalf("RewrappedRows = %d, want 2", result.RewrappedRows)
	}

	newEnv := envelope.New(newOnly, c)

	keyV1After, err := store.GetKey(ctx, db, "secret", "history", 1)
	if err != nil {
		t.Fatalf("GetKey v1 after rewrap: %v", err)
	}
	plaintextV1, err := newEnv.DecryptString(ctx, keyV1After, ciphertextV1, nil)
	if err != nil {
		t.Fatalf("DecryptString v1 with new key only: %v", err)
	}
	if plaintextV1 != "alpha" {
		t.Fatalf("plaintextV1 = %q, want %q", plaintextV1, "alpha")
	}

	keyV2After, err := store.GetKey(ctx, db, "secret", "history", 2)
	if err != nil {
		t.Fatalf("GetKey v2 after rewrap: %v", err)
	}
	plaintextV2, err := newEnv.DecryptString(ctx, keyV2After, ciphertextV2, nil)
	if err != nil {
		t.Fatalf("DecryptString v2 with new key only: %v", err)
	}
	if plaintextV2 != "beta" {
		t.Fatalf("plaintextV2 = %q, want %q", plaintextV2, "beta")
	}
}

// ---------------------------------------------------------------------------
// Additional Matrix Coverage: Edge Cases, Security Invariants & Races
// ---------------------------------------------------------------------------

func TestRotateKey_OnEmptyScopeReturnsErrKeyNotFound(t *testing.T) {
	db := setupPostgres(t)
	store, _ := setupTestStore(t)
	ctx := context.Background()

	_, err := store.RotateKey(ctx, db, "secret", "non-existent")
	if !errors.Is(err, encryption.ErrKeyNotFound) {
		t.Fatalf("RotateKey on empty scope: err = %v, want ErrKeyNotFound", err)
	}
}

func TestRecreateKeyAfterDestroy_IsolatesOldCiphertext(t *testing.T) {
	db := setupPostgres(t)
	store, env := setupTestStore(t)
	ctx := context.Background()

	oldV1, err := store.CreateKey(ctx, db, "user", "u-shred")
	if err != nil {
		t.Fatalf("CreateKey first: %v", err)
	}
	oldCiphertext, err := env.EncryptString(ctx, oldV1, "sensitive-pii", nil)
	if err != nil {
		t.Fatalf("EncryptString old: %v", err)
	}

	if err := store.DestroyKeys(ctx, db, "user", "u-shred"); err != nil {
		t.Fatalf("DestroyKeys: %v", err)
	}

	newV1, err := store.CreateKey(ctx, db, "user", "u-shred")
	if err != nil {
		t.Fatalf("CreateKey after destroy: %v", err)
	}
	if newV1.KeyVersion != 1 {
		t.Fatalf("KeyVersion = %d, want 1", newV1.KeyVersion)
	}

	// Old ciphertext encrypted under destroyed DEK must fail to decrypt with new v1 DEK
	if _, err := env.DecryptString(ctx, newV1, oldCiphertext, nil); !errors.Is(err, encryption.ErrDecryption) {
		t.Fatalf("DecryptString old ciphertext with new DEK: err = %v, want ErrDecryption", err)
	}
}

type countingWrapper struct {
	kek.Wrapper
	unwrapCalls atomic.Int32
}

func (c *countingWrapper) Unwrap(ctx context.Context, encryptedDEK, aad []byte) ([]byte, error) {
	c.unwrapCalls.Add(1)
	return c.Wrapper.Unwrap(ctx, encryptedDEK, aad)
}

func TestFullStack_SessionAndCachingKeyringWithRewrap(t *testing.T) {
	db := setupPostgres(t)
	ctx := context.Background()
	c := aesgcm.New()

	w1Base, err := local.NewWrapper("kek-1", makeSystemKey(61))
	if err != nil {
		t.Fatal(err)
	}
	w2Base, err := local.NewWrapper("kek-2", makeSystemKey(62))
	if err != nil {
		t.Fatal(err)
	}
	w1 := &countingWrapper{Wrapper: w1Base}
	w2 := &countingWrapper{Wrapper: w2Base}

	baseKR, err := kek.NewKeyring("kek-1", w1, w2)
	if err != nil {
		t.Fatal(err)
	}
	cachedKR, err := kek.NewCachingKeyring(baseKR, kek.CacheConfig{TTL: time.Minute, MaxEntries: 64})
	if err != nil {
		t.Fatal(err)
	}
	defer cachedKR.Close()

	env := envelope.New(cachedKR, c)
	store := postgres.NewStore(env, postgres.Config{})

	key, err := store.CreateKey(ctx, db, "user", "u-session")
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	// CreateKey populates CachingKeyring on Wrap (write-through), so immediate OpenSession hits cache (0 Unwrap calls)
	sessWarm, err := env.OpenSession(ctx, key)
	if err != nil {
		t.Fatalf("OpenSession warm: %v", err)
	}
	sessWarm.Close()
	if got := w1.unwrapCalls.Load(); got != 0 {
		t.Fatalf("w1.unwrapCalls on warm write-through cache = %d, want 0", got)
	}

	// Invalidate cache, then open 3 sessions; CachingKeyring must unwrap from w1 only once
	cachedKR.Invalidate()
	var ciphertexts [][]byte
	for i := 0; i < 3; i++ {
		sess, err := env.OpenSession(ctx, key)
		if err != nil {
			t.Fatalf("OpenSession %d: %v", i, err)
		}
		ct, err := sess.Encrypt([]byte(fmt.Sprintf("event-%d", i)), []byte("event-aad"))
		sess.Close()
		if err != nil {
			t.Fatalf("sess.Encrypt %d: %v", i, err)
		}
		ciphertexts = append(ciphertexts, ct)
	}
	if got := w1.unwrapCalls.Load(); got != 1 {
		t.Fatalf("w1.unwrapCalls = %d, want 1 (cached across 3 sessions)", got)
	}

	// Rewrap from kek-1 to kek-2 and invalidate cache
	res, err := postgres.RewrapKeys(ctx, db, postgres.Config{}, env, postgres.RewrapKeysOptions{
		FromKEKID: "kek-1",
		ToKEKID:   "kek-2",
	})
	if err != nil {
		t.Fatalf("RewrapKeys: %v", err)
	}
	if res.RewrappedRows != 1 {
		t.Fatalf("RewrappedRows = %d, want 1", res.RewrappedRows)
	}
	cachedKR.Invalidate()

	rewrappedKey, err := store.GetActiveKey(ctx, db, "user", "u-session")
	if err != nil {
		t.Fatalf("GetActiveKey: %v", err)
	}
	if rewrappedKey.KEKID != "kek-2" {
		t.Fatalf("KEKID = %q, want kek-2", rewrappedKey.KEKID)
	}

	sess, err := env.OpenSession(ctx, rewrappedKey)
	if err != nil {
		t.Fatalf("OpenSession after rewrap: %v", err)
	}
	defer sess.Close()

	for i, ct := range ciphertexts {
		pt, err := sess.Decrypt(ct, []byte("event-aad"))
		if err != nil {
			t.Fatalf("sess.Decrypt %d: %v", i, err)
		}
		if want := fmt.Sprintf("event-%d", i); string(pt) != want {
			t.Fatalf("pt %d = %q, want %q", i, string(pt), want)
		}
	}
	if got := w2.unwrapCalls.Load(); got != 1 {
		t.Fatalf("w2.unwrapCalls = %d, want 1", got)
	}
}

func TestConfusedDeputy_CiphertextTransplantRejected(t *testing.T) {
	db := setupPostgres(t)
	store, env := setupTestStore(t)
	ctx := context.Background()

	aliceKey, err := store.CreateKey(ctx, db, "user", "alice")
	if err != nil {
		t.Fatalf("CreateKey alice: %v", err)
	}
	if _, err := store.CreateKey(ctx, db, "user", "bob"); err != nil {
		t.Fatalf("CreateKey bob: %v", err)
	}

	// Transplant Alice's encrypted_dek directly into Bob's database row
	_, err = db.Exec(ctx,
		"UPDATE infrastructure.encryption_keys SET encrypted_dek = $1 WHERE scope = 'user' AND scope_id = 'bob' AND key_version = 1",
		aliceKey.EncryptedDEK,
	)
	if err != nil {
		t.Fatalf("transplant update: %v", err)
	}

	tamperedBobKey, err := store.GetActiveKey(ctx, db, "user", "bob")
	if err != nil {
		t.Fatalf("GetActiveKey bob: %v", err)
	}

	// Opening a session or encrypting/decrypting for Bob must fail AAD verification
	if _, err := env.OpenSession(ctx, tamperedBobKey); !errors.Is(err, encryption.ErrDecryption) {
		t.Fatalf("OpenSession on transplanted DEK: err = %v, want ErrDecryption", err)
	}
}

func TestRewrapKeys_TamperedRowFailsAndRollsBackBatch(t *testing.T) {
	db := setupPostgres(t)
	store, _ := setupTestStore(t)
	ctx := context.Background()
	c := aesgcm.New()

	oldKey := makeSystemKey(70)
	newKey := makeSystemKey(170)
	keyring, err := local.NewKeyringFromMap(map[string][]byte{
		"old": oldKey,
		"new": newKey,
	}, "new")
	if err != nil {
		t.Fatal(err)
	}
	env := envelope.New(keyring, c)

	mustStoreRawEncryptedKey(t, ctx, db, c, oldKey, "old", "user", "u-valid", 1, makeSystemKey(71))
	mustStoreRawEncryptedKey(t, ctx, db, c, oldKey, "old", "user", "u-tampered", 1, makeSystemKey(72))

	// Corrupt u-tampered's encrypted_dek by transplanting u-valid's ciphertext into u-tampered
	validRow, err := store.GetKey(ctx, db, "user", "u-valid", 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx,
		"UPDATE infrastructure.encryption_keys SET encrypted_dek = $1 WHERE scope = 'user' AND scope_id = 'u-tampered' AND key_version = 1",
		validRow.EncryptedDEK,
	); err != nil {
		t.Fatal(err)
	}

	// RewrapKeys with BatchSize=10 must fail on u-tampered and roll back the entire batch
	_, err = postgres.RewrapKeys(ctx, db, postgres.Config{}, env, postgres.RewrapKeysOptions{
		FromKEKID: "old",
		ToKEKID:   "new",
		BatchSize: 10,
	})
	if !errors.Is(err, encryption.ErrDecryption) {
		t.Fatalf("RewrapKeys on tampered row: err = %v, want ErrDecryption", err)
	}

	// Verify u-valid was rolled back and still references "old"
	afterRollback, err := store.GetKey(ctx, db, "user", "u-valid", 1)
	if err != nil {
		t.Fatal(err)
	}
	if afterRollback.KEKID != "old" {
		t.Fatalf("u-valid KEKID after batch rollback = %q, want \"old\"", afterRollback.KEKID)
	}
}

func TestRewrapKeys_UnknownKEKReturnsErrKeyNotFound(t *testing.T) {
	db := setupPostgres(t)
	store, env := setupTestStore(t)
	ctx := context.Background()

	created, err := store.CreateKey(ctx, db, "user", "u-unknown-kek")
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	// Unknown target KEK fails when rewrapping the matching row
	_, err = postgres.RewrapKeys(ctx, db, postgres.Config{}, env, postgres.RewrapKeysOptions{
		FromKEKID: "kek-1",
		ToKEKID:   "non-existent-kek",
	})
	if !errors.Is(err, encryption.ErrKeyNotFound) {
		t.Fatalf("unknown target KEK: err = %v, want ErrKeyNotFound", err)
	}

	// Row with an unknown source KEK in DB fails with ErrKeyNotFound when rewrapped
	if _, err := db.Exec(ctx,
		"INSERT INTO infrastructure.encryption_keys (scope, scope_id, key_version, encrypted_dek, kek_id) VALUES ('user', 'u-missing-src', 1, $1, 'missing-src-kek')",
		created.EncryptedDEK,
	); err != nil {
		t.Fatal(err)
	}
	_, err = postgres.RewrapKeys(ctx, db, postgres.Config{}, env, postgres.RewrapKeysOptions{
		FromKEKID: "missing-src-kek",
		ToKEKID:   "kek-1",
	})
	if !errors.Is(err, encryption.ErrKeyNotFound) {
		t.Fatalf("unknown source KEK: err = %v, want ErrKeyNotFound", err)
	}
}

func TestSQLSchemaConstraints_EnforcedByPostgres(t *testing.T) {
	db := setupPostgres(t)
	store, _ := setupTestStore(t)
	ctx := context.Background()

	created, err := store.CreateKey(ctx, db, "constraint", "c-1")
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	// 1. Partial unique index idx_encryption_keys_active rejects a second unrevoked version
	_, err = db.Exec(ctx,
		"INSERT INTO infrastructure.encryption_keys (scope, scope_id, key_version, encrypted_dek, kek_id, revoked_at) VALUES ($1, $2, 2, $3, 'kek-1', NULL)",
		"constraint", "c-1", created.EncryptedDEK,
	)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23505" {
		t.Fatalf("second active key: err = %v, want PostgreSQL unique violation 23505", err)
	}

	// 2. CHECK (key_version >= 1) rejects key_version = 0
	_, err = db.Exec(ctx,
		"INSERT INTO infrastructure.encryption_keys (scope, scope_id, key_version, encrypted_dek, kek_id) VALUES ('constraint', 'c-zero', 0, $1, 'kek-1')",
		created.EncryptedDEK,
	)
	if !errors.As(err, &pgErr) || pgErr.Code != "23514" {
		t.Fatalf("key_version 0: err = %v, want PostgreSQL check violation 23514", err)
	}

	// 3. CHECK (revoked_at IS NULL OR revoked_at >= created_at) rejects revoked_at < created_at
	_, err = db.Exec(ctx,
		"UPDATE infrastructure.encryption_keys SET revoked_at = created_at - INTERVAL '1 hour' WHERE scope = 'constraint' AND scope_id = 'c-1'",
	)
	if !errors.As(err, &pgErr) || pgErr.Code != "23514" {
		t.Fatalf("revoked_at < created_at: err = %v, want PostgreSQL check violation 23514", err)
	}
}

func TestConcurrentCreateSameScope_ExactlyOneWins(t *testing.T) {
	db := setupPostgres(t)
	store, _ := setupTestStore(t)
	ctx := context.Background()

	const n = 10
	var wg sync.WaitGroup
	var wins atomic.Int32
	var existsErrs atomic.Int32

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			key, err := store.CreateKey(ctx, db, "race", "same-scope")
			if err == nil && key.KeyVersion == 1 {
				wins.Add(1)
				return
			}
			if errors.Is(err, encryption.ErrKeyExists) {
				existsErrs.Add(1)
			}
		}()
	}
	wg.Wait()

	if wins.Load() != 1 {
		t.Fatalf("wins = %d, want 1", wins.Load())
	}
	if existsErrs.Load() != n-1 {
		t.Fatalf("existsErrs = %d, want %d", existsErrs.Load(), n-1)
	}
}

func TestConcurrentRotateSameScope_SingleActiveInvariant(t *testing.T) {
	db := setupPostgres(t)
	store, _ := setupTestStore(t)
	ctx := context.Background()

	if _, err := store.CreateKey(ctx, db, "race", "rotate-same"); err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	const n = 10
	var wg sync.WaitGroup
	var wins atomic.Int32
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := store.RotateKey(ctx, db, "race", "rotate-same"); err == nil {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()

	if wins.Load() < 1 {
		t.Fatal("expected at least 1 rotation to succeed")
	}

	// Verify exactly 1 active key exists for (race, rotate-same)
	var activeCount int
	err := db.QueryRow(ctx,
		"SELECT COUNT(*) FROM infrastructure.encryption_keys WHERE scope = 'race' AND scope_id = 'rotate-same' AND revoked_at IS NULL",
	).Scan(&activeCount)
	if err != nil {
		t.Fatal(err)
	}
	if activeCount != 1 {
		t.Fatalf("activeCount = %d, want 1", activeCount)
	}
}
