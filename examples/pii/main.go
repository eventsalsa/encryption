// Example: GDPR PII encryption and crypto-shredding lifecycle with PostgreSQL.
//
// In event-sourced architectures, events are immutable and cannot be deleted.
// Crypto-shredding solves GDPR's "Right to Erasure" (Article 17) by:
//  1. Generating 1 dedicated DEK (version 1) per user: (scope="user_pii", scopeID=userID).
//  2. Encrypting all user PII payloads in the event stream with this single pinned DEK.
//  3. When an erasure request arrives, calling store.DestroyKeys(ctx, conn, "user_pii", userID)
//     to hard-delete the DEK from PostgreSQL.
//  4. Without the DEK, historical events remain in the event store but are mathematically
//     undecryptable noise, fulfilling GDPR erasure without violating event immutability.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/eventsalsa/encryption"
	"github.com/eventsalsa/encryption/cipher/aesgcm"
	"github.com/eventsalsa/encryption/envelope"
	"github.com/eventsalsa/encryption/postgres"
	"github.com/eventsalsa/encryption/postgres/migrations"
	"github.com/eventsalsa/encryption/testutil"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	ctx := context.Background()

	// 1. Connect to PostgreSQL (uses DATABASE_URL or starts an ephemeral container)
	pool, cleanup, err := connectPostgres(ctx)
	if err != nil {
		return fmt.Errorf("connect to database: %w", err)
	}
	defer cleanup()

	// 2. Initialize Keyring, Cipher, Envelope engine, and Postgres Keystore
	keyring := testutil.NewTestKeyring()
	c := aesgcm.New()
	env := envelope.New(keyring, c)
	store := postgres.NewStore(env, postgres.Config{})

	userID := "user-99"
	scope := "user_pii"

	// 3. User Registration: Create 1 DEK (version 1) inside the SQL transaction
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	v, err := store.CreateKey(ctx, tx, scope, userID)
	if err != nil {
		return fmt.Errorf("create key: %w", err)
	}
	fmt.Printf("1. Created PII key version %d for user %s inside transaction\n", v, userID)

	key, err := store.GetActiveKey(ctx, tx, scope, userID)
	if err != nil {
		return fmt.Errorf("get active key: %w", err)
	}

	// 4. Encrypt user PII in-memory (zero DB overhead)
	ciphertext, err := env.Encrypt(key.SystemKeyID, key.EncryptedDEK, "alice.smith@example.com")
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}
	fmt.Printf("2. Encrypted PII payload: %s\n", ciphertext)

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	// 5. Read / Decrypt event payload
	readKey, err := store.GetActiveKey(ctx, pool, scope, userID)
	if err != nil {
		return fmt.Errorf("get active key: %w", err)
	}
	decrypted, err := env.Decrypt(readKey.SystemKeyID, readKey.EncryptedDEK, ciphertext)
	if err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}
	fmt.Printf("3. Decrypted PII payload: %s\n", decrypted)

	// 6. GDPR Article 17 Erasure Request: Crypto-Shred the DEK
	if err := store.DestroyKeys(ctx, pool, scope, userID); err != nil {
		return fmt.Errorf("destroy keys: %w", err)
	}
	fmt.Printf("4. Hard-deleted encryption keys for %s:%s\n", scope, userID)

	// 7. Verify key is gone — historical events are now permanently undecryptable
	_, err = store.GetActiveKey(ctx, pool, scope, userID)
	if errors.Is(err, encryption.ErrKeyNotFound) {
		fmt.Println("5. Key retrieval status: ErrKeyNotFound (as expected)")
		fmt.Println("\n✓ PII is permanently undecryptable. GDPR Right to Erasure satisfied.")
	}
	return nil
}

func connectPostgres(ctx context.Context) (*pgxpool.Pool, func(), error) {
	connStr := os.Getenv("DATABASE_URL")
	cleanup := func() {}

	if connStr == "" {
		ctr, err := tcpostgres.Run(ctx, "postgres:16-alpine",
			tcpostgres.WithDatabase("encryption_example"),
			tcpostgres.WithUsername("test"),
			tcpostgres.WithPassword("test"),
			testcontainers.WithWaitStrategy(
				wait.ForLog("database system is ready to accept connections").
					WithOccurrence(2).
					WithStartupTimeout(30*time.Second),
			),
		)
		if err != nil {
			return nil, nil, fmt.Errorf("start postgres container: %w", err)
		}
		cleanup = func() { _ = ctr.Terminate(ctx) }

		connStr, err = ctr.ConnectionString(ctx, "sslmode=disable")
		if err != nil {
			cleanup()
			return nil, nil, fmt.Errorf("container connection string: %w", err)
		}
	}

	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("open db pool: %w", err)
	}

	migrationSQL, err := migrations.SQL(postgres.Config{})
	if err != nil {
		pool.Close()
		cleanup()
		return nil, nil, fmt.Errorf("render migration: %w", err)
	}
	if _, err := pool.Exec(ctx, "CREATE SCHEMA IF NOT EXISTS infrastructure"); err != nil {
		pool.Close()
		cleanup()
		return nil, nil, fmt.Errorf("create schema: %w", err)
	}
	if _, err := pool.Exec(ctx, migrationSQL); err != nil {
		pool.Close()
		cleanup()
		return nil, nil, fmt.Errorf("apply migration: %w", err)
	}

	combinedCleanup := func() {
		pool.Close()
		cleanup()
	}
	return pool, combinedCleanup, nil
}
