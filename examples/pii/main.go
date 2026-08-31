// Example: GDPR PII encryption and crypto-shredding lifecycle.
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
	"log"
	"os"

	"github.com/eventsalsa/encryption"
	"github.com/eventsalsa/encryption/cipher/aesgcm"
	"github.com/eventsalsa/encryption/envelope"
	"github.com/eventsalsa/encryption/postgres"
	"github.com/eventsalsa/encryption/postgres/migrations"
	"github.com/eventsalsa/encryption/testutil"
	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("error: %v", err)
	}
}

func run() error {
	ctx := context.Background()
	dbURL := os.Getenv("DATABASE_URL")

	keyring := testutil.NewTestKeyring()
	c := aesgcm.New()
	env := envelope.New(keyring, c)
	store := postgres.NewStore(env, postgres.Config{})

	userID := "user-4815162342"
	scope := "user_pii"

	if dbURL != "" {
		pool, err := pgxpool.New(ctx, dbURL)
		if err != nil {
			return fmt.Errorf("connect to postgres: %w", err)
		}
		defer pool.Close()

		// Apply keystore migration
		migrationSQL, err := migrations.SQL(postgres.Config{})
		if err != nil {
			return fmt.Errorf("generate migration: %w", err)
		}
		if _, err := pool.Exec(ctx, "CREATE SCHEMA IF NOT EXISTS infrastructure"); err != nil {
			return fmt.Errorf("create schema: %w", err)
		}
		if _, err := pool.Exec(ctx, migrationSQL); err != nil {
			return fmt.Errorf("apply migration: %w", err)
		}

		fmt.Printf("=== 1. User Registration (Creating PII DEK inside Transaction) ===\n")
		tx, err := pool.Begin(ctx)
		if err != nil {
			return fmt.Errorf("begin tx: %w", err)
		}
		defer func() {
			_ = tx.Rollback(ctx)
		}()

		// Create user DEK at version 1
		v, err := store.CreateKey(ctx, tx, scope, userID)
		if err != nil {
			return fmt.Errorf("create key: %w", err)
		}
		fmt.Printf("Created PII key version %d for user %s\n", v, userID)

		// Fetch active key inside transaction
		key, err := store.GetActiveKey(ctx, tx, scope, userID)
		if err != nil {
			return fmt.Errorf("get active key: %w", err)
		}

		// Encrypt PII payload in-memory (zero DB overhead)
		emailPayload := "alice.smith@example.com"
		ciphertext, err := env.Encrypt(key.SystemKeyID, key.EncryptedDEK, emailPayload)
		if err != nil {
			return fmt.Errorf("encrypt: %w", err)
		}
		fmt.Printf("Encrypted email: %s\n", ciphertext)

		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit tx: %w", err)
		}

		fmt.Printf("\n=== 2. Event Sourced Read Path (Decryption) ===\n")
		readKey, err := store.GetActiveKey(ctx, pool, scope, userID)
		if err != nil {
			return fmt.Errorf("get active key: %w", err)
		}
		decrypted, err := env.Decrypt(readKey.SystemKeyID, readKey.EncryptedDEK, ciphertext)
		if err != nil {
			return fmt.Errorf("decrypt: %w", err)
		}
		fmt.Printf("Decrypted email: %s\n", decrypted)

		fmt.Printf("\n=== 3. GDPR Article 17 Erasure Request (Crypto-Shredding) ===\n")
		// Permanently delete user DEK from PostgreSQL
		if err := store.DestroyKeys(ctx, pool, scope, userID); err != nil {
			return fmt.Errorf("destroy keys: %w", err)
		}
		fmt.Printf("Hard-deleted encryption key for %s:%s\n", scope, userID)

		// Attempting to read key now returns ErrKeyNotFound
		_, err = store.GetActiveKey(ctx, pool, scope, userID)
		if errors.Is(err, encryption.ErrKeyNotFound) {
			fmt.Printf("Key retrieval status: %v (as expected)\n", err)
		} else {
			return fmt.Errorf("expected ErrKeyNotFound, got %v", err)
		}

		fmt.Println("\n✓ User PII in the immutable event log is permanently and mathematically shredded.")
	} else {
		fmt.Println("=== GDPR PII Crypto-Shredding Workflow ===")
		fmt.Println("Note: Set DATABASE_URL to run against live PostgreSQL.")
		fmt.Println()
		fmt.Println("1. PII Key Strategy: 1 DEK pinned per subject (version 1).")
		fmt.Println("   - DEKs are created once during user registration: store.CreateKey(ctx, tx, \"user_pii\", userID)")
		fmt.Println("   - System KEK rotation uses postgres.RewrapSystemKeys in-place without rotating DEKs.")
		fmt.Println("2. Crypto-Shredding: store.DestroyKeys(ctx, pool, \"user_pii\", userID)")
		fmt.Println("   - Hard-deletes the DEK row (DELETE FROM infrastructure.encryption_keys).")
		fmt.Println("   - Historical event streams remain immutable, but all ciphertext is unreadable.")

		// Demonstrate pure in-memory crypto-shredding step
		dek, err := env.GenerateDEK()
		if err != nil {
			return fmt.Errorf("generate DEK: %w", err)
		}
		defer encryption.ZeroBytes(dek)

		sysKeyID := env.ActiveKeyID()
		encDEK, err := env.WrapDEK(sysKeyID, dek)
		if err != nil {
			return fmt.Errorf("wrap DEK: %w", err)
		}

		email := "alice.smith@example.com"
		ciphertext, err := env.Encrypt(sysKeyID, encDEK, email)
		if err != nil {
			return fmt.Errorf("encrypt: %w", err)
		}
		fmt.Printf("\nDemo encrypted ciphertext: %s\n", ciphertext)

		decrypted, err := env.Decrypt(sysKeyID, encDEK, ciphertext)
		if err != nil {
			return fmt.Errorf("decrypt: %w", err)
		}
		fmt.Printf("Demo decrypted plaintext:  %s\n", decrypted)

		encryption.ZeroBytes(encDEK)
		fmt.Println("Demo DEK destroyed from memory.")
		fmt.Println("\n✓ GDPR Right to Erasure satisfied.")
	}

	return nil
}
