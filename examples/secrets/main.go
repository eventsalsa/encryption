// Example: Secret encryption with key rotation and historical audit retention.
//
// Unlike user PII (which is pinned to 1 DEK and destroyed for GDPR erasure),
// application secrets (e.g. API tokens, third-party webhook secrets, credentials)
// require periodic rotation while preserving the ability to decrypt historical records.
//
// Workflow:
//  1. Secret v1 is created: store.CreateKey(ctx, conn, "api_token", "stripe")
//  2. Payloads are encrypted under v1.
//  3. When credentials rotate (e.g. 90-day policy), call store.RotateKey(ctx, conn, "api_token", "stripe").
//     - Inserts DEK version 2.
//     - Soft-revokes version 1 (revoked_at = NOW()).
//  4. New writes automatically use active key version 2.
//  5. Historical events/receipts encrypted under version 1 remain decryptable by fetching
//     key version 1 explicitly: store.GetKey(ctx, conn, "api_token", "stripe", 1).
package main

import (
	"context"
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

	scope, secretID := "api_token", "stripe_production"

	if dbURL != "" {
		pool, err := pgxpool.New(ctx, dbURL)
		if err != nil {
			return fmt.Errorf("connect to postgres: %w", err)
		}
		defer pool.Close()

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

		fmt.Printf("=== 1. Initial Secret Setup (Version 1) ===\n")
		v1, err := store.CreateKey(ctx, pool, scope, secretID)
		if err != nil {
			return fmt.Errorf("create key v1: %w", err)
		}
		keyV1, err := store.GetActiveKey(ctx, pool, scope, secretID)
		if err != nil {
			return fmt.Errorf("get active key v1: %w", err)
		}

		secretPayloadV1 := "sk_live_2026_q1_initial_token_value"
		cipherV1, err := env.Encrypt(keyV1.SystemKeyID, keyV1.EncryptedDEK, secretPayloadV1)
		if err != nil {
			return fmt.Errorf("encrypt v1: %w", err)
		}
		fmt.Printf("Created key version %d. Ciphertext: %s\n", v1, cipherV1)

		fmt.Printf("\n=== 2. 90-Day Secret Rotation (Version 2) ===\n")
		v2, err := store.RotateKey(ctx, pool, scope, secretID)
		if err != nil {
			return fmt.Errorf("rotate key to v2: %w", err)
		}
		keyV2, err := store.GetActiveKey(ctx, pool, scope, secretID)
		if err != nil {
			return fmt.Errorf("get active key v2: %w", err)
		}

		secretPayloadV2 := "sk_live_2026_q2_rotated_token_value"
		cipherV2, err := env.Encrypt(keyV2.SystemKeyID, keyV2.EncryptedDEK, secretPayloadV2)
		if err != nil {
			return fmt.Errorf("encrypt v2: %w", err)
		}
		fmt.Printf("Rotated to active key version %d. Ciphertext: %s\n", v2, cipherV2)

		fmt.Printf("\n=== 3. Audit Verification (Decrypting Both Versions) ===\n")
		// Fetch historical key version 1 (which is soft-revoked)
		histKeyV1, err := store.GetKey(ctx, pool, scope, secretID, 1)
		if err != nil {
			return fmt.Errorf("get key v1: %w", err)
		}
		if histKeyV1.RevokedAt == nil {
			return fmt.Errorf("expected key v1 to be revoked")
		}
		fmt.Printf("Historical key v1 revoked_at: %s\n", histKeyV1.RevokedAt.Format("2006-01-02 15:04:05"))

		plainV1, err := env.Decrypt(histKeyV1.SystemKeyID, histKeyV1.EncryptedDEK, cipherV1)
		if err != nil {
			return fmt.Errorf("decrypt v1: %w", err)
		}
		plainV2, err := env.Decrypt(keyV2.SystemKeyID, keyV2.EncryptedDEK, cipherV2)
		if err != nil {
			return fmt.Errorf("decrypt v2: %w", err)
		}

		fmt.Printf("Decrypted historical v1: %s\n", plainV1)
		fmt.Printf("Decrypted active v2:     %s\n", plainV2)

		fmt.Println("\n✓ Secret rotation successful: active key updated while historical data remains auditable.")
	} else {
		fmt.Println("=== Secret Rotation & Audit Retention Workflow ===")
		fmt.Println("Note: Set DATABASE_URL to run against live PostgreSQL.")
		fmt.Println()
		fmt.Println("1. Rotation Strategy: Versioned DEKs with soft revocation.")
		fmt.Println("   - Create initial key: store.CreateKey(ctx, conn, \"api_token\", \"stripe\") -> version 1")
		fmt.Println("   - Rotate key:         store.RotateKey(ctx, conn, \"api_token\", \"stripe\") -> version 2")
		fmt.Println("   - Soft-revokes version 1 (sets revoked_at = NOW()).")
		fmt.Println("2. Auditing Historical Data:")
		fmt.Println("   - Active key (version 2) is used for new data: store.GetActiveKey(...)")
		fmt.Println("   - Historical payloads (version 1) remain readable: store.GetKey(..., version=1)")

		// Demonstrate in-memory version workflow
		sysKeyID := env.ActiveKeyID()

		dek1, err := env.GenerateDEK()
		if err != nil {
			return fmt.Errorf("generate DEK 1: %w", err)
		}
		encDEK1, err := env.WrapDEK(sysKeyID, dek1)
		if err != nil {
			return fmt.Errorf("wrap DEK 1: %w", err)
		}
		encryption.ZeroBytes(dek1)

		dek2, err := env.GenerateDEK()
		if err != nil {
			return fmt.Errorf("generate DEK 2: %w", err)
		}
		encDEK2, err := env.WrapDEK(sysKeyID, dek2)
		if err != nil {
			return fmt.Errorf("wrap DEK 2: %w", err)
		}
		encryption.ZeroBytes(dek2)

		c1, err := env.Encrypt(sysKeyID, encDEK1, "sk_live_q1_token")
		if err != nil {
			return fmt.Errorf("encrypt 1: %w", err)
		}
		c2, err := env.Encrypt(sysKeyID, encDEK2, "sk_live_q2_token")
		if err != nil {
			return fmt.Errorf("encrypt 2: %w", err)
		}

		p1, err := env.Decrypt(sysKeyID, encDEK1, c1)
		if err != nil {
			return fmt.Errorf("decrypt 1: %w", err)
		}
		p2, err := env.Decrypt(sysKeyID, encDEK2, c2)
		if err != nil {
			return fmt.Errorf("decrypt 2: %w", err)
		}

		fmt.Printf("\nDemo decrypted historical v1: %s\n", p1)
		fmt.Printf("Demo decrypted active v2:     %s\n", p2)
		fmt.Println("\n✓ Secret rotation and historical decryption verified.")
	}

	return nil
}
