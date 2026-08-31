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
	"os"
	"time"

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

	scope, secretID := "api_token", "stripe_production"

	// 3. Initial Secret Creation (Version 1)
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
	fmt.Printf("1. Created key version %d. Encrypted secret: %s\n", v1, cipherV1)

	// 4. 90-Day Secret Rotation: Generate Version 2 and soft-revoke Version 1
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
	fmt.Printf("2. Rotated to active key version %d. Encrypted new secret: %s\n", v2, cipherV2)

	// 5. Audit Verification: Historical and active secrets both decrypt accurately
	histKeyV1, err := store.GetKey(ctx, pool, scope, secretID, 1)
	if err != nil {
		return fmt.Errorf("get key v1: %w", err)
	}
	fmt.Printf("3. Historical key v1 status: revoked_at = %s\n", histKeyV1.RevokedAt.Format(time.RFC3339))

	plainV1, err := env.Decrypt(histKeyV1.SystemKeyID, histKeyV1.EncryptedDEK, cipherV1)
	if err != nil {
		return fmt.Errorf("decrypt v1: %w", err)
	}
	plainV2, err := env.Decrypt(keyV2.SystemKeyID, keyV2.EncryptedDEK, cipherV2)
	if err != nil {
		return fmt.Errorf("decrypt v2: %w", err)
	}

	fmt.Printf("4. Decrypted historical secret (v1): %s\n", plainV1)
	fmt.Printf("   Decrypted active secret     (v2): %s\n", plainV2)

	fmt.Println("\n✓ Secret rotation successful: active key updated while historical audit trail remains readable.")
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
