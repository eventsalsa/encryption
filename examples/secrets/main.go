// Example: secret encryption with key rotation.
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/eventsalsa/encryption"
	"github.com/eventsalsa/encryption/secret"
	"github.com/eventsalsa/encryption/testutil"

	_ "github.com/eventsalsa/encryption/cipher/aesgcm"
)

func main() {
	ctx := context.Background()

	keyring := testutil.NewTestKeyring()
	store := testutil.NewInMemoryKeyStore()

	mod := encryption.New(encryption.Config{
		Keyring: keyring,
		Store:   store,
	})

	adapter := secret.NewAdapter(mod.Envelope)

	scope, scopeID := "api_token", "service-A"

	// Create initial key (version 1).
	v1, err := mod.KeyManager.CreateKey(ctx, scope, scopeID)
	if err != nil {
		log.Fatal("CreateKey: ", err)
	}
	fmt.Printf("Created key version %d\n", v1)

	// Encrypt a secret with key v1.
	secret1, err := adapter.Encrypt(ctx, scope, scopeID, "s3cr3t-token-v1")
	if err != nil {
		log.Fatal("Encrypt v1: ", err)
	}
	fmt.Printf("Secret 1 (key v%d): %s\n", secret1.KeyVersion, secret1.Content)

	// --- Rotate the key ---
	v2, err := mod.KeyManager.RotateKey(ctx, scope, scopeID)
	if err != nil {
		log.Fatal("RotateKey: ", err)
	}
	fmt.Printf("\nRotated to key version %d\n", v2)

	// Encrypt a new secret with key v2.
	secret2, err := adapter.Encrypt(ctx, scope, scopeID, "s3cr3t-token-v2")
	if err != nil {
		log.Fatal("Encrypt v2: ", err)
	}
	fmt.Printf("Secret 2 (key v%d): %s\n", secret2.KeyVersion, secret2.Content)

	// Decrypt both — each uses its own key version.
	plain1, err := adapter.Decrypt(ctx, scope, scopeID, secret1)
	if err != nil {
		log.Fatal("Decrypt secret1: ", err)
	}
	plain2, err := adapter.Decrypt(ctx, scope, scopeID, secret2)
	if err != nil {
		log.Fatal("Decrypt secret2: ", err)
	}

	fmt.Printf("\nDecrypted secret 1 (key v%d): %s\n", secret1.KeyVersion, plain1)
	fmt.Printf("Decrypted secret 2 (key v%d): %s\n", secret2.KeyVersion, plain2)

	fmt.Println("\n✓ Both old and new secrets decrypt correctly after rotation.")
}
