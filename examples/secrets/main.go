// Example: secret encryption with key rotation.
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/eventsalsa/encryption"
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

	scope, secretID := "api_token", "service-A"

	// 1. Create initial key (version 1).
	v1, err := mod.KeyManager.CreateKey(ctx, nil, scope, secretID)
	if err != nil {
		log.Fatal("CreateKey: ", err)
	}
	fmt.Printf("Created key version %d\n", v1)

	// 2. Fetch key v1 and encrypt secret.
	keyV1, err := store.GetActiveKey(ctx, nil, scope, secretID)
	if err != nil {
		log.Fatal("GetActiveKey: ", err)
	}
	secret1, err := mod.Envelope.Encrypt(keyV1.SystemKeyID, keyV1.EncryptedDEK, "s3cr3t-token-v1")
	if err != nil {
		log.Fatal("Encrypt v1: ", err)
	}
	fmt.Printf("Secret 1 (key v%d): %s\n", keyV1.KeyVersion, secret1)

	// --- 3. Rotate the key ---
	v2, err := mod.KeyManager.RotateKey(ctx, nil, scope, secretID)
	if err != nil {
		log.Fatal("RotateKey: ", err)
	}
	fmt.Printf("\nRotated to key version %d\n", v2)

	// 4. Fetch new active key v2 and encrypt new secret.
	keyV2, err := store.GetActiveKey(ctx, nil, scope, secretID)
	if err != nil {
		log.Fatal("GetActiveKey: ", err)
	}
	secret2, err := mod.Envelope.Encrypt(keyV2.SystemKeyID, keyV2.EncryptedDEK, "s3cr3t-token-v2")
	if err != nil {
		log.Fatal("Encrypt v2: ", err)
	}
	fmt.Printf("Secret 2 (key v%d): %s\n", keyV2.KeyVersion, secret2)

	// 5. Decrypt both historical and new secrets using their respective key versions.
	plain1, err := mod.Envelope.Decrypt(keyV1.SystemKeyID, keyV1.EncryptedDEK, secret1)
	if err != nil {
		log.Fatal("Decrypt secret1: ", err)
	}
	plain2, err := mod.Envelope.Decrypt(keyV2.SystemKeyID, keyV2.EncryptedDEK, secret2)
	if err != nil {
		log.Fatal("Decrypt secret2: ", err)
	}

	fmt.Printf("\nDecrypted secret 1 (key v%d): %s\n", keyV1.KeyVersion, plain1)
	fmt.Printf("Decrypted secret 2 (key v%d): %s\n", keyV2.KeyVersion, plain2)

	fmt.Println("\n✓ Both old and new secrets decrypt correctly after rotation.")
}
