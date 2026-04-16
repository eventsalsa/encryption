// Example: basic envelope encryption with the encryption module.
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

	// Set up an in-memory keyring and key store (for testing/demo only).
	keyring := testutil.NewTestKeyring()
	store := testutil.NewInMemoryKeyStore()

	// Create the encryption module (uses AES-256-GCM by default).
	mod := encryption.New(encryption.Config{
		Keyring: keyring,
		Store:   store,
	})

	// Create a DEK for scope "user" / scopeID "42".
	scope, scopeID := "user", "42"
	version, err := mod.KeyManager.CreateKey(ctx, scope, scopeID)
	if err != nil {
		log.Fatal("CreateKey: ", err)
	}
	fmt.Printf("Created key version %d for %s:%s\n", version, scope, scopeID)

	// Encrypt a plaintext string.
	plaintext := "Hello, envelope encryption!"
	ciphertext, keyVer, err := mod.Envelope.Encrypt(ctx, scope, scopeID, plaintext)
	if err != nil {
		log.Fatal("Encrypt: ", err)
	}
	fmt.Printf("Encrypted (key v%d): %s\n", keyVer, ciphertext)

	// Decrypt it back.
	decrypted, err := mod.Envelope.Decrypt(ctx, scope, scopeID, ciphertext, keyVer)
	if err != nil {
		log.Fatal("Decrypt: ", err)
	}
	fmt.Printf("Decrypted: %s\n", decrypted)
}
