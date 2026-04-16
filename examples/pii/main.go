// Example: PII encryption with crypto-shredding.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/eventsalsa/encryption"
	"github.com/eventsalsa/encryption/pii"
	"github.com/eventsalsa/encryption/testutil"

	_ "github.com/eventsalsa/encryption/cipher/aesgcm"
)

// userID implements fmt.Stringer so it can be used as a PII subject ID.
type userID string

func (u userID) String() string { return string(u) }

func main() {
	ctx := context.Background()

	keyring := testutil.NewTestKeyring()
	store := testutil.NewInMemoryKeyStore()

	mod := encryption.New(encryption.Config{
		Keyring: keyring,
		Store:   store,
	})

	// Create a PII adapter for the "pii_email" scope.
	adapter := pii.NewAdapter[userID](mod.Envelope, "pii_email")

	uid := userID("user-99")

	// Create a DEK for this user's PII.
	_, err := mod.KeyManager.CreateKey(ctx, "pii_email", uid.String())
	if err != nil {
		log.Fatal("CreateKey: ", err)
	}

	// Encrypt an email address.
	email := "alice@example.com"
	encrypted, err := adapter.Encrypt(ctx, uid, email)
	if err != nil {
		log.Fatal("Encrypt: ", err)
	}
	fmt.Printf("Encrypted email: %s\n", encrypted)

	// Decrypt it back.
	decrypted, err := adapter.Decrypt(ctx, uid, encrypted)
	if err != nil {
		log.Fatal("Decrypt: ", err)
	}
	fmt.Printf("Decrypted email: %s\n", decrypted)

	// --- Crypto-shredding: destroy all keys for this user ---
	fmt.Println("\nDestroying keys (crypto-shredding)...")
	if err := mod.KeyManager.DestroyKeys(ctx, "pii_email", uid.String()); err != nil {
		log.Fatal("DestroyKeys: ", err)
	}

	// Attempt to decrypt after key destruction — must fail.
	_, err = adapter.Decrypt(ctx, uid, encrypted)
	if err == nil {
		log.Fatal("expected error after crypto-shredding, got nil")
	}
	if errors.Is(err, encryption.ErrKeyNotFound) {
		fmt.Println("Decrypt after shredding: ErrKeyNotFound (as expected)")
	} else {
		fmt.Printf("Decrypt after shredding: %v\n", err)
	}

	fmt.Println("\n✓ PII is permanently unreadable after crypto-shredding.")
}
