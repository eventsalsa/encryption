// Example: GDPR PII encryption and crypto-shredding.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/eventsalsa/encryption"
	"github.com/eventsalsa/encryption/encerr"
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

	scope, userID := "pii_email", "user-99"

	// 1. Create a DEK for this user's PII.
	_, err := mod.KeyManager.CreateKey(ctx, nil, scope, userID)
	if err != nil {
		log.Fatal("CreateKey: ", err)
	}

	// 2. Fetch the active key.
	key, err := store.GetActiveKey(ctx, nil, scope, userID)
	if err != nil {
		log.Fatal("GetActiveKey: ", err)
	}

	// 3. Encrypt the email address.
	email := "alice@example.com"
	encrypted, err := mod.Envelope.Encrypt(key.SystemKeyID, key.EncryptedDEK, email)
	if err != nil {
		log.Fatal("Encrypt: ", err)
	}
	fmt.Printf("Encrypted email: %s\n", encrypted)

	// 4. Decrypt it back.
	decrypted, err := mod.Envelope.Decrypt(key.SystemKeyID, key.EncryptedDEK, encrypted)
	if err != nil {
		log.Fatal("Decrypt: ", err)
	}
	fmt.Printf("Decrypted email: %s\n", decrypted)

	// --- 5. Crypto-shredding: destroy all keys for this user ---
	fmt.Println("\nDestroying keys (crypto-shredding)...")
	if err := mod.KeyManager.DestroyKeys(ctx, nil, scope, userID); err != nil {
		log.Fatal("DestroyKeys: ", err)
	}

	// 6. Attempt to fetch key after key destruction — must fail.
	_, err = store.GetActiveKey(ctx, nil, scope, userID)
	if err == nil {
		log.Fatal("expected error fetching key after crypto-shredding, got nil")
	}
	if errors.Is(err, encerr.ErrKeyNotFound) {
		fmt.Println("Fetch key after shredding: ErrKeyNotFound (as expected)")
	} else {
		fmt.Printf("Fetch key after shredding: %v\n", err)
	}

	fmt.Println("\n✓ PII is permanently unreadable after crypto-shredding.")
}
