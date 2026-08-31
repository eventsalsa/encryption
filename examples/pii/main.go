// Example: GDPR PII encryption and crypto-shredding concepts.
package main

import (
	"fmt"
	"os"

	"github.com/eventsalsa/encryption"
	"github.com/eventsalsa/encryption/cipher/aesgcm"
	"github.com/eventsalsa/encryption/envelope"
	"github.com/eventsalsa/encryption/testutil"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// 1. Initialize envelope crypto engine.
	keyring := testutil.NewTestKeyring()
	c := aesgcm.New()
	env := envelope.New(keyring, c)

	// 2. Generate a dedicated DEK for a user's PII.
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
	fmt.Printf("1. Created user DEK wrapped with system key %q\n", sysKeyID)

	// 3. Encrypt the user's email address.
	email := "alice@example.com"
	encryptedEmail, err := env.Encrypt(sysKeyID, encDEK, email)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}
	fmt.Printf("2. Encrypted PII payload: %s\n", encryptedEmail)

	// 4. Decrypt the email address.
	decrypted, err := env.Decrypt(sysKeyID, encDEK, encryptedEmail)
	if err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}
	fmt.Printf("3. Decrypted PII payload: %s\n", decrypted)

	// --- 5. Crypto-shredding: destroy the DEK ---
	// In production, call: store.DestroyKeys(ctx, conn, "user_pii", userID)
	fmt.Println("\n4. Performing crypto-shredding (destroying user DEK)...")
	encryption.ZeroBytes(encDEK)

	// 6. Any attempt to decrypt without the DEK is mathematically impossible.
	fmt.Println("5. Without the DEK, historical ciphertexts in the event store are permanently shredded.")
	fmt.Println("\n✓ GDPR Right to Erasure satisfied via cryptographic deletion.")
	return nil
}
