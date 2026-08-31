// Example: secret encryption with key rotation workflow.
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

	sysKeyID := env.ActiveKeyID()

	// 2. Generate and wrap DEK v1.
	dek1, err := env.GenerateDEK()
	if err != nil {
		return fmt.Errorf("generate DEK v1: %w", err)
	}
	defer encryption.ZeroBytes(dek1)

	encDEK1, err := env.WrapDEK(sysKeyID, dek1)
	if err != nil {
		return fmt.Errorf("wrap DEK v1: %w", err)
	}

	secret1 := "production-api-token-2026-q1"
	ciphertext1, err := env.Encrypt(sysKeyID, encDEK1, secret1)
	if err != nil {
		return fmt.Errorf("encrypt v1: %w", err)
	}
	fmt.Printf("Key v1 Encrypted Secret: %s\n", ciphertext1)

	// 3. Key Rotation: Generate and wrap DEK v2.
	// In production, call: store.RotateKey(ctx, conn, "api_token", "stripe")
	dek2, err := env.GenerateDEK()
	if err != nil {
		return fmt.Errorf("generate DEK v2: %w", err)
	}
	defer encryption.ZeroBytes(dek2)

	encDEK2, err := env.WrapDEK(sysKeyID, dek2)
	if err != nil {
		return fmt.Errorf("wrap DEK v2: %w", err)
	}

	secret2 := "production-api-token-2026-q2"
	ciphertext2, err := env.Encrypt(sysKeyID, encDEK2, secret2)
	if err != nil {
		return fmt.Errorf("encrypt v2: %w", err)
	}
	fmt.Printf("Key v2 Encrypted Secret: %s\n", ciphertext2)

	// 4. Decrypt both historical (v1) and active (v2) secrets.
	decrypted1, err := env.Decrypt(sysKeyID, encDEK1, ciphertext1)
	if err != nil {
		return fmt.Errorf("decrypt v1: %w", err)
	}
	decrypted2, err := env.Decrypt(sysKeyID, encDEK2, ciphertext2)
	if err != nil {
		return fmt.Errorf("decrypt v2: %w", err)
	}

	fmt.Printf("\nDecrypted v1: %s\n", decrypted1)
	fmt.Printf("Decrypted v2: %s\n", decrypted2)
	fmt.Println("\n✓ Both old and new secrets decrypt correctly after rotation.")
	return nil
}
