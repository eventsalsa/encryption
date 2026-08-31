// Example: in-memory envelope encryption with envelope.Envelope.
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
	// 1. Set up system keyring and symmetric cipher.
	keyring := testutil.NewTestKeyring()
	c := aesgcm.New()

	// 2. Initialize in-memory envelope engine.
	env := envelope.New(keyring, c)

	// 3. Generate a fresh DEK in-memory and wrap it with the active system key.
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
	fmt.Printf("Generated DEK (%d bytes) wrapped with system key %q\n", len(dek), sysKeyID)

	// 4. Encrypt plaintext using the wrapped DEK.
	plaintext := "Hello, envelope encryption!"
	ciphertext, err := env.Encrypt(sysKeyID, encDEK, plaintext)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}
	fmt.Printf("Encrypted ciphertext: %s\n", ciphertext)

	// 5. Decrypt ciphertext back to plaintext.
	decrypted, err := env.Decrypt(sysKeyID, encDEK, ciphertext)
	if err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}
	fmt.Printf("Decrypted plaintext:  %s\n", decrypted)
	return nil
}
