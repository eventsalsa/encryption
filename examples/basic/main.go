// Example: envelope encryption with envelope.Envelope and envelope.Session.
package main

import (
	"context"
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
	ctx := context.Background()

	// 1. Set up KEK keyring and symmetric data cipher.
	keyring := testutil.NewTestKeyring()
	c := aesgcm.New()

	// 2. Initialize envelope engine.
	env := envelope.New(keyring, c)

	// 3. Generate a fresh DEK and wrap it with the active KEK bound to a KeyScope.
	dek, err := env.GenerateDEK()
	if err != nil {
		return fmt.Errorf("generate DEK: %w", err)
	}
	defer encryption.ZeroBytes(dek)

	scope := encryption.KeyScope{Scope: "user-pii", ScopeID: "user-1", KeyVersion: 1}
	kekID, encDEK, err := env.WrapDEK(ctx, scope, dek)
	if err != nil {
		return fmt.Errorf("wrap DEK: %w", err)
	}
	fmt.Printf("Generated DEK (%d bytes) wrapped with KEK %q\n", len(dek), kekID)

	key := &encryption.EncryptedKey{
		Scope:        scope.Scope,
		ScopeID:      scope.ScopeID,
		KeyVersion:   scope.KeyVersion,
		EncryptedDEK: encDEK,
		KEKID:        kekID,
	}

	// 4. Encrypt plaintext using the wrapped DEK and optional payload AAD.
	plaintext := "Hello, envelope encryption!"
	payloadAAD := []byte("field:greeting")
	ciphertext, err := env.EncryptString(ctx, key, plaintext, payloadAAD)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}
	fmt.Printf("Encrypted ciphertext: %s\n", ciphertext)

	// 5. Decrypt ciphertext back to plaintext.
	decrypted, err := env.DecryptString(ctx, key, ciphertext, payloadAAD)
	if err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}
	fmt.Printf("Decrypted plaintext:  %s\n", decrypted)
	return nil
}
