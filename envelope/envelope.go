// Package envelope implements envelope encryption using a two-tier key
// hierarchy: system keys (KEKs) protect data encryption keys (DEKs), and DEKs
// protect application data.
package envelope

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/eventsalsa/encryption/cipher"
	encryption "github.com/eventsalsa/encryption/encerr"
	"github.com/eventsalsa/encryption/keystore"
	"github.com/eventsalsa/encryption/systemkey"
)

// Encryptor performs envelope encrypt/decrypt using a keyring, key store, and cipher.
type Encryptor struct {
	keyring systemkey.Keyring
	store   keystore.KeyStore
	cipher  cipher.Cipher
}

// NewEncryptor returns an Encryptor wired to the given keyring, store, and cipher.
func NewEncryptor(keyring systemkey.Keyring, store keystore.KeyStore, c cipher.Cipher) *Encryptor {
	return &Encryptor{keyring: keyring, store: store, cipher: c}
}

// Encrypt encrypts plaintext for the given scope/scopeID and returns the
// base64-encoded ciphertext along with the key version used.
func (e *Encryptor) Encrypt(ctx context.Context, scope, scopeID, plaintext string) (ciphertext string, keyVersion int, err error) {
	key, err := e.store.GetActiveKey(ctx, scope, scopeID)
	if err != nil {
		return "", 0, fmt.Errorf("envelope encrypt: get active key: %w", err)
	}

	sysKey, err := e.keyring.Key(key.SystemKeyID)
	if err != nil {
		return "", 0, fmt.Errorf("envelope encrypt: get system key: %w", err)
	}

	dek, err := e.cipher.Decrypt(sysKey, key.EncryptedDEK)
	if err != nil {
		return "", 0, fmt.Errorf("envelope encrypt: decrypt DEK: %w", err)
	}
	defer encryption.ZeroBytes(dek)

	ct, err := e.cipher.Encrypt(dek, []byte(plaintext))
	if err != nil {
		return "", 0, fmt.Errorf("envelope encrypt: %w", err)
	}

	return base64.StdEncoding.EncodeToString(ct), key.KeyVersion, nil
}

// Decrypt decrypts base64-encoded ciphertext that was encrypted under the
// specified key version for the given scope/scopeID.
func (e *Encryptor) Decrypt(ctx context.Context, scope, scopeID, ciphertext string, keyVersion int) (string, error) {
	key, err := e.store.GetKey(ctx, scope, scopeID, keyVersion)
	if err != nil {
		return "", fmt.Errorf("envelope decrypt: get key: %w", err)
	}

	sysKey, err := e.keyring.Key(key.SystemKeyID)
	if err != nil {
		return "", fmt.Errorf("envelope decrypt: get system key: %w", err)
	}

	dek, err := e.cipher.Decrypt(sysKey, key.EncryptedDEK)
	if err != nil {
		return "", fmt.Errorf("envelope decrypt: decrypt DEK: %w", err)
	}
	defer encryption.ZeroBytes(dek)

	raw, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("envelope decrypt: base64 decode: %w", err)
	}

	pt, err := e.cipher.Decrypt(dek, raw)
	if err != nil {
		return "", fmt.Errorf("envelope decrypt: %w", err)
	}

	return string(pt), nil
}
