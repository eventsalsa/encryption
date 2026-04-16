package secret

import (
	"context"

	"github.com/eventsalsa/encryption/envelope"
)

// Adapter bridges the generic envelope encryptor to secret-specific semantics.
type Adapter struct {
	encryptor *envelope.Encryptor
}

// NewAdapter creates a new secret Adapter.
func NewAdapter(encryptor *envelope.Encryptor) *Adapter {
	return &Adapter{encryptor: encryptor}
}

// Encrypt encrypts plaintext and returns an EncryptedValue with the key version.
func (a *Adapter) Encrypt(ctx context.Context, scope, scopeID, plaintext string) (EncryptedValue, error) {
	ciphertext, keyVersion, err := a.encryptor.Encrypt(ctx, scope, scopeID, plaintext)
	if err != nil {
		return EncryptedValue{}, err
	}

	return New(ciphertext, keyVersion), nil
}

// Decrypt decrypts an EncryptedValue using the stored key version.
func (a *Adapter) Decrypt(ctx context.Context, scope, scopeID string, value EncryptedValue) (string, error) {
	return a.encryptor.Decrypt(ctx, scope, scopeID, value.Content, value.KeyVersion)
}
