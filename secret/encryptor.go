package secret

import "context"

// Encryptor encrypts plaintext secrets for a specific scope.
type Encryptor interface {
	Encrypt(ctx context.Context, scope, scopeID, plaintext string) (EncryptedValue, error)
}

// Decryptor decrypts encrypted secrets for a specific scope.
type Decryptor interface {
	Decrypt(ctx context.Context, scope, scopeID string, value EncryptedValue) (string, error)
}
