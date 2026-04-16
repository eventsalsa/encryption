package pii

import (
	"context"
	"fmt"

	"github.com/eventsalsa/encryption/envelope"
)

// Adapter bridges generic envelope encryption to PII-specific interfaces.
// It hardcodes key version to 1 (PII keys don't rotate).
type Adapter[ID fmt.Stringer] struct {
	encryptor *envelope.Encryptor
	scope     string
}

// NewAdapter creates a new PII adapter for the given scope.
func NewAdapter[ID fmt.Stringer](
	encryptor *envelope.Encryptor,
	scope string,
) *Adapter[ID] {
	return &Adapter[ID]{
		encryptor: encryptor,
		scope:     scope,
	}
}

// Encrypt encrypts plaintext PII for the given subject.
func (a *Adapter[ID]) Encrypt(ctx context.Context, subjectID ID, plaintext string) (EncryptedValue, error) {
	ciphertext, _, err := a.encryptor.Encrypt(ctx, a.scope, subjectID.String(), plaintext)
	if err != nil {
		return "", err
	}
	return EncryptedValue(ciphertext), nil
}

// Decrypt decrypts encrypted PII for the given subject.
// Key version is always 1 for PII (hardcoded).
func (a *Adapter[ID]) Decrypt(ctx context.Context, subjectID ID, value EncryptedValue) (string, error) {
	return a.encryptor.Decrypt(ctx, a.scope, subjectID.String(), string(value), 1)
}
