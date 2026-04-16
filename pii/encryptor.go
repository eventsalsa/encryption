package pii

import (
	"context"
	"fmt"
)

// Encryptor encrypts plaintext PII for a specific subject.
type Encryptor[ID fmt.Stringer] interface {
	Encrypt(ctx context.Context, subjectID ID, plaintext string) (EncryptedValue, error)
}

// Decryptor decrypts encrypted PII for a specific subject.
type Decryptor[ID fmt.Stringer] interface {
	Decrypt(ctx context.Context, subjectID ID, value EncryptedValue) (string, error)
}
