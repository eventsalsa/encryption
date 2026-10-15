// Package awskms implements kek.Wrapper and kek.Rewrapper backed by AWS Key
// Management Service (AWS KMS) using AWS SDK for Go v2.
package awskms

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/eventsalsa/encryption"
	"github.com/eventsalsa/encryption/kek"
)

// DefaultContextKey is the default AWS KMS EncryptionContext map key used to
// bind Additional Authenticated Data (AAD) when no custom key is provided via
// WithContextKey.
const DefaultContextKey = "eventsalsa:aad"

// Option configures a Wrapper.
type Option func(*Wrapper) error

// WithContextKey overrides the AWS KMS EncryptionContext key used to store
// base64-encoded AAD (default: DefaultContextKey).
func WithContextKey(key string) Option {
	return func(w *Wrapper) error {
		if key == "" {
			return fmt.Errorf("awskms: context key must not be empty: %w", encryption.ErrInvalidConfig)
		}
		w.contextKey = key
		return nil
	}
}

// Client defines the AWS KMS operations required by Wrapper.
// It is satisfied by *kms.Client from github.com/aws/aws-sdk-go-v2/service/kms.
type Client interface {
	Encrypt(ctx context.Context, params *kms.EncryptInput, optFns ...func(*kms.Options)) (*kms.EncryptOutput, error)
	Decrypt(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error)
	ReEncrypt(ctx context.Context, params *kms.ReEncryptInput, optFns ...func(*kms.Options)) (*kms.ReEncryptOutput, error)
}

// Wrapper implements kek.Wrapper and kek.Rewrapper using AWS KMS.
// The underlying KEK material never leaves AWS KMS.
type Wrapper struct {
	client     Client
	keyID      string
	contextKey string
}

var (
	_ kek.Wrapper   = (*Wrapper)(nil)
	_ kek.Rewrapper = (*Wrapper)(nil)
)

// NewWrapper creates an AWS KMS KEK Wrapper for the given keyID (ARN, alias ARN, or key ID).
func NewWrapper(client Client, keyID string, opts ...Option) (*Wrapper, error) {
	if client == nil {
		return nil, fmt.Errorf("awskms: client is nil: %w", encryption.ErrInvalidConfig)
	}
	if keyID == "" {
		return nil, fmt.Errorf("awskms: key ID is required: %w", encryption.ErrInvalidConfig)
	}
	w := &Wrapper{
		client:     client,
		keyID:      keyID,
		contextKey: DefaultContextKey,
	}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt(w); err != nil {
			return nil, err
		}
	}
	return w, nil
}

// ID returns the configured AWS KMS key identifier.
func (w *Wrapper) ID() string {
	return w.keyID
}

// Wrap encrypts a plaintext DEK using AWS KMS Encrypt and binds aad via EncryptionContext.
func (w *Wrapper) Wrap(ctx context.Context, dek, aad []byte) ([]byte, error) {
	if len(dek) == 0 {
		return nil, fmt.Errorf("awskms wrap: DEK must not be empty: %w", encryption.ErrInvalidKeySize)
	}

	out, err := w.client.Encrypt(ctx, &kms.EncryptInput{
		KeyId:             &w.keyID,
		Plaintext:         dek,
		EncryptionContext: buildEncryptionContext(w.contextKey, aad),
	})
	if err != nil {
		return nil, fmt.Errorf("awskms wrap with %q: %w: %w", w.keyID, err, encryption.ErrEncryption)
	}
	if out == nil || len(out.CiphertextBlob) == 0 {
		return nil, fmt.Errorf("awskms wrap with %q: empty ciphertext response: %w", w.keyID, encryption.ErrEncryption)
	}

	return out.CiphertextBlob, nil
}

// Unwrap decrypts an encrypted DEK using AWS KMS Decrypt, explicitly pinning
// KeyId and verifying aad via EncryptionContext.
func (w *Wrapper) Unwrap(ctx context.Context, encryptedDEK, aad []byte) ([]byte, error) {
	if len(encryptedDEK) == 0 {
		return nil, fmt.Errorf("awskms unwrap: ciphertext is empty: %w", encryption.ErrDecryption)
	}

	out, err := w.client.Decrypt(ctx, &kms.DecryptInput{
		KeyId:             &w.keyID,
		CiphertextBlob:    encryptedDEK,
		EncryptionContext: buildEncryptionContext(w.contextKey, aad),
	})
	if err != nil {
		return nil, fmt.Errorf("awskms unwrap with %q: %w: %w", w.keyID, err, encryption.ErrDecryption)
	}
	if out == nil || len(out.Plaintext) == 0 {
		return nil, fmt.Errorf("awskms unwrap with %q: empty plaintext response: %w", w.keyID, encryption.ErrDecryption)
	}

	dek := make([]byte, len(out.Plaintext))
	copy(dek, out.Plaintext)
	encryption.ZeroBytes(out.Plaintext)
	return dek, nil
}

// Rewrap performs server-side DEK re-encryption via AWS KMS ReEncrypt when
// target is also an *awskms.Wrapper sharing the same Client. Otherwise, it
// returns errors.ErrUnsupported so kek.Keyring falls back to Unwrap + Wrap.
func (w *Wrapper) Rewrap(ctx context.Context, target kek.Wrapper, encryptedDEK, sourceAAD, targetAAD []byte) ([]byte, error) {
	targetAWS, ok := target.(*Wrapper)
	if !ok || targetAWS.client != w.client {
		return nil, errors.ErrUnsupported
	}
	if len(encryptedDEK) == 0 {
		return nil, fmt.Errorf("awskms rewrap: ciphertext is empty: %w", encryption.ErrDecryption)
	}

	out, err := w.client.ReEncrypt(ctx, &kms.ReEncryptInput{
		SourceKeyId:                  &w.keyID,
		DestinationKeyId:             &targetAWS.keyID,
		CiphertextBlob:               encryptedDEK,
		SourceEncryptionContext:      buildEncryptionContext(w.contextKey, sourceAAD),
		DestinationEncryptionContext: buildEncryptionContext(targetAWS.contextKey, targetAAD),
	})
	if err != nil {
		return nil, fmt.Errorf("awskms rewrap from %q to %q: %w: %w", w.keyID, targetAWS.keyID, err, encryption.ErrEncryption)
	}
	if out == nil || len(out.CiphertextBlob) == 0 {
		return nil, fmt.Errorf("awskms rewrap from %q to %q: empty ciphertext response: %w", w.keyID, targetAWS.keyID, encryption.ErrEncryption)
	}

	return out.CiphertextBlob, nil
}

func buildEncryptionContext(contextKey string, aad []byte) map[string]string {
	if len(aad) == 0 {
		return nil
	}
	return map[string]string{
		contextKey: base64.StdEncoding.EncodeToString(aad),
	}
}
