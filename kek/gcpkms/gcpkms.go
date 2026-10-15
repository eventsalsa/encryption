// Package gcpkms implements kek.Wrapper backed by Google Cloud Key Management
// Service (Cloud KMS) with end-to-end Castagnoli CRC32C integrity verification.
package gcpkms

import (
	"context"
	"fmt"
	"hash/crc32"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/eventsalsa/encryption"
	"github.com/eventsalsa/encryption/kek"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var crc32cTable = crc32.MakeTable(crc32.Castagnoli)

// Client defines the Google Cloud KMS operations required by Wrapper.
// It is satisfied by *kms.KeyManagementClient from cloud.google.com/go/kms/apiv1.
type Client interface {
	Encrypt(ctx context.Context, req *kmspb.EncryptRequest, opts ...gax.CallOption) (*kmspb.EncryptResponse, error)
	Decrypt(ctx context.Context, req *kmspb.DecryptRequest, opts ...gax.CallOption) (*kmspb.DecryptResponse, error)
}

// Wrapper implements kek.Wrapper using Google Cloud KMS.
// The underlying CryptoKey material never leaves Google Cloud KMS.
type Wrapper struct {
	client  Client
	keyName string
}

var _ kek.Wrapper = (*Wrapper)(nil)

// NewWrapper creates a Google Cloud KMS KEK Wrapper for the given CryptoKey
// resource name (e.g., "projects/*/locations/*/keyRings/*/cryptoKeys/*").
func NewWrapper(client Client, keyName string) (*Wrapper, error) {
	if client == nil {
		return nil, fmt.Errorf("gcpkms: client is nil: %w", encryption.ErrInvalidConfig)
	}
	if keyName == "" {
		return nil, fmt.Errorf("gcpkms: key name is required: %w", encryption.ErrInvalidConfig)
	}
	return &Wrapper{
		client:  client,
		keyName: keyName,
	}, nil
}

// ID returns the configured Google Cloud KMS CryptoKey resource name.
func (w *Wrapper) ID() string {
	return w.keyName
}

// Wrap encrypts a plaintext DEK using Google Cloud KMS Encrypt, binding aad
// and enforcing end-to-end CRC32C integrity verification on request and response.
func (w *Wrapper) Wrap(ctx context.Context, dek, aad []byte) ([]byte, error) {
	if len(dek) == 0 {
		return nil, fmt.Errorf("gcpkms wrap: DEK must not be empty: %w", encryption.ErrInvalidKeySize)
	}

	req := &kmspb.EncryptRequest{
		Name:            w.keyName,
		Plaintext:       dek,
		PlaintextCrc32C: crc32cProto(dek),
	}
	if len(aad) > 0 {
		req.AdditionalAuthenticatedData = aad
		req.AdditionalAuthenticatedDataCrc32C = crc32cProto(aad)
	}

	resp, err := w.client.Encrypt(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("gcpkms wrap with %q: %w: %w", w.keyName, err, encryption.ErrEncryption)
	}
	if resp == nil {
		return nil, fmt.Errorf("gcpkms wrap with %q: nil response: %w", w.keyName, encryption.ErrEncryption)
	}
	if !resp.GetVerifiedPlaintextCrc32C() {
		return nil, fmt.Errorf("gcpkms wrap with %q: plaintext CRC32C not verified by server: %w", w.keyName, encryption.ErrEncryption)
	}
	if len(aad) > 0 && !resp.GetVerifiedAdditionalAuthenticatedDataCrc32C() {
		return nil, fmt.Errorf("gcpkms wrap with %q: AAD CRC32C not verified by server: %w", w.keyName, encryption.ErrEncryption)
	}
	if resp.GetCiphertextCrc32C() == nil || resp.GetCiphertextCrc32C().GetValue() != crc32cSum(resp.GetCiphertext()) {
		return nil, fmt.Errorf("gcpkms wrap with %q: response ciphertext CRC32C mismatch: %w", w.keyName, encryption.ErrEncryption)
	}

	return resp.GetCiphertext(), nil
}

// Unwrap decrypts an encrypted DEK using Google Cloud KMS Decrypt, verifying
// aad and enforcing end-to-end CRC32C integrity verification on request and response.
func (w *Wrapper) Unwrap(ctx context.Context, encryptedDEK, aad []byte) ([]byte, error) {
	if len(encryptedDEK) == 0 {
		return nil, fmt.Errorf("gcpkms unwrap: ciphertext is empty: %w", encryption.ErrDecryption)
	}

	req := &kmspb.DecryptRequest{
		Name:             w.keyName,
		Ciphertext:       encryptedDEK,
		CiphertextCrc32C: crc32cProto(encryptedDEK),
	}
	if len(aad) > 0 {
		req.AdditionalAuthenticatedData = aad
		req.AdditionalAuthenticatedDataCrc32C = crc32cProto(aad)
	}

	resp, err := w.client.Decrypt(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("gcpkms unwrap with %q: %w: %w", w.keyName, err, encryption.ErrDecryption)
	}
	if resp == nil || len(resp.GetPlaintext()) == 0 {
		return nil, fmt.Errorf("gcpkms unwrap with %q: empty plaintext response: %w", w.keyName, encryption.ErrDecryption)
	}
	if resp.GetPlaintextCrc32C() == nil || resp.GetPlaintextCrc32C().GetValue() != crc32cSum(resp.GetPlaintext()) {
		encryption.ZeroBytes(resp.GetPlaintext())
		return nil, fmt.Errorf("gcpkms unwrap with %q: response plaintext CRC32C mismatch: %w", w.keyName, encryption.ErrDecryption)
	}

	dek := make([]byte, len(resp.GetPlaintext()))
	copy(dek, resp.GetPlaintext())
	encryption.ZeroBytes(resp.GetPlaintext())
	return dek, nil
}

func crc32cSum(data []byte) int64 {
	return int64(crc32.Checksum(data, crc32cTable))
}

func crc32cProto(data []byte) *wrapperspb.Int64Value {
	return wrapperspb.Int64(crc32cSum(data))
}
