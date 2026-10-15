package gcpkms_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"hash/crc32"
	"testing"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/eventsalsa/encryption"
	"github.com/eventsalsa/encryption/kek"
	"github.com/eventsalsa/encryption/kek/gcpkms"
	"github.com/eventsalsa/encryption/kek/local"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var castagnoliTable = crc32.MakeTable(crc32.Castagnoli)

func crcSum(b []byte) int64 {
	return int64(crc32.Checksum(b, castagnoliTable))
}

type mockGCPClient struct {
	keys                 map[string]kek.Wrapper
	corruptCiphertextCRC bool
	corruptPlaintextCRC  bool
	unverifiedPlaintext  bool
	unverifiedAAD        bool
}

func newMockGCPClient(t *testing.T, keyNames ...string) *mockGCPClient {
	t.Helper()
	m := &mockGCPClient{
		keys: make(map[string]kek.Wrapper, len(keyNames)),
	}
	for _, name := range keyNames {
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			t.Fatal(err)
		}
		w, err := local.NewWrapper(name, raw)
		if err != nil {
			t.Fatal(err)
		}
		m.keys[name] = w
	}
	return m
}

func (m *mockGCPClient) Encrypt(ctx context.Context, req *kmspb.EncryptRequest, _ ...gax.CallOption) (*kmspb.EncryptResponse, error) {
	w, ok := m.keys[req.GetName()]
	if !ok {
		return nil, fmt.Errorf("unknown CryptoKey %q", req.GetName())
	}
	if req.GetPlaintextCrc32C().GetValue() != crcSum(req.GetPlaintext()) {
		return nil, fmt.Errorf("request plaintext CRC32C mismatch")
	}
	if len(req.GetAdditionalAuthenticatedData()) > 0 &&
		req.GetAdditionalAuthenticatedDataCrc32C().GetValue() != crcSum(req.GetAdditionalAuthenticatedData()) {
		return nil, fmt.Errorf("request AAD CRC32C mismatch")
	}

	ct, err := w.Wrap(ctx, req.GetPlaintext(), req.GetAdditionalAuthenticatedData())
	if err != nil {
		return nil, err
	}

	ctCRC := crcSum(ct)
	if m.corruptCiphertextCRC {
		ctCRC ^= 0xFF
	}

	return &kmspb.EncryptResponse{
		Name:                    req.GetName(),
		Ciphertext:              ct,
		CiphertextCrc32C:        wrapperspb.Int64(ctCRC),
		VerifiedPlaintextCrc32C: !m.unverifiedPlaintext,
		VerifiedAdditionalAuthenticatedDataCrc32C: len(req.GetAdditionalAuthenticatedData()) > 0 && !m.unverifiedAAD,
	}, nil
}

func (m *mockGCPClient) Decrypt(ctx context.Context, req *kmspb.DecryptRequest, _ ...gax.CallOption) (*kmspb.DecryptResponse, error) {
	w, ok := m.keys[req.GetName()]
	if !ok {
		return nil, fmt.Errorf("unknown CryptoKey %q", req.GetName())
	}
	if req.GetCiphertextCrc32C().GetValue() != crcSum(req.GetCiphertext()) {
		return nil, fmt.Errorf("request ciphertext CRC32C mismatch")
	}
	if len(req.GetAdditionalAuthenticatedData()) > 0 &&
		req.GetAdditionalAuthenticatedDataCrc32C().GetValue() != crcSum(req.GetAdditionalAuthenticatedData()) {
		return nil, fmt.Errorf("request AAD CRC32C mismatch")
	}

	pt, err := w.Unwrap(ctx, req.GetCiphertext(), req.GetAdditionalAuthenticatedData())
	if err != nil {
		return nil, err
	}

	ptCRC := crcSum(pt)
	if m.corruptPlaintextCRC {
		ptCRC ^= 0xFF
	}

	return &kmspb.DecryptResponse{
		Plaintext:       pt,
		PlaintextCrc32C: wrapperspb.Int64(ptCRC),
	}, nil
}

func TestNewWrapperValidation(t *testing.T) {
	t.Parallel()
	keyName := "projects/p/locations/l/keyRings/r/cryptoKeys/k1"
	client := newMockGCPClient(t, keyName)

	if _, err := gcpkms.NewWrapper(nil, keyName); !errors.Is(err, encryption.ErrInvalidConfig) {
		t.Fatalf("nil client: err = %v, want ErrInvalidConfig", err)
	}
	if _, err := gcpkms.NewWrapper(client, ""); !errors.Is(err, encryption.ErrInvalidConfig) {
		t.Fatalf("empty keyName: err = %v, want ErrInvalidConfig", err)
	}
}

func TestWrapUnwrapAndAAD(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	keyName1 := "projects/p/locations/l/keyRings/r/cryptoKeys/k1"
	keyName2 := "projects/p/locations/l/keyRings/r/cryptoKeys/k2"
	client := newMockGCPClient(t, keyName1, keyName2)

	w1, err := gcpkms.NewWrapper(client, keyName1)
	if err != nil {
		t.Fatal(err)
	}
	w2, err := gcpkms.NewWrapper(client, keyName2)
	if err != nil {
		t.Fatal(err)
	}

	dek := []byte("0123456789abcdef0123456789abcdef")
	aad := []byte("4:user|5:u-123|1")

	encDEK, err := w1.Wrap(ctx, dek, aad)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	// Wrong AAD must fail with ErrDecryption
	if _, err := w1.Unwrap(ctx, encDEK, []byte("4:user|5:u-999|1")); !errors.Is(err, encryption.ErrDecryption) {
		t.Fatalf("Unwrap wrong AAD: err = %v, want ErrDecryption", err)
	}

	// Wrong CryptoKey must fail with ErrDecryption
	if _, err := w2.Unwrap(ctx, encDEK, aad); !errors.Is(err, encryption.ErrDecryption) {
		t.Fatalf("Unwrap wrong CryptoKey: err = %v, want ErrDecryption", err)
	}

	got, err := w1.Unwrap(ctx, encDEK, aad)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Fatalf("got %x, want %x", got, dek)
	}
}

func TestCRC32CIntegrityVerification(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	keyName := "projects/p/locations/l/keyRings/r/cryptoKeys/k1"
	dek := []byte("0123456789abcdef0123456789abcdef")
	aad := []byte("scope-aad")

	t.Run("unverified plaintext CRC on Encrypt", func(t *testing.T) {
		t.Parallel()
		client := newMockGCPClient(t, keyName)
		client.unverifiedPlaintext = true
		w, _ := gcpkms.NewWrapper(client, keyName)
		if _, err := w.Wrap(ctx, dek, aad); !errors.Is(err, encryption.ErrEncryption) {
			t.Fatalf("err = %v, want ErrEncryption", err)
		}
	})

	t.Run("unverified AAD CRC on Encrypt", func(t *testing.T) {
		t.Parallel()
		client := newMockGCPClient(t, keyName)
		client.unverifiedAAD = true
		w, _ := gcpkms.NewWrapper(client, keyName)
		if _, err := w.Wrap(ctx, dek, aad); !errors.Is(err, encryption.ErrEncryption) {
			t.Fatalf("err = %v, want ErrEncryption", err)
		}
	})

	t.Run("corrupted ciphertext CRC on Encrypt response", func(t *testing.T) {
		t.Parallel()
		client := newMockGCPClient(t, keyName)
		client.corruptCiphertextCRC = true
		w, _ := gcpkms.NewWrapper(client, keyName)
		if _, err := w.Wrap(ctx, dek, aad); !errors.Is(err, encryption.ErrEncryption) {
			t.Fatalf("err = %v, want ErrEncryption", err)
		}
	})

	t.Run("corrupted plaintext CRC on Decrypt response", func(t *testing.T) {
		t.Parallel()
		client := newMockGCPClient(t, keyName)
		w, _ := gcpkms.NewWrapper(client, keyName)
		encDEK, err := w.Wrap(ctx, dek, aad)
		if err != nil {
			t.Fatal(err)
		}
		client.corruptPlaintextCRC = true
		if _, err := w.Unwrap(ctx, encDEK, aad); !errors.Is(err, encryption.ErrDecryption) {
			t.Fatalf("err = %v, want ErrDecryption", err)
		}
	})
}
