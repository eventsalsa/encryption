package awskms_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/eventsalsa/encryption"
	"github.com/eventsalsa/encryption/kek"
	"github.com/eventsalsa/encryption/kek/awskms"
	"github.com/eventsalsa/encryption/kek/local"
)

type mockKMSClient struct {
	keys          map[string]kek.Wrapper
	encryptCalls  int
	decryptCalls  int
	reEncryptCall int
}

func newMockKMSClient(t *testing.T, keyIDs ...string) *mockKMSClient {
	t.Helper()
	m := &mockKMSClient{
		keys: make(map[string]kek.Wrapper, len(keyIDs)),
	}
	for _, id := range keyIDs {
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			t.Fatal(err)
		}
		w, err := local.NewWrapper(id, raw)
		if err != nil {
			t.Fatal(err)
		}
		m.keys[id] = w
	}
	return m
}

func encodeContext(ec map[string]string) []byte {
	if len(ec) == 0 {
		return nil
	}
	var buf bytes.Buffer
	for k, v := range ec {
		fmt.Fprintf(&buf, "%s=%s;", k, v)
	}
	return buf.Bytes()
}

func (m *mockKMSClient) Encrypt(ctx context.Context, params *kms.EncryptInput, _ ...func(*kms.Options)) (*kms.EncryptOutput, error) {
	m.encryptCalls++
	if params.KeyId == nil {
		return nil, fmt.Errorf("missing KeyId")
	}
	w, ok := m.keys[*params.KeyId]
	if !ok {
		return nil, fmt.Errorf("unknown KMS key %q", *params.KeyId)
	}
	ct, err := w.Wrap(ctx, params.Plaintext, encodeContext(params.EncryptionContext))
	if err != nil {
		return nil, err
	}
	return &kms.EncryptOutput{
		CiphertextBlob: ct,
		KeyId:          params.KeyId,
	}, nil
}

func (m *mockKMSClient) Decrypt(ctx context.Context, params *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	m.decryptCalls++
	if params.KeyId == nil {
		return nil, fmt.Errorf("missing KeyId")
	}
	w, ok := m.keys[*params.KeyId]
	if !ok {
		return nil, fmt.Errorf("unknown KMS key %q", *params.KeyId)
	}
	pt, err := w.Unwrap(ctx, params.CiphertextBlob, encodeContext(params.EncryptionContext))
	if err != nil {
		return nil, err
	}
	return &kms.DecryptOutput{
		Plaintext: pt,
		KeyId:     params.KeyId,
	}, nil
}

func (m *mockKMSClient) ReEncrypt(ctx context.Context, params *kms.ReEncryptInput, _ ...func(*kms.Options)) (*kms.ReEncryptOutput, error) {
	m.reEncryptCall++
	decOut, err := m.Decrypt(ctx, &kms.DecryptInput{
		KeyId:             params.SourceKeyId,
		CiphertextBlob:    params.CiphertextBlob,
		EncryptionContext: params.SourceEncryptionContext,
	})
	if err != nil {
		return nil, err
	}
	encOut, err := m.Encrypt(ctx, &kms.EncryptInput{
		KeyId:             params.DestinationKeyId,
		Plaintext:         decOut.Plaintext,
		EncryptionContext: params.DestinationEncryptionContext,
	})
	if err != nil {
		return nil, err
	}
	return &kms.ReEncryptOutput{
		CiphertextBlob: encOut.CiphertextBlob,
		KeyId:          params.DestinationKeyId,
		SourceKeyId:    params.SourceKeyId,
	}, nil
}

func TestNewWrapperValidation(t *testing.T) {
	t.Parallel()
	client := newMockKMSClient(t, "arn:aws:kms:us-east-1:111122223333:key/k1")

	if _, err := awskms.NewWrapper(nil, "k1"); !errors.Is(err, encryption.ErrInvalidConfig) {
		t.Fatalf("nil client: err = %v, want ErrInvalidConfig", err)
	}
	if _, err := awskms.NewWrapper(client, ""); !errors.Is(err, encryption.ErrInvalidConfig) {
		t.Fatalf("empty keyID: err = %v, want ErrInvalidConfig", err)
	}
	if _, err := awskms.NewWrapper(client, "k1", awskms.WithContextKey("")); !errors.Is(err, encryption.ErrInvalidConfig) {
		t.Fatalf("empty context key: err = %v, want ErrInvalidConfig", err)
	}
}

func TestWithContextKeyIsolation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	keyARN := "arn:aws:kms:us-east-1:111122223333:key/k1"
	client := newMockKMSClient(t, keyARN)

	wDefault, err := awskms.NewWrapper(client, keyARN)
	if err != nil {
		t.Fatal(err)
	}
	wCustom, err := awskms.NewWrapper(client, keyARN, awskms.WithContextKey("acme:aad"))
	if err != nil {
		t.Fatal(err)
	}

	dek := []byte("0123456789abcdef0123456789abcdef")
	aad := []byte("scope-aad")

	encCustom, err := wCustom.Wrap(ctx, dek, aad)
	if err != nil {
		t.Fatalf("Wrap custom: %v", err)
	}

	// Unwrapping with a different context key fails because the EncryptionContext map differs
	if _, err := wDefault.Unwrap(ctx, encCustom, aad); !errors.Is(err, encryption.ErrDecryption) {
		t.Fatalf("Unwrap mismatched context key: err = %v, want ErrDecryption", err)
	}

	got, err := wCustom.Unwrap(ctx, encCustom, aad)
	if err != nil {
		t.Fatalf("Unwrap matching custom context key: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Fatalf("got %x, want %x", got, dek)
	}
}

func TestWrapUnwrapAndEncryptionContextAAD(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	keyARN1 := "arn:aws:kms:us-east-1:111122223333:key/k1"
	keyARN2 := "arn:aws:kms:us-east-1:111122223333:key/k2"
	client := newMockKMSClient(t, keyARN1, keyARN2)

	w1, err := awskms.NewWrapper(client, keyARN1)
	if err != nil {
		t.Fatal(err)
	}
	w2, err := awskms.NewWrapper(client, keyARN2)
	if err != nil {
		t.Fatal(err)
	}

	dek := []byte("0123456789abcdef0123456789abcdef")
	aad := []byte("4:user|5:u-123|1")

	encDEK, err := w1.Wrap(ctx, dek, aad)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	// Wrong AAD fails with ErrDecryption
	if _, err := w1.Unwrap(ctx, encDEK, []byte("4:user|5:u-999|1")); !errors.Is(err, encryption.ErrDecryption) {
		t.Fatalf("Unwrap wrong AAD: err = %v, want ErrDecryption", err)
	}

	// Wrong KMS KeyId fails with ErrDecryption
	if _, err := w2.Unwrap(ctx, encDEK, aad); !errors.Is(err, encryption.ErrDecryption) {
		t.Fatalf("Unwrap wrong KeyId: err = %v, want ErrDecryption", err)
	}

	got, err := w1.Unwrap(ctx, encDEK, aad)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Fatalf("got %x, want %x", got, dek)
	}
}

func TestNativeReEncryptAndCrossProviderFallback(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	keyARN1 := "arn:aws:kms:us-east-1:111122223333:key/k1"
	keyARN2 := "arn:aws:kms:us-east-1:111122223333:key/k2"
	client := newMockKMSClient(t, keyARN1, keyARN2)

	w1, _ := awskms.NewWrapper(client, keyARN1)
	w2, _ := awskms.NewWrapper(client, keyARN2)
	localW, _ := local.NewWrapper("local-1", make([]byte, 32))

	kr, err := kek.NewKeyring(keyARN2, w1, w2, localW)
	if err != nil {
		t.Fatal(err)
	}

	dek := []byte("0123456789abcdef0123456789abcdef")
	aad := []byte("scope-aad")

	encDEK, err := w1.Wrap(ctx, dek, aad)
	if err != nil {
		t.Fatal(err)
	}

	// Rewrapping from AWS KMS w1 -> AWS KMS w2 uses server-side ReEncrypt!
	rewrappedAWS, err := kr.Rewrap(ctx, keyARN1, keyARN2, encDEK, aad, aad)
	if err != nil {
		t.Fatalf("Rewrap AWS->AWS: %v", err)
	}
	if client.reEncryptCall != 1 {
		t.Fatalf("reEncryptCall = %d, want 1", client.reEncryptCall)
	}

	gotAWS, err := w2.Unwrap(ctx, rewrappedAWS, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotAWS, dek) {
		t.Fatal("DEK mismatch after AWS->AWS ReEncrypt")
	}

	// Rewrapping from AWS KMS w2 -> local wrapper returns ErrUnsupported from w2.Rewrap
	// and transparently falls back to Unwrap + Wrap in kek.Keyring!
	rewrappedLocal, err := kr.Rewrap(ctx, keyARN2, "local-1", rewrappedAWS, aad, aad)
	if err != nil {
		t.Fatalf("Rewrap AWS->local fallback: %v", err)
	}
	gotLocal, err := localW.Unwrap(ctx, rewrappedLocal, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotLocal, dek) {
		t.Fatal("DEK mismatch after AWS->local fallback rewrap")
	}
}
