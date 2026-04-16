package encryption

import (
	"github.com/eventsalsa/encryption/cipher"
	"github.com/eventsalsa/encryption/envelope"
	"github.com/eventsalsa/encryption/hash"
	"github.com/eventsalsa/encryption/keymanager"
	"github.com/eventsalsa/encryption/keystore"
	"github.com/eventsalsa/encryption/systemkey"
)

// Config holds all configuration needed for the encryption module.
type Config struct {
	Keyring systemkey.Keyring
	Store   keystore.KeyStore
	Cipher  cipher.Cipher // optional — defaults to AES-256-GCM
}

// Module is the assembled encryption module providing all components.
type Module struct {
	KeyManager *keymanager.Manager
	Envelope   *envelope.Encryptor
	Hasher     hash.Hasher // nil if no HMAC key provided
}

// New creates a fully wired encryption module from the given config.
// If cfg.Cipher is nil, the cipher registered via DefaultCipherFactory
// is used (AES-256-GCM when cipher/aesgcm is imported).
func New(cfg Config) *Module {
	c := cfg.Cipher
	if c == nil {
		if DefaultCipherFactory == nil {
			panic("encryption: no cipher provided and no default cipher registered; import cipher/aesgcm for AES-256-GCM")
		}
		c = DefaultCipherFactory()
	}
	return &Module{
		KeyManager: keymanager.New(cfg.Keyring, cfg.Store, c),
		Envelope:   envelope.NewEncryptor(cfg.Keyring, cfg.Store, c),
	}
}

// Option is a functional option for NewWithDefaults.
type Option func(*options)

type options struct {
	cipher  cipher.Cipher
	hmacKey []byte
}

// WithCipher sets a custom cipher implementation.
func WithCipher(c cipher.Cipher) Option {
	return func(o *options) { o.cipher = c }
}

// WithHMACKey enables the HMAC hasher with the given key.
func WithHMACKey(key []byte) Option {
	return func(o *options) { o.hmacKey = key }
}

// NewWithDefaults creates a module with AES-256-GCM cipher.
// Provide a KeyStore and Keyring; use options for additional configuration.
func NewWithDefaults(keyring systemkey.Keyring, store keystore.KeyStore, opts ...Option) *Module {
	o := &options{}
	for _, opt := range opts {
		opt(o)
	}

	cfg := Config{
		Keyring: keyring,
		Store:   store,
		Cipher:  o.cipher,
	}

	m := New(cfg)

	if len(o.hmacKey) > 0 {
		m.Hasher = hash.NewHMACHasher(o.hmacKey)
	}

	return m
}
