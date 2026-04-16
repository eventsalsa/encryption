package encryption

import "github.com/eventsalsa/encryption/cipher"

// DefaultCipherFactory is called to create the default cipher when
// Config.Cipher is nil. It is set automatically by importing a cipher
// package that registers itself (e.g., cipher/aesgcm).
//
// If no cipher package has been imported and Config.Cipher is nil,
// New will panic.
var DefaultCipherFactory func() cipher.Cipher
