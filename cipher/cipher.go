// Package cipher defines the authenticated symmetric encryption interface (AEAD)
// used throughout the encryption library. Implementations must be safe for
// concurrent use.
package cipher

// Cipher performs authenticated symmetric encryption and decryption (AEAD).
// Implementations must be safe for concurrent use.
type Cipher interface {
	// Encrypt encrypts plaintext and cryptographically binds it to aad
	// (Additional Authenticated Data).
	// The ciphertext format is implementation-defined (e.g., nonce + ciphertext + tag).
	Encrypt(key, plaintext, aad []byte) ([]byte, error)

	// Decrypt decrypts ciphertext and verifies aad.
	Decrypt(key, ciphertext, aad []byte) ([]byte, error)

	// KeySize returns the required key size in bytes.
	KeySize() int
}
