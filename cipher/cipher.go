// Package cipher defines the symmetric encryption interface used throughout
// the encryption library. Implementations must be safe for concurrent use.
package cipher

// Cipher performs symmetric encryption and decryption.
// Implementations must be safe for concurrent use.
type Cipher interface {
	// Encrypt encrypts plaintext and returns ciphertext.
	// The ciphertext format is implementation-defined (e.g., nonce + ciphertext + tag).
	Encrypt(key, plaintext []byte) ([]byte, error)

	// Decrypt decrypts ciphertext and returns plaintext.
	Decrypt(key, ciphertext []byte) ([]byte, error)

	// KeySize returns the required key size in bytes.
	KeySize() int
}
