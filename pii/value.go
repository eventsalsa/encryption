package pii

// EncryptedValue represents an encrypted piece of PII.
// It is an opaque base64-encoded string. Key version is always 1 (no rotation).
// When the encryption key is destroyed (crypto-shredding), this value becomes permanently unreadable.
type EncryptedValue string

// Redacted is a constant for displaying redacted PII in logs/debug output.
const Redacted = EncryptedValue("[REDACTED]")

// String returns the underlying string value.
func (e EncryptedValue) String() string {
	return string(e)
}

// IsEmpty returns true if the encrypted value is an empty string.
func (e EncryptedValue) IsEmpty() bool {
	return e == ""
}
