package secret

// EncryptedValue represents an encrypted secret with its associated key version.
type EncryptedValue struct {
	Content    string
	KeyVersion int
}

// New creates a new EncryptedValue.
func New(content string, keyVersion int) EncryptedValue {
	return EncryptedValue{
		Content:    content,
		KeyVersion: keyVersion,
	}
}

// IsEmpty returns true if the Content is empty.
func (e EncryptedValue) IsEmpty() bool {
	return e.Content == ""
}
