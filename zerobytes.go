package encryption

// ZeroBytes overwrites a byte slice with zeros to clear sensitive key material
// from memory. Use with defer after decrypting DEKs:
//
//	defer encryption.ZeroBytes(dek)
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
