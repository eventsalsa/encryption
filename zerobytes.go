package encryption

import "github.com/eventsalsa/encryption/encerr"

// ZeroBytes overwrites a byte slice with zeros to clear sensitive key material
// from memory. Use with defer after decrypting DEKs:
//
//	defer encryption.ZeroBytes(dek)
func ZeroBytes(b []byte) {
	encerr.ZeroBytes(b)
}
