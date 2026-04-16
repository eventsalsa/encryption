package systemkey

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/eventsalsa/encryption/encerr"
)

// FileKeyConfig holds the configuration for loading keys from files.
type FileKeyConfig struct {
	// KeyPaths maps key IDs to file paths containing base64-encoded keys.
	KeyPaths    map[string]string
	ActiveKeyID string
}

// NewKeyringFromFiles reads base64-encoded 32-byte keys from the configured
// file paths and returns a memoryKeyring.
func NewKeyringFromFiles(cfg FileKeyConfig) (Keyring, error) {
	keys := make(map[string][]byte, len(cfg.KeyPaths))
	for id, path := range cfg.KeyPaths {
		data, err := os.ReadFile(path) //#nosec G304 -- KeyPaths are provided by trusted configuration, not user input //nolint:gosec
		if err != nil {
			return nil, fmt.Errorf("systemkey: reading key %q: %w", id, err)
		}
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
		if err != nil {
			return nil, fmt.Errorf("systemkey: decoding key %q: %w", id, err)
		}
		if len(decoded) != 32 {
			return nil, fmt.Errorf("systemkey: key %q is %d bytes, want 32: %w", id, len(decoded), encerr.ErrInvalidKeySize)
		}
		keys[id] = decoded
	}
	return NewKeyring(keys, cfg.ActiveKeyID), nil
}
