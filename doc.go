// Package encryption provides envelope encryption for event-sourced systems.
//
// It supports two encryption categories with distinct semantics:
//
//   - PII (Personally Identifiable Information): per-subject encryption keys
//     with no rotation, supporting GDPR crypto-shredding via key destruction.
//   - Secrets (API credentials, tokens): versioned encryption keys with
//     rotation support, where old ciphertext remains decryptable.
//
// # Architecture
//
// The library uses envelope encryption: data is encrypted with a Data Encryption
// Key (DEK), and the DEK is encrypted with a system Key Encryption Key (KEK).
//
//   - cipher/: pluggable symmetric encryption (default: AES-256-GCM)
//   - systemkey/: system key (KEK) management
//   - keystore/: encrypted DEK persistence
//   - keymanager/: key lifecycle (create, rotate, revoke, destroy)
//   - envelope/: envelope encryption engine
//   - pii/: PII value types and adapters
//   - secret/: secret value types and adapters
//   - hash/: deterministic HMAC-SHA256 hashing
//
// # Quick Start
//
// Use [New] or [NewWithDefaults] to create a fully wired [Module]:
//
//	m := encryption.New(encryption.Config{
//	    Keyring: keyring,
//	    Store:   store,
//	})
package encryption
