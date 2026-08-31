// Package encryption provides envelope encryption for Go systems.
//
// # Architecture
//
// The library uses envelope encryption: data is encrypted with a Data Encryption
// Key (DEK), and the DEK is encrypted with a system Key Encryption Key (KEK).
//
//   - cipher/: pluggable symmetric encryption interface and implementations (AES-256-GCM)
//   - systemkey/: system key (KEK) management abstractions
//   - keystore/: encrypted DEK persistence abstractions and PostgreSQL implementation
//   - keymanager/: key lifecycle (create, rotate, revoke, destroy)
//   - envelope/: pure in-memory envelope encryption engine
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
