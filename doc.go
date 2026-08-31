// Package encryption provides envelope encryption for Go systems.
//
// # Architecture
//
// The library uses envelope encryption: data is encrypted with a Data Encryption
// Key (DEK), and the DEK is encrypted with a system Key Encryption Key (KEK).
//
//   - cipher/: pluggable symmetric encryption interface and implementations (AES-256-GCM)
//   - systemkey/: system key (KEK) management abstractions and filesystem loaders
//   - envelope/: pure in-memory envelope encryption engine
//   - postgres/: stateless PostgreSQL keystore and key lifecycle management
//   - postgres/migrations: PostgreSQL migration SQL generator
//   - hash/: deterministic HMAC-SHA256 blind indexing
package encryption
