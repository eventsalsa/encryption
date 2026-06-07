---
name: secure-cryptography
description: Cryptographic security standards, key isolation, memory hygiene, and safe error handling.
---

# Cryptographic & Security Standards

Use this skill when implementing, reviewing, or modifying encryption routines, key management flows, ciphertext formatting, or security boundaries.

## Cryptographic Operations

- **Cipher Algorithm**: Use AES-256-GCM authenticated encryption.
- **Nonce Generation**:
  - Nonces MUST be exactly 12 bytes.
  - Generate nonces using cryptographically secure random numbers from the Go standard library (`crypto/rand.Read`).
  - Never use deterministic, counter-based, or reusable nonces.
  - A fresh nonce must be generated for every encryption call.
- **Ciphertext Layout**:
  - The format of the output payload is: `[12-byte nonce][ciphertext][16-byte GCM auth tag]`.
  - Store and transmit ciphertexts as standard base64-encoded strings.
  - Before attempting decryption, validate that the ciphertext satisfies the minimum length requirements (at least 28 bytes for nonce and GCM auth tag).

## Key Lifecycle & Isolation

- **Two-Layer Key Hierarchy**:
  - **Key Encrypting Key (KEK)**: System-level root key. System keys must never leave the boundary of the `systemkey.Keyring` abstraction.
  - **Data Encrypting Key (DEK)**: Key used to encrypt actual data payloads. DEKs must always be stored encrypted at rest in the `keystore.KeyStore`.
  - **Plaintext Exposure**: DEKs should only exist in plaintext in memory during active encryption or decryption operations.
- **PII vs. Secrets Semantics**:
  - **PII Keys**: Used for personal data. They are ALWAYS fixed at version 1. PII keys do not support rotation. Instead, GDPR compliance is achieved through crypto-shredding.
  - **Secret Keys**: Used for system secrets. They support rotation, which creates a new key version. Older key versions are retained to decrypt historical payloads.
  - **Key Destruction**: The `DestroyKeys` operation must perform a hard delete (not a soft revoke or logical flag change) to ensure that the shredded data is permanently unrecoverable.

## Memory Hygiene

- **DEK Disposal**: Plaintext DEK bytes must be explicitly zeroed immediately after use. Always use `defer encryption.ZeroBytes(dek)` (or `encerr.ZeroBytes` in sub-packages) immediately after obtaining a plaintext DEK.
- **Exclusion of Secrets**: Never log, print, or expose raw key bytes or plaintexts.
- **Public API Boundary**: Never return raw key bytes in public API responses or struct fields exposed outside the library.

## Safe Error Handling

- **Sentinel Errors**: Rely on predefined errors in `errors.go` (e.g., `ErrKeyNotFound`, `ErrDecryption`).
- **Contextual Wrapping**: Wrap underlying errors using `fmt.Errorf("context: %w", err)` to maintain context.
- **No Leaks**: Ensure that no plaintext values or key material are included in error messages.
- **Decryption Failure Ambiguity**: Decryption failures should return a generic error and must not reveal details that distinguish between an incorrect key and data tampering (preventing side-channel attacks).
