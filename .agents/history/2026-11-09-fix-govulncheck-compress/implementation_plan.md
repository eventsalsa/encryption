# Implementation Plan: Remediate GO-2026-6865 in govulncheck

Upgrade indirect dependency `github.com/klauspost/compress` to `v1.20.2` to resolve vulnerability `GO-2026-6865` / `GHSA-fpmh-frq8-7rj8` causing the scheduled `Security` workflow run to fail.

## Proposed Changes

### Dependencies
- Upgrade `github.com/klauspost/compress` from `v1.18.7` to `v1.20.2` in `go.mod` and `go.sum`.
- Run `go mod tidy` to clean up checksums and indirect dependency annotations.

## Verification Plan

### Automated Tests
- Run `govulncheck ./... && govulncheck -C kek/awskms ./... && govulncheck -C kek/gcpkms ./...` to verify zero reachable vulnerabilities.
- Run `make check` (go vet, golangci-lint, unit tests with race detector, integration tests, gosec, govulncheck).
- Run `make build` and `make test`.
