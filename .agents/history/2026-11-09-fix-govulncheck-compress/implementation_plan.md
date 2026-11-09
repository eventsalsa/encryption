# Implementation Plan: Isolate `examples/` Module & Remediate GO-2026-6865

Decouple the `examples/` package tree into an isolated Go sub-module (`github.com/eventsalsa/encryption/examples`) so container tooling (`testcontainers-go` and its indirect dependencies) is separated from the core library.

## Proposed Changes

### Module Isolation
- Initialize `examples/go.mod` for `github.com/eventsalsa/encryption/examples` with a local replace directive (`replace github.com/eventsalsa/encryption => ../`).
- Revert the manual bump of `klauspost/compress` in root `go.mod` back to `v1.18.7` to prove the core library is untouched and clean.
- Update `examples/go.mod` with `klauspost/compress@v1.20.2` so the example harness is also vulnerability-free.

### Build & CI Tooling
- Update `Makefile`: Add `examples` to `SUBMODULES` and update config paths for `golangci-lint` and `gosec`.
- Update `.github/workflows/ci.yml`: Add `examples` module to `Vet`, `golangci-lint`, and `test` jobs.
- Update `.github/workflows/security.yml`: Add `examples` module to `gosec`, `govulncheck`, and `codeql` matrices/steps.
- Update `.github/dependabot.yml`: Add `/examples` directory for weekly Go module updates.

## Verification Plan

### Automated Checks
- Run `govulncheck ./... && govulncheck -C kek/awskms ./... && govulncheck -C kek/gcpkms ./... && govulncheck -C examples ./...`
- Run `make check`, `make build`, and `make test`.
