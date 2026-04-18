# Changelog

## v0.0.3 - 2026-04-18

### Added

- Added `(*postgres.Store).RewrapSystemKeys`, a PostgreSQL administrative API for re-encrypting stored DEKs from one system key ID to another in short batches, with dry-run support and progress counters.

### Changed

- Updated the README to document the PostgreSQL system-key rewrap workflow, including the recommended operator sequence and why rewrap remains a library API instead of a built-in CLI.
- Expanded PostgreSQL coverage for system-key rewrap option validation, dry runs, idempotency, concurrent runs, and historical ciphertext decryptability after retiring the old key.
- Expanded `make check` into the full truthful local validation suite and widened integration-tagged test coverage to `go test -race -count=1 -tags=integration ./...`.
- Clarified repository contributor context so `make check` matches the locally runnable required checks, with GitHub-only CodeQL called out separately.

## v0.0.2 - 2026-04-17

### Added

- Added `cmd/migrate-gen`, a stable CLI entrypoint for generating or printing the PostgreSQL encryption keystore migration.
- Added package helpers in `keystore/postgres/migrations` for rendering and writing migration SQL with `postgres.Config` schema and table overrides.

### Changed

- Updated the README to document the CLI-first migration flow and the package-based advanced alternative.

### Fixed

- Pinned the GitHub Actions gosec step to `securego/gosec@v2.25.0`, fixing workflow resolution failures caused by the missing `v2` ref.
