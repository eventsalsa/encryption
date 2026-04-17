# Changelog

## v0.0.2 - 2026-04-17

### Added

- Added `cmd/migrate-gen`, a stable CLI entrypoint for generating or printing the PostgreSQL encryption keystore migration.
- Added package helpers in `keystore/postgres/migrations` for rendering and writing migration SQL with `postgres.Config` schema and table overrides.

### Changed

- Updated the README to document the CLI-first migration flow and the package-based advanced alternative.

### Fixed

- Pinned the GitHub Actions gosec step to `securego/gosec@v2.25.0`, fixing workflow resolution failures caused by the missing `v2` ref.
