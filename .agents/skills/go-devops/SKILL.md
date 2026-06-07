---
name: go-devops
description: CI/CD, Go linting, vulnerability checking, and GitHub Actions workflow maintenance.
---

# Go DevOps & CI/CD Guidelines

Use this skill when managing GitHub Actions workflows, linting configurations, dependency update policies, or security scanning pipelines for the project.

## CI Workflow (`.github/workflows/ci.yml`)

The integration pipeline runs on push to `main` and on all pull requests. It comprises the following steps:
1. **Format Check**: Run `gofmt -l .` and `goimports -l .` to verify formatting.
2. **Static Analysis (Vet)**: Run `go vet ./...`.
3. **Linter Suite**: Execute `golangci-lint run --timeout=5m`.
4. **Test Suite**: Run tests with race detection and coverage output:
   ```bash
   go test -race -count=1 -coverprofile=coverage.out ./...
   ```
5. **Coverage Reporting**: Upload the coverage profile as a build artifact.

When modifying workflows, use `actions/checkout@v4`, `actions/setup-go@v5`, and `golangci/golangci-lint-action@v6`.

## Security Workflow (`.github/workflows/security.yml`)

The security pipeline runs on push to `main`, PRs, and a weekly cron schedule (`0 6 * * 1`). It covers:
1. **gosec**: Run `securego/gosec` to generate a SARIF report, uploading the results to the GitHub Security tab.
2. **govulncheck**: Run `golang.org/x/vuln/cmd/govulncheck@latest` to scan against the Go vulnerability database.
3. **CodeQL**: Run standard GitHub semantic analysis for Go.

## Linting Configuration (`.golangci.yml`)

Maintain strict linting standards tailored for a security-critical Go library. The following linters must remain enabled:
- `gosec` — cryptographic safety and secure coding practices
- `govet` — standard suspicious constructs
- `staticcheck` — advanced static analysis checks
- `errcheck` — checking for unhandled error returns
- `ineffassign` — identifying ineffective assignments
- `unused` — dead code detection
- `gocritic` — style, performance, and safety checks
- `revive` — general Go linting rules
- `bodyclose` — HTTP/SQL resource leakage checks
- `noctx` — HTTP request context check
- `exhaustive` — comprehensive enum switch cases
- `prealloc` — slice preallocation optimization suggestions
- `misspell` — typo detection

The linting execution timeout must be set to 5 minutes, targeting Go 1.24.

## Dependency Updates (`.github/dependabot.yml`)

- **Ecosystems**: Manage both Go modules (`gomod`) and GitHub Actions (`github-actions`).
- **Schedule**: Configure weekly updates.
- **Grouping**: Group minor and patch updates together to minimize pull request noise.

## Pipelines & Action Conventions

- **Version Pinning**: Pin GitHub Actions to their major versions (e.g., `@v4`, `@v5`).
- **Race Detection**: Always include the `-race` flag for testing, as concurrent cipher operations depend on thread safety.
- **Vulnerability Reporting**: Export scan outputs to the GitHub Security tab via SARIF where supported.
- **Concurrency Control**: Use concurrency groups in GitHub Actions to cancel redundant workflow runs on active PRs.
