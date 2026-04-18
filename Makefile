.PHONY: build check fmt golangci govulncheck gosec lint test test-integration vet

## Run the full local check suite mirrored by CI and the security workflow.
check: fmt vet golangci test build test-integration gosec govulncheck

## Run go vet
vet:
	go vet ./...

## Run golangci-lint
golangci:
	golangci-lint run --timeout=5m

## Run all tests with race detector and coverage
test:
	tmp=$$(mktemp); \
	trap 'rm -f "$$tmp"' EXIT; \
	go test -race -count=1 -coverprofile="$$tmp" ./...

## Run integration-tagged tests (requires Docker when Postgres integration tests are present)
test-integration:
	go test -race -count=1 -tags=integration ./...

## Build all packages
build:
	go build ./...

## Check formatting (fails if files need formatting)
fmt:
	@test -z "$$(gofmt -l .)" || { gofmt -l .; echo "run gofmt to fix"; exit 1; }

## Run formatting, vet, and golangci-lint
lint: fmt vet golangci

## Run gosec with a temporary SARIF output file
gosec:
	tmp=$$(mktemp --suffix=.sarif); \
	trap 'rm -f "$$tmp"' EXIT; \
	gosec -no-fail -fmt sarif -out "$$tmp" ./...

## Run govulncheck
govulncheck:
	govulncheck ./...
