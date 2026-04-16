.PHONY: lint test test-integration vet build check fmt

## Run all checks (vet + test)
check: vet test

## Run go vet
vet:
	go vet ./...

## Run all tests with race detector
test:
	go test -race -count=1 ./...

## Run PostgreSQL integration tests (requires Docker)
test-integration:
	go test -race -count=1 -tags=integration ./keystore/postgres/

## Build all packages
build:
	go build ./...

## Check formatting (fails if files need formatting)
fmt:
	@test -z "$$(gofmt -l .)" || { gofmt -l .; echo "run gofmt to fix"; exit 1; }

## Run all linters and tests
lint: fmt vet
