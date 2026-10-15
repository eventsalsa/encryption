.PHONY: build check fmt golangci govulncheck gosec lint test test-integration vet

SUBMODULES := kek/awskms kek/gcpkms

## Run the full local check suite mirrored by CI and the security workflow.
check: fmt vet golangci test build test-integration gosec govulncheck

## Run go vet across root module and sub-modules
vet:
	go vet ./...
	@for mod in $(SUBMODULES); do \
		go vet -C "$$mod" ./...; \
	done

## Run golangci-lint across root module and sub-modules
golangci:
	golangci-lint run --timeout=5m
	@for mod in $(SUBMODULES); do \
		(cd "$$mod" && golangci-lint run --config=../../.golangci.yml --timeout=5m); \
	done

## Run all tests with race detector and coverage across root module and sub-modules
test:
	tmp=$$(mktemp); \
	trap 'rm -f "$$tmp"' EXIT; \
	go test -race -count=1 -coverprofile="$$tmp" ./...
	@for mod in $(SUBMODULES); do \
		go test -C "$$mod" -race -count=1 ./...; \
	done

## Run integration-tagged tests (requires Docker when Postgres integration tests are present)
test-integration:
	go test -race -count=1 -tags=integration ./...

## Build all packages across root module and sub-modules
build:
	go build ./...
	@for mod in $(SUBMODULES); do \
		go build -C "$$mod" ./...; \
	done

## Check formatting (fails if files need formatting)
fmt:
	@test -z "$$(gofmt -l .)" || { gofmt -l .; echo "run gofmt to fix"; exit 1; }

## Run formatting, vet, and golangci-lint
lint: fmt vet golangci

## Run gosec with a temporary SARIF output file across root module and sub-modules
gosec:
	tmp=$$(mktemp --suffix=.sarif); \
	trap 'rm -f "$$tmp"' EXIT; \
	gosec -no-fail -exclude-dir=kek/awskms -exclude-dir=kek/gcpkms -fmt sarif -out "$$tmp" ./...
	@for mod in $(SUBMODULES); do \
		tmp=$$(mktemp --suffix=.sarif); \
		(cd "$$mod" && gosec -no-fail -fmt sarif -out "$$tmp" ./...); \
		rm -f "$$tmp"; \
	done

## Run govulncheck across root module and sub-modules
govulncheck:
	govulncheck ./...
	@for mod in $(SUBMODULES); do \
		govulncheck -C "$$mod" ./...; \
	done
