# homepki — common developer tasks.
# Override variables on the command line, e.g. `make run CM_DATA_DIR=/tmp/foo`.

BIN_DIR ?= bin
BIN     ?= $(BIN_DIR)/homepki
ENTRY   := ./cmd/homepki
PKG     := ./...

# Defaults for `make run` so the server starts without needing env files.
CRL_BASE_URL  ?= http://localhost:8080
CM_DATA_DIR   ?= ./tmp/data
CM_LOG_FORMAT ?= text

.DEFAULT_GOAL := help

.PHONY: help
help: ## list available targets
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: build
build: ## build the homepki binary into bin/
	@mkdir -p $(BIN_DIR)
	go build -o $(BIN) $(ENTRY)

.PHONY: run
run: ## run the server with dev-friendly env defaults
	CRL_BASE_URL=$(CRL_BASE_URL) CM_DATA_DIR=$(CM_DATA_DIR) CM_LOG_FORMAT=$(CM_LOG_FORMAT) go run $(ENTRY)

.PHONY: test
test: ## run unit tests with race detector (overrides CGO_ENABLED=0 for the run)
	CGO_ENABLED=1 go test -race -count=1 $(PKG)

.PHONY: vet
vet: ## go vet
	go vet $(PKG)

.PHONY: fmt
fmt: ## format Go sources
	gofmt -w -s .

.PHONY: tidy
tidy: ## go mod tidy
	go mod tidy

.PHONY: lint
lint: ## golangci-lint (devcontainer has it pre-installed)
	golangci-lint run

.PHONY: check
check: vet test ## quick local CI: vet + test

.PHONY: clean
clean: ## remove build artifacts and local data dir
	rm -rf $(BIN_DIR) tmp
