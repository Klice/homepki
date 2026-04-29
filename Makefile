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

.PHONY: dev
dev: ## wipe ./tmp/data, start the server, and seed CAs + leaves (uses scripts/dev-bootstrap.sh)
	scripts/dev-bootstrap.sh

.PHONY: dev-stop
dev-stop: ## stop the dev server started by `make dev` (kills the pid in tmp/homepki.pid)
	@if [ -f ./tmp/homepki.pid ]; then \
		pid=$$(cat ./tmp/homepki.pid); \
		if kill -0 $$pid 2>/dev/null; then \
			echo "stopping dev server (pid $$pid)"; \
			kill $$pid; \
		else \
			echo "no running process for pid $$pid"; \
		fi; \
		rm -f ./tmp/homepki.pid; \
	else \
		echo "no ./tmp/homepki.pid; nothing to stop"; \
	fi

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

.PHONY: generate
generate: ## run sqlc to regenerate internal/store/storedb (commit the result)
	sqlc generate

.PHONY: generate-check
generate-check: ## fail if generated code is stale relative to schema/queries
	sqlc diff

.PHONY: lint
lint: ## golangci-lint (devcontainer has it pre-installed)
	golangci-lint run

.PHONY: smoke
smoke: ## end-to-end smoke against a real binary (curl + openssl assertions)
	scripts/smoke.sh

.PHONY: image
image: ## build the production Docker image as homepki:dev
	docker build -t homepki:dev .

.PHONY: check
check: vet test ## quick local CI: vet + test

.PHONY: clean
clean: ## remove build artifacts and local data dir
	rm -rf $(BIN_DIR) tmp
