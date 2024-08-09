# If you update this file, please follow:
# https://suva.sh/posts/well-documented-makefiles/

.DEFAULT_GOAL:=help

# binary versions
BIN_DIR ?= ./bin
GOLANGCI_VERSION ?= 1.59.1

GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)

##@ Help Targets

help:  ## Display this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[0m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Test Targets

.PHONY: test
test: static ## Run tests
	@mkdir -p _build/cov
	go test -covermode=atomic -coverpkg=./... -coverprofile cover.out ./... -timeout 120m

##@ Static Analysis Targets

static: fmt lint vet

fmt: ## Run go fmt against code
	go fmt ./...

lint: golangci-lint ## Run golangci-lint
	$(GOLANGCI_LINT) run

vet: ## Run go vet against code
	go vet ./...

##@ Tool & Binary Targets

golangci-lint:
	if ! test -f $(BIN_DIR)/golangci-lint-linux-amd64; then \
		curl -LOs https://github.com/golangci/golangci-lint/releases/download/v$(GOLANGCI_VERSION)/golangci-lint-$(GOLANGCI_VERSION)-linux-amd64.tar.gz; \
		tar -zxf golangci-lint-$(GOLANGCI_VERSION)-linux-amd64.tar.gz; \
		mv golangci-lint-$(GOLANGCI_VERSION)-*/golangci-lint $(BIN_DIR)/golangci-lint-linux-amd64; \
		chmod +x $(BIN_DIR)/golangci-lint-linux-amd64; \
		rm -rf ./golangci-lint-$(GOLANGCI_VERSION)-linux-amd64*; \
	fi
	if ! test -f $(BIN_DIR)/golangci-lint-$(GOOS)-$(GOARCH); then \
		curl -LOs https://github.com/golangci/golangci-lint/releases/download/v$(GOLANGCI_VERSION)/golangci-lint-$(GOLANGCI_VERSION)-$(GOOS)-$(GOARCH).tar.gz; \
		tar -zxf golangci-lint-$(GOLANGCI_VERSION)-$(GOOS)-$(GOARCH).tar.gz; \
		mv golangci-lint-$(GOLANGCI_VERSION)-*/golangci-lint $(BIN_DIR)/golangci-lint-$(GOOS)-$(GOARCH); \
		chmod +x $(BIN_DIR)/golangci-lint-$(GOOS)-$(GOARCH); \
		rm -rf ./golangci-lint-$(GOLANGCI_VERSION)-$(GOOS)-$(GOARCH)*; \
	fi
GOLANGCI_LINT=$(BIN_DIR)/golangci-lint-$(GOOS)-$(GOARCH)
