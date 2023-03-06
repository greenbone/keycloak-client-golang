PROJECT := user-management-api
GIT_COMMIT := $(shell git rev-list -1 HEAD)

.PHONY: help
help: ## Show this help
	@grep -hE '^[A-Za-z0-9_ \-]*?:.*##.*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.EXPORT_ALL_VARIABLES:
CGO_ENABLED=0
GOPRIVATE=github.com/greenbone
GOOS=linux
GOARCH=amd64

all: lint test build

test: ## Run all tests
	go test -v ./...

cover: ## Run cover
	go test -cover ./... 

lint: ## Lint go code
	golangci-lint run

format: ## Format and tidy
	go mod tidy && go fmt ./...

update: ## Update go dependencies
	go get -u -t ./... && go mod tidy

outdated: ## Show outdated go dependencies
ifeq (, $(shell which go-mod-outdated))
	go install github.com/psampaz/go-mod-outdated@latest
endif
	go list -u -m -json all | go-mod-outdated -update -direct

.PHONY: tools
tools: ## Install tools
ifeq (, $(shell which golangci-lint))
	brew install golangci-lint
endif
	brew upgrade golangci-lint

.PHONY: build
build: ## Build go application
	go build -trimpath ./...
