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

GOTESTSUM       = go run gotest.tools/gotestsum@latest
GOFUMPT         = go run mvdan.cc/gofumpt@latest
GOIMPORTS       = go run golang.org/x/tools/cmd/goimports@latest
GOLANGCI-LINT   = go run github.com/golangci/golangci-lint/cmd/golangci-lint@latest
GO-MOD-OUTDATED = go run github.com/psampaz/go-mod-outdated@latest
GO-MOD-UPGRADE  = go run github.com/oligot/go-mod-upgrade@latest

all: lint test build

test: ## Run all tests
	go test ./...

test-alt: ## Run all tests
	@$(GOTESTSUM) -f dots-v2

watch: ## Run tests and watch for changes
	@$(GOTESTSUM) -f dots-v2; $(GOTESTSUM) -f dots-v2 --watch

cover: ## Run cover
	go test -cover ./...

lint: ## Lint go code
	$(GOLANGCI-LINT) run

format: ## Format and tidy
	go mod tidy && $(GOIMPORTS) -l -w .

format-gofumpt: ## Format with gofumpt
	go mod tidy && $(GOFUMPT) -l -w .

update: ## Update go dependencies
	go get -u -t ./... && go mod tidy

list-outdated: ## List outdated mods
	go list -u -f '{{if (and (not (or .Main .Indirect)) .Update)}}{{.Path}}: {{.Version}} -> {{.Update.Version}}{{end}}' -m all 2> /dev/null

outdated: ## Show outdated go dependencies
	go list -u -m -json all | $(GO-MOD-OUTDATED) -update -direct

upgrade: ## Interactive go module upgrade
	$(GO-MOD-UPGRADE)

.PHONY: build
build: ## Build go application
	go build -trimpath ./...
