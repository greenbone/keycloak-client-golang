.PHONY: help
help: ## Show this help
	@grep -hE '^[A-Za-z0-9_ \-]*?:.*##.*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.EXPORT_ALL_VARIABLES:
CGO_ENABLED=0
GOPRIVATE=github.com/greenbone
GOOS=linux
GOARCH=amd64

run: ## Runs the keycloak mock server
	@go run .

token: ## Obtain token from mock server
	@curl -s \
		-d "client_id=local-web" \
		-d "grant_type=password" \
		-d "username=initial" \
		-d "password=password" \
		"http://localhost:3333/auth/realms/opensight-asset/protocol/openid-connect/token"