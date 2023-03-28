.PHONY: help
help: ## Show this help
	@grep -hE '^[A-Za-z0-9_ \-]*?:.*##.*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.EXPORT_ALL_VARIABLES:
CGO_ENABLED=0
GOPRIVATE=github.com/greenbone
GOOS=linux
GOARCH=amd64

tools: ## Install tools
ifeq (, $(shell which jq))
	sudo apt install jq
endif

run: ## Runs the keycloak mock server
	@go run .

cert: REALM=opensight-asset
cert: ## Obtain keycloak certificates
	@curl -s "http://localhost:8080/auth/realms/$(REALM)/protocol/openid-connect/certs"

token-resp: USER=initial
token-resp: REALM=opensight-asset
token-resp: CLIENT_ID=local-web
token-resp: ## Obtain token from mock server
	@curl -s \
		-d "client_id=$(CLIENT_ID)" \
		-d "grant_type=password" \
		-d "username=$(USER)" \
		-d "password=some_password" \
		"http://localhost:8080/auth/realms/$(REALM)/protocol/openid-connect/token"

token: USER=initial
token: REALM=opensight-asset
token: CLIENT_ID=local-web
token: tools ## Get and extract access token from mock keycloak
	@$(MAKE) -s token-resp USER=$(USER) REALM=$(REALM) CLIENT_ID=$(CLIENT_ID) | jq -r .access_token

token-decode: USER=initial
token-decode: REALM=opensight-asset
token-decode: CLIENT_ID=local-web
token-decode: tools ## Get decoded access token from mock keycloak
	@$(MAKE) -s token USER=$(USER) REALM=$(REALM) CLIENT_ID=$(CLIENT_ID) | cut -d. -f2 | base64 -d | jq

refresh: USER=initial
refresh: REALM=opensight-asset
refresh: CLIENT_ID=local-web
refresh: tools ## Get and extract refresh token from mock keycloak
	@$(MAKE) -s token-resp USER=$(USER) REALM=$(REALM) CLIENT_ID=$(CLIENT_ID) | jq -r .refresh_token

refresh-decode: USER=initial
refresh-decode: REALM=opensight-asset
refresh-decode: CLIENT_ID=local-web
refresh-decode: tools ## Get decoded refresh token from mock keycloak
	@$(MAKE) -s refresh USER=$(USER) REALM=$(REALM) CLIENT_ID=$(CLIENT_ID) | cut -d. -f2 | base64 -d | jq
