package auth

import (
	"context"

	"github.com/Nerzal/gocloak/v12"
	"github.com/golang-jwt/jwt/v4"
	"github.com/rs/zerolog/log"
)

type ITokenReceiver interface {
	GetAccessToken() (string, error)
	getToken() (*gocloak.JWT, error)
}

type KeycloakJWTCacheInMemory struct {
	keycloakJWTClient ITokenReceiver
	cachedToken       *gocloak.JWT
}

var _ ITokenReceiver = &KeycloakJWTCacheInMemory{}

func NewKeycloakJWTCacheInMemory(keycloakJWTClient ITokenReceiver) *KeycloakJWTCacheInMemory {
	return &KeycloakJWTCacheInMemory{
		keycloakJWTClient: keycloakJWTClient,
	}
}

func (k *KeycloakJWTCacheInMemory) isTokenValid() bool {
	if k.cachedToken == nil {
		return false
	}

	parser := jwt.NewParser()
	claims := &jwt.MapClaims{}

	_, _, err := parser.ParseUnverified(k.cachedToken.AccessToken, claims)
	if err != nil {
		return false
	}

	err = claims.Valid()
	if err != nil {
		log.Debug().Msgf("Token is invalid: %v", err)
		return false
	}

	return true
}

func (k *KeycloakJWTCacheInMemory) getToken() (*gocloak.JWT, error) {
	if k.cachedToken == nil || !k.isTokenValid() {
		token, err := k.keycloakJWTClient.getToken()
		if err != nil {
			return nil, err
		}
		k.cachedToken = token
		log.Debug().Msgf("updated token: %s", token.AccessToken)
	} else {
		log.Debug().Msgf("Using cached token: %s", k.cachedToken.AccessToken)
	}

	return k.cachedToken, nil
}

func (k *KeycloakJWTCacheInMemory) GetAccessToken() (string, error) {
	token, err := k.getToken()
	if err != nil {
		return "", err
	}

	return token.AccessToken, nil
}

type KeycloakJWTClient struct {
	client       *gocloak.GoCloak
	basePath     string
	clientName   string
	clientSecret string
	realm        string
}

var _ ITokenReceiver = &KeycloakJWTClient{}

func NewKeycloakJWTClient(basePath, clientName, clientSecret, realm string) *KeycloakJWTClient {
	return &KeycloakJWTClient{
		client:       gocloak.NewClient(basePath),
		basePath:     basePath,
		clientName:   clientName,
		clientSecret: clientSecret,
		realm:        realm,
	}
}

func (k *KeycloakJWTClient) getToken() (*gocloak.JWT, error) {
	token, err := k.client.LoginClient(context.Background(), k.clientName, k.clientSecret, k.realm)
	if err != nil {
		return nil, err
	}

	return token, nil
}

func (k *KeycloakJWTClient) GetAccessToken() (string, error) {
	token, err := k.getToken()
	if err != nil {
		return "", err
	}

	return token.AccessToken, nil
}
