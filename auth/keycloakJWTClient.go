package auth

import (
	"context"
	"github.com/Nerzal/gocloak/v12"
	"github.com/golang-jwt/jwt/v4"
	"github.com/rs/zerolog/log"
	"time"
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

func (k *KeycloakJWTCacheInMemory) isTokenValid() (bool, error) {
	return true, nil
	parser := jwt.NewParser()

	claims := &jwt.MapClaims{}
	_, _, err := parser.ParseUnverified(k.cachedToken.AccessToken, claims)
	if err != nil {
		return false, err
	}

	return claims.VerifyExpiresAt(time.Now().Unix(), true), nil
}

func (k *KeycloakJWTCacheInMemory) getToken() (*gocloak.JWT, error) {
	var token *gocloak.JWT = k.cachedToken
	tokenIsValid, err := k.isTokenValid()
	if err != nil {
		return nil, err
	}

	log.Info().Msgf("tokenIsValid: %v", tokenIsValid)

	if k.cachedToken == nil || !tokenIsValid {
		var err error
		token, err = k.keycloakJWTClient.getToken()
		k.cachedToken = token
		log.Debug().Msgf("updated token: %s", token.AccessToken)
		if err != nil {
			return nil, err
		}
	} else {
		log.Debug().Msgf("Using cached token: %s", token.AccessToken)
	}

	return token, nil
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
