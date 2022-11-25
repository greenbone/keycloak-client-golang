package auth

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/golang-jwt/jwt/v4"
)

type KeycloakAuthorizer struct {
	tokenIssuer string
	publicKey   *rsa.PublicKey
}

func NewKeycloakAuthorizer(realmId string, authServerUrl string, pemPublicKeyCert string) (*KeycloakAuthorizer, error) {
	if realmId == "" {
		return nil, errors.New("realm id cannot be empty")
	}

	authUrl, err := url.ParseRequestURI(authServerUrl)
	if err != nil {
		return nil, fmt.Errorf("couldn't parse auth server url: %w", err)
	}
	tokenIssuer := authUrl.JoinPath("/realms/" + realmId).String()

	publicKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(pemPublicKeyCert))
	if err != nil {
		return nil, fmt.Errorf("couldn't parse rsa pubkey from pem cert: %w", err)
	}

	return &KeycloakAuthorizer{
		tokenIssuer: tokenIssuer,
		publicKey:   publicKey,
	}, nil
}

func (a KeycloakAuthorizer) ParseAuthorizationHeader(authHeader string) (*UserContext, error) {
	fields := strings.Fields(authHeader)
	if len(fields) != 2 {
		return nil, fmt.Errorf("header contains invalid number of fields: %d", len(fields))
	}
	if strings.ToLower(fields[0]) != "bearer" {
		return nil, fmt.Errorf("header contains invalid token type: %q", fields[0])
	}

	return a.ParseJWT(fields[1])
}

func (a KeycloakAuthorizer) ParseJWT(token string) (*UserContext, error) {
	type customClaims struct {
		jwt.RegisteredClaims
		UserId   string   `json:"sub"`
		Email    string   `json:"email"`
		UserName string   `json:"preferred_username"`
		Roles    []string `json:"roles"`
		Groups   []string `json:"groups"`
	}

	jwtToken, err := jwt.ParseWithClaims(token, &customClaims{}, func(*jwt.Token) (interface{}, error) {
		return a.publicKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("validation of token failed: %w", err)
	}

	claims := jwtToken.Claims.(*customClaims)
	if claims.RegisteredClaims.Issuer != a.tokenIssuer {
		return nil, fmt.Errorf("invalid domain of issuer of token %q", claims.RegisteredClaims.Issuer)
	}

	return &UserContext{
		KeycloakUserID: claims.UserId,
		UserName:       claims.UserName,
		EmailAddress:   claims.Email,
		Roles:          claims.Roles,
		Groups:         claims.Groups,
	}, nil
}