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

	tokenIssuer, err := url.JoinPath(authUrl.String(), "/realms/"+realmId)
	if err != nil {
		return nil, fmt.Errorf("couldn't create valid token issuer: %w", err)
	}

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
		return nil, fmt.Errorf("header contains invalid number (%q) of fields", len(fields))
	}
	if strings.ToLower(fields[0]) != "bearer" {
		return nil, fmt.Errorf("header contains invalid token type %q", fields[0])
	}

	return a.ParseJWT(fields[1])
}

func (a KeycloakAuthorizer) ParseJWT(token string) (*UserContext, error) {
	type customClaims struct {
		jwt.RegisteredClaims
		PreferredUsername string   `json:"preferred_username"`
		Email             string   `json:"email"`
		UserId            string   `json:"sub"`
		Roles             []string `json:"Role"`
		Groups            []string `json:"Group"`
	}

	jwtToken, err := jwt.ParseWithClaims(token, &customClaims{}, func(*jwt.Token) (interface{}, error) {
		return a.publicKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("validation of token failed: %w", err)
	}
	if !jwtToken.Valid {
		return nil, fmt.Errorf("token is invalid")
	}
	if jwtToken.Header["alg"] == nil {
		return nil, fmt.Errorf("token alg must be defined")
	}

	claims, ok := jwtToken.Claims.(*customClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims type")
	}
	if claims.RegisteredClaims.Issuer != a.tokenIssuer {
		return nil, fmt.Errorf("invalid domain of issuer of token %q", claims.RegisteredClaims.Issuer)
	}

	return &UserContext{
		claims.PreferredUsername,
		claims.Email,
		claims.UserId,
		claims.Roles,
		claims.Groups,
	}, nil
}
