package auth

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"net/url"

	"github.com/golang-jwt/jwt/v4"
)

// KeycloakAuthorizer is used to validate if JWT has a correct signature and is valid and returns keycloak claims
type KeycloakAuthorizer struct {
	tokenIssuer string
	publicKey   *rsa.PublicKey
}

// NewKeycloakAuthorizer creates a new authorizer that checks if issuer is correct keycloak instance and realm and validates JWT signature with PEM formated public cert from keycloak
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

// ParseAuthorizationHeader parser an authorization header in format "BEARER JWT_TOKEN" where JWT_TOKEN is the keycloak auth token and returns UserContext with extracted token claims
func (a KeycloakAuthorizer) ParseAuthorizationHeader(authHeader string) (*UserContext, error) {
	token, err := parseAuthorizationHeader(authHeader)
	if err != nil {
		return nil, fmt.Errorf("error parsing header string: %w")
	}

	return a.ParseJWT(token)
}

// ParseJWT parses and validated JWT token and returns UserContext with extracted token claims
func (a KeycloakAuthorizer) ParseJWT(token string) (*UserContext, error) {
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
