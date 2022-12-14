package auth

import (
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v4"
)

// KeycloakMultiAuthorizer is used to validate if JWT has a correct signature and is valid and returns keycloak claims
type KeycloakMultiAuthorizer struct {
	infoGetter RealmInfoGetter
}

// KeycloakRealmInfo provides keycloak realm and server information
type KeycloakRealmInfo struct {
	AuthServerUrl    string
	PEMPublicKeyCert string
}

type RealmInfoGetter func(realmId string) (KeycloakRealmInfo, error)

// NewKeycloakAuthorizerMultiRealm creates a new authorizer that checks if issuer is correct keycloak instance and realm and validates JWT signature with PEM formated public cert from keycloak.
// It also checks if Origin header mathes allowed origins from the JWT. It works for multiple realms and caches the realm information if cache is enabled,
func NewKeycloakAuthorizerMultiRealm(infoGetter RealmInfoGetter) (*KeycloakMultiAuthorizer, error) {
	if infoGetter == nil {
		return nil, errors.New("realm info getter cannot be nil")
	}

	return &KeycloakMultiAuthorizer{
		infoGetter: infoGetter,
	}, nil
}

// ParseAuthorizationHeader parser an authorization header in format "BEARER JWT_TOKEN" where JWT_TOKEN is the keycloak auth token and returns UserContext with extracted token claims
func (a KeycloakMultiAuthorizer) ParseAuthorizationHeader(authHeader string) (*UserContext, error) {
	token, err := parseAuthorizationHeader(authHeader)
	if err != nil {
		return nil, fmt.Errorf("error parsing header string: %w")
	}

	return a.ParseJWT(token)
}

// ParseJWT parses and validated JWT token and returns UserContext with extracted token claims
func (a KeycloakMultiAuthorizer) ParseJWT(token string) (*UserContext, error) {
	jwtToken, err := jwt.ParseWithClaims(token, &customClaims{}, nil)
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
