package auth

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/Nerzal/gocloak/v12"
	"github.com/golang-jwt/jwt/v4"
)

// KeycloakAuthorizer is used to validate if JWT has a correct signature and is valid and returns keycloak claims
type KeycloakAuthorizer struct {
	realmInfo KeycloakRealmInfo
	client    *gocloak.GoCloak
}

// KeycloakRealmInfo provides keycloak realm and server information
type KeycloakRealmInfo struct {
	RealmId               string // RealmId is the realm name that is passed to services via env vars
	AuthServerInternalUrl string // AuthServerInternalUrl should point to keycloak auth server on internal (not public) network, e.g. http://keycloak:8080/auth
	tokenIssuer           string
}

func (i *KeycloakRealmInfo) validate() error {
	if i.RealmId == "" {
		return fmt.Errorf("realm id cannot be empty")
	}

	authUrl, err := url.ParseRequestURI(i.AuthServerInternalUrl)
	if err != nil {
		return fmt.Errorf("couldn't parse auth server url: %w", err)
	}

	i.tokenIssuer = authUrl.JoinPath("/realms/" + i.RealmId).String()

	return nil
}

// NewKeycloakAuthorizer creates a new authorizer that checks if issuer is correct keycloak instance and realm and validates JWT signature with public cert from keycloak.
// It also checks if Origin header mathes allowed origins from the JWT.
func NewKeycloakAuthorizer(realmInfo KeycloakRealmInfo) (*KeycloakAuthorizer, error) {
	if err := realmInfo.validate(); err != nil {
		return nil, fmt.Errorf("invalid realm info: %w", err)
	}

	client := gocloak.NewClient(realmInfo.AuthServerInternalUrl)

	return &KeycloakAuthorizer{
		realmInfo: realmInfo,
		client:    client,
	}, nil
}

func (a *KeycloakAuthorizer) parseAuthorizationHeader(authorizationHeader string) (string, error) {
	fields := strings.Fields(authorizationHeader)
	if len(fields) != 2 {
		return "", fmt.Errorf("header contains invalid number of fields: %d", len(fields))
	}
	if strings.ToLower(fields[0]) != "bearer" {
		return "", fmt.Errorf("header contains invalid token type: %q", fields[0])
	}
	return fields[1], nil
}

// ParseRequest parses a request (authorization header and origin of the call), validates JWT and returns UserContext with extracted token claims
func (a *KeycloakAuthorizer) ParseRequest(ctx context.Context, authorizationHeader string, originHeader string) (*UserContext, error) {
	token, err := a.parseAuthorizationHeader(authorizationHeader)
	if err != nil {
		return nil, fmt.Errorf("couldn't parse authorization header: %w", err)
	}

	userCtx, err := a.ParseJWT(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("couldn't parse token: %w", err)
	}

	correctOrigin := false
	for _, origin := range userCtx.AllowedOrigins {
		if originHeader == origin {
			correctOrigin = true
			break
		}
	}
	if !correctOrigin {
		return nil, fmt.Errorf("not allowed origin: %s", originHeader)
	}

	return userCtx, nil
}

// ParseAuthorizationHeader parser an authorization header in format "BEARER JWT_TOKEN" where JWT_TOKEN is the keycloak auth token and returns UserContext with extracted token claims
func (a *KeycloakAuthorizer) ParseAuthorizationHeader(ctx context.Context, authHeader string) (*UserContext, error) {
	token, err := a.parseAuthorizationHeader(authHeader)
	if err != nil {
		return nil, fmt.Errorf("couldn't parse header: %w", err)
	}

	userCtx, err := a.ParseJWT(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("couldn't parse token: %w", err)
	}

	return userCtx, nil
}

// ParseJWT parses and validated JWT token and returns UserContext with extracted token claims
func (a *KeycloakAuthorizer) ParseJWT(ctx context.Context, token string) (*UserContext, error) {
	type customClaims struct {
		jwt.RegisteredClaims
		UserId         string   `json:"sub"`
		Email          string   `json:"email"`
		UserName       string   `json:"preferred_username"`
		Roles          []string `json:"roles"`
		Groups         []string `json:"groups"`
		AllowedOrigins []string `json:"allowed-origins"`
	}

	jwtToken, _, err := jwt.NewParser().ParseUnverified(token, &customClaims{})
	if err != nil {
		return nil, fmt.Errorf("parsing of token failed: %w", err)
	}
	claims := jwtToken.Claims.(*customClaims)

	parts := strings.Split(claims.RegisteredClaims.Issuer, "/")
	realm := parts[len(parts)-1]
	if realm == "" {
		return nil, fmt.Errorf("token doesn't contain realm info")
	}

	cc := customClaims{}
	a.client.DecodeAccessTokenCustomClaims(ctx, token, a.realmInfo.RealmId, &cc)

	// realmInfo, err := a.getRealmInfo(realm)
	// if err != nil {
	// 	return nil, fmt.Errorf("get realm info: %w", err)
	// }

	_, err = jwt.Parse(token, func(*jwt.Token) (interface{}, error) {
		return realmInfo.publicKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("validation of token failed: %w", err)
	}

	if claims.RegisteredClaims.Issuer != realmInfo.tokenIssuer {
		return nil, fmt.Errorf("invalid domain of issuer of token %q", claims.RegisteredClaims.Issuer)
	}

	return &UserContext{
		Realm:          realm,
		UserID:         claims.UserId,
		UserName:       claims.UserName,
		EmailAddress:   claims.Email,
		Roles:          claims.Roles,
		Groups:         claims.Groups,
		AllowedOrigins: claims.AllowedOrigins,
	}, nil
}
