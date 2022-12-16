package auth

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/golang-jwt/jwt/v4"
)

// KeycloakAuthorizer is used to validate if JWT has a correct signature and is valid and returns keycloak claims
type KeycloakAuthorizer struct {
	infoGetter RealmInfoGetter
	cache      bool
	cacheMap   map[string]KeycloakRealmInfo
}

// KeycloakRealmInfo provides keycloak realm and server information
type KeycloakRealmInfo struct {
	AuthServerUrl    string
	PEMPublicKeyCert string
	realm            string
	tokenIssuer      string
	publicKey        *rsa.PublicKey
}

func (i *KeycloakRealmInfo) validate(realm string) error {
	authUrl, err := url.ParseRequestURI(i.AuthServerUrl)
	if err != nil {
		return fmt.Errorf("couldn't parse auth server url: %w", err)
	}

	publicKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(i.PEMPublicKeyCert))
	if err != nil {
		return fmt.Errorf("couldn't parse rsa pubkey from pem cert: %w", err)
	}

	i.realm = realm
	i.publicKey = publicKey
	i.tokenIssuer = authUrl.JoinPath("/realms/" + realm).String()

	return nil
}

type RealmInfoGetter func(realm string) (KeycloakRealmInfo, error)

type KeycloakAuthorizerOption func(f *KeycloakAuthorizer)

func WithRealmInfoCache() KeycloakAuthorizerOption {
	return func(a *KeycloakAuthorizer) {
		a.cache = true
		a.cacheMap = make(map[string]KeycloakRealmInfo)
	}
}

// NewKeycloakAuthorizer creates a new authorizer that checks if issuer is correct keycloak instance and realm and validates JWT signature with PEM formated public cert from keycloak.
// It also checks if Origin header mathes allowed origins from the JWT. It works for multiple realms and caches the realm information if cache is enabled.
func NewKeycloakAuthorizer(infoGetter RealmInfoGetter, opts ...KeycloakAuthorizerOption) (*KeycloakAuthorizer, error) {
	if infoGetter == nil {
		return nil, errors.New("realm info getter cannot be nil")
	}

	authorizer := &KeycloakAuthorizer{
		infoGetter: infoGetter,
	}

	for _, opt := range opts {
		opt(authorizer)
	}

	return authorizer, nil
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
func (a *KeycloakAuthorizer) ParseRequest(authorizationHeader string, originHeader string) (*UserContext, error) {
	token, err := a.parseAuthorizationHeader(authorizationHeader)
	if err != nil {
		return nil, fmt.Errorf("couldn't parse authorization header: %w", err)
	}

	userCtx, err := a.ParseJWT(token)
	if err != nil {
		return nil, fmt.Errorf("couldn't parse token: %w", err)
	}

	correctOrigin := false
	for _, origin := range userCtx.allowedOrigins {
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
func (a *KeycloakAuthorizer) ParseAuthorizationHeader(authHeader string) (*UserContext, error) {
	token, err := a.parseAuthorizationHeader(authHeader)
	if err != nil {
		return nil, fmt.Errorf("couldn't parse header: %w", err)
	}

	userCtx, err := a.ParseJWT(token)
	if err != nil {
		return nil, fmt.Errorf("couldn't parse token: %w", err)
	}

	return userCtx, nil
}

// ParseJWT parses and validated JWT token and returns UserContext with extracted token claims
func (a *KeycloakAuthorizer) ParseJWT(token string) (*UserContext, error) {
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

	realmInfo, err := a.getRealmInfo(realm)
	if err != nil {
		return nil, fmt.Errorf("get realm info: %w", err)
	}

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
		allowedOrigins: claims.AllowedOrigins,
	}, nil
}

func (a *KeycloakAuthorizer) getRealmInfo(realm string) (*KeycloakRealmInfo, error) {
	if a.cache {
		if realmInfo, ok := a.cacheMap[realm]; ok {
			return &realmInfo, nil
		}
	}

	realmInfo, err := a.infoGetter(realm)
	if err != nil {
		return nil, fmt.Errorf("couldn't get info for realm: %w", err)
	}
	if err := realmInfo.validate(realm); err != nil {
		return nil, fmt.Errorf("invalid realm info: %w", err)
	}

	if a.cache {
		a.cacheMap[realm] = realmInfo
	}

	return &realmInfo, nil
}
