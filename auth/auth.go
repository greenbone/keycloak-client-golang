// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-3.0-or-later

package auth

import (
	"context"
	"errors"
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
	AuthServerInternalUrl string // AuthServerInternalUrl should point to keycloak auth server on internal (not public) network, e.g. http://keycloak:8080/auth; used for contacting keycloak for realm certificate for JWT
	AuthServerPublicUrl   string // AuthServerPublicUrl should point to keycloak auth server on public (not internal) network, e.g. http://localhost:28080/auth; used to validate issuer field in JWT
}

func (i *KeycloakRealmInfo) validate() error {
	var errs []error

	if i.RealmId == "" {
		errs = append(errs, fmt.Errorf("realm id cannot be empty"))
	}

	_, err := url.ParseRequestURI(i.AuthServerInternalUrl)
	if err != nil {
		errs = append(errs, fmt.Errorf("couldn't parse auth server internal url: %w", err))
	}

	_, err = url.ParseRequestURI(i.AuthServerPublicUrl)
	if err != nil {
		errs = append(errs, fmt.Errorf("couldn't parse auth server public url: %w", err))
	}

	if len(errs) > 0 {
		return fmt.Errorf("\n%w", errors.Join(errs...))
	}

	return nil
}

// NewKeycloakAuthorizer creates a new authorizer that checks if issuer is correct keycloak instance and realm and validates JWT signature with public cert from keycloak.
// It also checks if Origin header mathes allowed origins from the JWT.
func NewKeycloakAuthorizer(realmInfo KeycloakRealmInfo, options ...func(*KeycloakAuthorizer)) (*KeycloakAuthorizer, error) {
	if err := realmInfo.validate(); err != nil {
		return nil, fmt.Errorf("invalid realm info: %w", err)
	}

	client := gocloak.NewClient(realmInfo.AuthServerInternalUrl)

	authorizer := &KeycloakAuthorizer{
		realmInfo: realmInfo,
		client:    client,
	}

	for _, o := range options {
		o(authorizer)
	}

	return authorizer, nil
}

func ConfigureGoCloak(f func(c *gocloak.GoCloak)) func(a *KeycloakAuthorizer) {
	return func(a *KeycloakAuthorizer) {
		f(a.client)
	}
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

// ParseRequest parses a request (Authorization header - required; Origin header - optional), validates JWT and returns UserContext with extracted token claims
func (a *KeycloakAuthorizer) ParseRequest(ctx context.Context, authorizationHeader string, originHeader string) (UserContext, error) {
	token, err := a.parseAuthorizationHeader(authorizationHeader)
	if err != nil {
		return UserContext{}, fmt.Errorf("couldn't parse authorization header: %w", err)
	}

	userCtx, err := a.ParseJWT(ctx, token)
	if err != nil {
		return UserContext{}, fmt.Errorf("couldn't parse token: %w", err)
	}

	if originHeader != "" {
		correctOrigin := false
		for _, origin := range userCtx.AllowedOrigins {
			if originHeader == origin {
				correctOrigin = true
				break
			}
		}
		if !correctOrigin {
			return UserContext{}, fmt.Errorf("not allowed origin: %s", originHeader)
		}
	}

	return userCtx, nil
}

// ParseAuthorizationHeader parser an authorization header in format "BEARER JWT_TOKEN" where JWT_TOKEN is the keycloak auth token and returns UserContext with extracted token claims
func (a *KeycloakAuthorizer) ParseAuthorizationHeader(ctx context.Context, authHeader string) (UserContext, error) {
	token, err := a.parseAuthorizationHeader(authHeader)
	if err != nil {
		return UserContext{}, fmt.Errorf("couldn't parse header: %w", err)
	}

	userCtx, err := a.ParseJWT(ctx, token)
	if err != nil {
		return UserContext{}, fmt.Errorf("couldn't parse token: %w", err)
	}

	return userCtx, nil
}

// ParseJWT parses and validated JWT token and returns UserContext with extracted token claims
func (a *KeycloakAuthorizer) ParseJWT(ctx context.Context, token string) (UserContext, error) {
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
		return UserContext{}, fmt.Errorf("parsing of token failed: %w", err)
	}
	claims := jwtToken.Claims.(*customClaims)

	if _, _, err := a.client.DecodeAccessToken(ctx, token, a.realmInfo.RealmId); err != nil {
		return UserContext{}, fmt.Errorf("validation of token failed: %w", err)
	}

	return UserContext{
		Realm:          a.realmInfo.RealmId,
		UserID:         claims.UserId,
		UserName:       claims.UserName,
		EmailAddress:   claims.Email,
		Roles:          claims.Roles,
		Groups:         claims.Groups,
		AllowedOrigins: claims.AllowedOrigins,
	}, nil
}
