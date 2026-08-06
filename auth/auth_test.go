// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"context"
	"fmt"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewKeycloakAuthorizer(t *testing.T) {
	t.Run("Empty realm id", func(t *testing.T) {
		authorizer, err := NewKeycloakAuthorizer(KeycloakRealmInfo{})

		assert.ErrorContains(t, err, "invalid realm info")
		assert.ErrorContains(t, err, "realm id cannot be empty")
		assert.ErrorContains(t, err, "couldn't parse auth server internal url")
		assert.Nil(t, authorizer)
	})

	t.Run("Invalid auth url", func(t *testing.T) {
		tests := []string{
			"",
			"invalid-url",
			":///invalid@:",
			"http:// - ",
		}
		t.Run("internal", func(t *testing.T) {
			for _, test := range tests {
				t.Run("internal url "+test, func(t *testing.T) {
					authorizer, err := NewKeycloakAuthorizer(KeycloakRealmInfo{
						AuthServerInternalUrl: test,
						RealmId:               validRealm,
						AuthServerPublicUrl:   validPublicUrl,
					})

					assert.ErrorContains(t, err, "invalid realm info")
					assert.ErrorContains(t, err, "couldn't parse auth server internal url")
					assert.Nil(t, authorizer)
				})
				t.Run("public url "+test, func(t *testing.T) {
					authorizer, err := NewKeycloakAuthorizer(KeycloakRealmInfo{
						AuthServerPublicUrl:   test,
						RealmId:               validRealm,
						AuthServerInternalUrl: validInternalUrl,
					})

					assert.ErrorContains(t, err, "invalid realm info")
					assert.ErrorContains(t, err, "couldn't parse auth server public url")
					assert.Nil(t, authorizer)
				})
			}
		})
	})

	t.Run("OK", func(t *testing.T) {
		authorizer, err := NewKeycloakAuthorizer(KeycloakRealmInfo{
			RealmId:               validRealm,
			AuthServerInternalUrl: validInternalUrl,
			AuthServerPublicUrl:   validPublicUrl,
		})

		assert.NoError(t, err)
		assert.NotNil(t, authorizer)
	})
}

func TestParseJWT(t *testing.T) {
	tokenIssuer, err := NewTokenIssuer(publicKeyALG, publicKeyID)
	require.NoError(t, err)
	authServer := FakeAuthServer(t, tokenIssuer)

	authorizer, err := NewKeycloakAuthorizer(KeycloakRealmInfo{
		RealmId:               validRealm,
		AuthServerInternalUrl: authServer.URL,
		AuthServerPublicUrl:   validPublicUrl,
	},
		WithValidMethods("RS256"),
		WithAudience(validAudience, "other valid audience"),
	)
	require.NoError(t, err)
	require.NotNil(t, authorizer)

	t.Run("Wrong algorithm", func(t *testing.T) {
		token := tokenIssuer.GetTokenWithAlg(t, jwt.SigningMethodHS256.Alg(), validClaims())

		userContext, err := authorizer.ParseJWT(context.Background(), token)

		assert.ErrorContains(t, err, "invalid token signing method")
		assert.Zero(t, userContext)
	})

	t.Run("Wrong signature", func(t *testing.T) {
		token := tokenIssuer.GetToken(t, jwt.MapClaims{
			"iss": validPublicUrl + "/realms/" + validRealm,
		})
		token += "XX" // malformed signature

		userContext, err := authorizer.ParseJWT(context.Background(), token)

		assert.ErrorContains(t, err, "validation of token failed")
		assert.ErrorContains(t, err, "crypto/rsa: verification error")
		assert.Zero(t, userContext)
	})

	t.Run("Expired token", func(t *testing.T) {
		claims := validClaims()
		claims["exp"] = 1500000000
		token := tokenIssuer.GetToken(t, claims)

		userContext, err := authorizer.ParseJWT(context.Background(), token)

		assert.ErrorContains(t, err, "token has invalid claims")
		assert.ErrorContains(t, err, "token is expired")
		assert.Zero(t, userContext)
	})

	t.Run("missing expiration", func(t *testing.T) {
		claims := validClaims()
		delete(claims, "exp")
		token := tokenIssuer.GetToken(t, claims)

		userContext, err := authorizer.ParseJWT(context.Background(), token)

		assert.ErrorContains(t, err, "validation of token claims failed")
		assert.ErrorContains(t, err, "exp claim is required")
		assert.Zero(t, userContext)
	})

	t.Run("invalid issuedAt", func(t *testing.T) {
		claims := validClaims()
		claims["iat"] = 9999999999
		token := tokenIssuer.GetToken(t, claims)

		userContext, err := authorizer.ParseJWT(context.Background(), token)

		assert.ErrorContains(t, err, "validation of token claims failed")
		assert.ErrorContains(t, err, "token used before issued")
		assert.Zero(t, userContext)
	})

	t.Run("Wrong issuer", func(t *testing.T) {
		claims := validClaims()
		claims["iss"] = "invalid_issuer"
		token := tokenIssuer.GetToken(t, claims)

		userContext, err := authorizer.ParseJWT(context.Background(), token)

		assert.ErrorContains(t, err, "validation of token claims failed")
		assert.ErrorContains(t, err, "token has invalid issuer")
		assert.Zero(t, userContext)
	})

	t.Run("Missing subject", func(t *testing.T) {
		claims := validClaims()
		delete(claims, "sub")
		token := tokenIssuer.GetToken(t, claims)

		userContext, err := authorizer.ParseJWT(context.Background(), token)

		assert.ErrorContains(t, err, "validation of token claims failed")
		assert.ErrorContains(t, err, "missing subject claim")
		assert.Zero(t, userContext)
	})

	t.Run("Wrong audience", func(t *testing.T) {
		claims := validClaims()
		claims["aud"] = "invalid_audience"
		token := tokenIssuer.GetToken(t, claims)

		userContext, err := authorizer.ParseJWT(context.Background(), token)

		assert.ErrorContains(t, err, "validation of token claims failed")
		assert.ErrorContains(t, err, "token has invalid audience")
		assert.Zero(t, userContext)
	})

	t.Run("Invalid claims", func(t *testing.T) {
		claims := validClaims()
		claims["email"] = 12345
		claims["roles"] = 1
		claims["groups"] = 2
		token := tokenIssuer.GetToken(t, claims)

		userContext, err := authorizer.ParseJWT(context.Background(), token)

		assert.ErrorContains(t, err, "parsing of token failed")
		assert.ErrorContains(t, err, "cannot unmarshal number")
		assert.Zero(t, userContext)
	})

	t.Run("OK", func(t *testing.T) {
		token := tokenIssuer.GetToken(t, validClaims())

		userContext, err := authorizer.ParseJWT(context.Background(), token)

		require.NoError(t, err)
		require.NotZero(t, userContext)

		assert.Equal(t, "user-management", userContext.Realm)
		assert.Equal(t, "1927ed8a-3f1f-4846-8433-db290ea5ff90", userContext.UserID)
		assert.Equal(t, "initial@host.local", userContext.EmailAddress)
		assert.Equal(t, "initial", userContext.UserName)
		assert.ElementsMatch(t, []string{"offline_access", "uma_authorization", "user", "default-roles-user-management"}, userContext.Roles)
		assert.ElementsMatch(t, []string{"user-management-initial"}, userContext.Groups)
		assert.ElementsMatch(t, []string{validOrigin}, userContext.AllowedOrigins)
	})
}

func TestParseAuthorizationHeader(t *testing.T) {
	tokenIssuer, err := NewTokenIssuer(publicKeyALG, publicKeyID)
	require.NoError(t, err)
	authServer := FakeAuthServer(t, tokenIssuer)
	validToken := tokenIssuer.GetToken(t, validClaims())

	authorizer, err := NewKeycloakAuthorizer(KeycloakRealmInfo{
		RealmId:               validRealm,
		AuthServerInternalUrl: authServer.URL,
		AuthServerPublicUrl:   validPublicUrl,
	})
	require.NoError(t, err)
	require.NotNil(t, authorizer)

	t.Run("Invalid fields", func(t *testing.T) {
		tests := []string{
			"",
			"one_field",
			"too many fields",
		}
		for _, test := range tests {
			t.Run(test, func(t *testing.T) {
				userContext, err := authorizer.ParseAuthorizationHeader(context.Background(), test)

				assert.ErrorContains(t, err, "header contains invalid number of fields")
				assert.Zero(t, userContext)
			})
		}
	})

	t.Run("Invalid token type", func(t *testing.T) {
		userContext, err := authorizer.ParseAuthorizationHeader(context.Background(), "not_bearer some_token")

		assert.ErrorContains(t, err, "header contains invalid token type")
		assert.Zero(t, userContext)
	})

	t.Run("Invalid token", func(t *testing.T) {
		expiredClaims := validClaims()
		expiredClaims["exp"] = 1500000000
		expiredToken := tokenIssuer.GetToken(t, expiredClaims)

		userContext, err := authorizer.ParseAuthorizationHeader(context.Background(), "bearer "+expiredToken)

		assert.ErrorContains(t, err, "validation of token failed")
		assert.Zero(t, userContext)
	})

	t.Run("OK", func(t *testing.T) {
		userContext, err := authorizer.ParseAuthorizationHeader(context.Background(), fmt.Sprintf("bearer %s", validToken))
		require.NoError(t, err)
		require.NotZero(t, userContext)

		assert.Equal(t, "user-management", userContext.Realm)
		assert.Equal(t, "1927ed8a-3f1f-4846-8433-db290ea5ff90", userContext.UserID)
		assert.Equal(t, "initial@host.local", userContext.EmailAddress)
		assert.Equal(t, "initial", userContext.UserName)
		assert.ElementsMatch(t, []string{"offline_access", "uma_authorization", "user", "default-roles-user-management"}, userContext.Roles)
		assert.ElementsMatch(t, []string{"user-management-initial"}, userContext.Groups)
	})
}

func TestParseRequest(t *testing.T) {
	tokenIssuer, err := NewTokenIssuer(publicKeyALG, publicKeyID)
	require.NoError(t, err)
	authServer := FakeAuthServer(t, tokenIssuer)
	validToken := tokenIssuer.GetToken(t, validClaims())

	authorizer, err := NewKeycloakAuthorizer(KeycloakRealmInfo{
		RealmId:               validRealm,
		AuthServerInternalUrl: authServer.URL,
		AuthServerPublicUrl:   validPublicUrl,
	})
	require.NoError(t, err)
	require.NotNil(t, authorizer)

	t.Run("Invalid authorization header", func(t *testing.T) {
		userContext, err := authorizer.ParseRequest(context.Background(), "invalid", validOrigin)

		assert.ErrorContains(t, err, "couldn't parse authorization header")
		assert.Zero(t, userContext)
	})

	t.Run("Invalid token", func(t *testing.T) {
		userContext, err := authorizer.ParseRequest(context.Background(), "bearer invalid_token", validOrigin)

		assert.ErrorContains(t, err, "couldn't parse token")
		assert.Zero(t, userContext)
	})

	t.Run("Invalid origin", func(t *testing.T) {
		userContext, err := authorizer.ParseRequest(context.Background(), fmt.Sprintf("bearer %s", validToken), "http://invalid-origin.com")

		assert.ErrorContains(t, err, "not allowed origin")
		assert.Zero(t, userContext)
	})

	t.Run("OK without origin", func(t *testing.T) {
		userContext, err := authorizer.ParseRequest(context.Background(), fmt.Sprintf("bearer %s", validToken), "")
		require.NoError(t, err)
		require.NotZero(t, userContext)

		assert.Equal(t, "user-management", userContext.Realm)
		assert.Equal(t, "1927ed8a-3f1f-4846-8433-db290ea5ff90", userContext.UserID)
		assert.Equal(t, "initial@host.local", userContext.EmailAddress)
		assert.Equal(t, "initial", userContext.UserName)
		assert.ElementsMatch(t, []string{"offline_access", "uma_authorization", "user", "default-roles-user-management"}, userContext.Roles)
		assert.ElementsMatch(t, []string{"user-management-initial"}, userContext.Groups)
	})

	t.Run("OK", func(t *testing.T) {
		userContext, err := authorizer.ParseRequest(context.Background(), fmt.Sprintf("bearer %s", validToken), validOrigin)
		require.NoError(t, err)
		require.NotZero(t, userContext)

		assert.Equal(t, "user-management", userContext.Realm)
		assert.Equal(t, "1927ed8a-3f1f-4846-8433-db290ea5ff90", userContext.UserID)
		assert.Equal(t, "initial@host.local", userContext.EmailAddress)
		assert.Equal(t, "initial", userContext.UserName)
		assert.ElementsMatch(t, []string{"offline_access", "uma_authorization", "user", "default-roles-user-management"}, userContext.Roles)
		assert.ElementsMatch(t, []string{"user-management-initial"}, userContext.Groups)
	})
}
