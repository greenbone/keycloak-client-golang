package auth

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewKeycloakAuthorizer(t *testing.T) {
	t.Run("Empty realm id", func(t *testing.T) {
		authorizer, err := NewKeycloakAuthorizer(KeycloakRealmInfo{})

		assert.ErrorContains(t, err, "invalid realm info")
		assert.ErrorContains(t, err, "realm id cannot be empty")
		assert.Nil(t, authorizer)
	})

	t.Run("Invalid auth url", func(t *testing.T) {
		tests := []string{
			"",
			"invalid-url",
			":///invalid@:",
			"http:// - ",
		}
		for _, test := range tests {
			t.Run(test, func(t *testing.T) {
				authorizer, err := NewKeycloakAuthorizer(KeycloakRealmInfo{
					AuthServerInternalUrl: test,
					RealmId:               validRealm,
				})
				assert.ErrorContains(t, err, "invalid realm info")
				assert.ErrorContains(t, err, "couldn't parse auth server url")
				assert.Nil(t, authorizer)
			})
		}
	})

	t.Run("OK", func(t *testing.T) {
		authorizer, err := NewKeycloakAuthorizer(KeycloakRealmInfo{
			RealmId:               validRealm,
			AuthServerInternalUrl: validUrl,
		})

		assert.NoError(t, err)
		assert.NotNil(t, authorizer)
	})
}

func TestParseJWT(t *testing.T) {
	authorizer, err := NewKeycloakAuthorizer(KeycloakRealmInfo{
		RealmId:               validRealm,
		AuthServerInternalUrl: validUrl,
	})
	require.NoError(t, err)
	require.NotNil(t, authorizer)

	FakeCertResponse(t, authorizer)

	t.Run("No realm info", func(t *testing.T) {
		userContext, err := authorizer.ParseJWT(context.Background(), noRealmToken)

		assert.ErrorContains(t, err, "invalid domain of issuer")
		assert.Nil(t, userContext)
	})

	t.Run("Wrong algorithm", func(t *testing.T) {
		userContext, err := authorizer.ParseJWT(context.Background(), invalidAlgorithmToken)

		assert.ErrorContains(t, err, "validation of token failed")
		assert.ErrorContains(t, err, "cannot find a key to decode the token")
		assert.Nil(t, userContext)
	})

	t.Run("Wrong signature", func(t *testing.T) {
		userContext, err := authorizer.ParseJWT(context.Background(), invalidSignatureToken)

		assert.ErrorContains(t, err, "validation of token failed")
		assert.ErrorContains(t, err, "crypto/rsa: verification error")
		assert.Nil(t, userContext)
	})

	t.Run("Expired token", func(t *testing.T) {
		userContext, err := authorizer.ParseJWT(context.Background(), expiredToken)

		assert.ErrorContains(t, err, "validation of token failed")
		assert.ErrorContains(t, err, "Token is expired")
		assert.Nil(t, userContext)
	})

	t.Run("Invalid claims", func(t *testing.T) {
		userContext, err := authorizer.ParseJWT(context.Background(), invalidClaimsToken)

		assert.ErrorContains(t, err, "parsing of token failed")
		assert.ErrorContains(t, err, "cannot unmarshal number")
		assert.Nil(t, userContext)
	})

	t.Run("Invalid issuer", func(t *testing.T) {
		userContext, err := authorizer.ParseJWT(context.Background(), invalidIssuerToken)

		assert.ErrorContains(t, err, "invalid domain of issuer")
		assert.Nil(t, userContext)
	})

	t.Run("Invalid realm", func(t *testing.T) {
		userContext, err := authorizer.ParseJWT(context.Background(), invalidRealmToken)

		assert.ErrorContains(t, err, "invalid domain of issuer")
		assert.Nil(t, userContext)
	})

	t.Run("OK", func(t *testing.T) {
		userContext, err := authorizer.ParseJWT(context.Background(), validToken)

		require.NoError(t, err)
		require.NotNil(t, userContext)

		assert.Equal(t, "user-management", userContext.Realm)
		assert.Equal(t, "1927ed8a-3f1f-4846-8433-db290ea5ff90", userContext.UserID)
		assert.Equal(t, "initial@host.local", userContext.EmailAddress)
		assert.Equal(t, "initial", userContext.UserName)
		assert.ElementsMatch(t, []string{"offline_access", "uma_authorization", "user", "default-roles-user-management"}, userContext.Roles)
		assert.ElementsMatch(t, []string{"user-management-initial"}, userContext.Groups)
	})
}

func TestParseAuthorizationHeader(t *testing.T) {
	authorizer, err := NewKeycloakAuthorizer(KeycloakRealmInfo{
		RealmId:               validRealm,
		AuthServerInternalUrl: validUrl,
	})
	require.NoError(t, err)
	require.NotNil(t, authorizer)

	FakeCertResponse(t, authorizer)

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
				assert.Nil(t, userContext)
			})
		}
	})

	t.Run("Invalid token type", func(t *testing.T) {
		userContext, err := authorizer.ParseAuthorizationHeader(context.Background(), "not_bearer some_token")

		assert.ErrorContains(t, err, "header contains invalid token type")
		assert.Nil(t, userContext)
	})

	t.Run("Invalid token", func(t *testing.T) {
		userContext, err := authorizer.ParseAuthorizationHeader(context.Background(), "bearer "+expiredToken)

		assert.ErrorContains(t, err, "validation of token failed")
		assert.Nil(t, userContext)
	})

	t.Run("OK", func(t *testing.T) {
		userContext, err := authorizer.ParseAuthorizationHeader(context.Background(), fmt.Sprintf("bearer %s", validToken))

		require.NoError(t, err)
		require.NotNil(t, userContext)

		assert.Equal(t, "user-management", userContext.Realm)
		assert.Equal(t, "1927ed8a-3f1f-4846-8433-db290ea5ff90", userContext.UserID)
		assert.Equal(t, "initial@host.local", userContext.EmailAddress)
		assert.Equal(t, "initial", userContext.UserName)
		assert.ElementsMatch(t, []string{"offline_access", "uma_authorization", "user", "default-roles-user-management"}, userContext.Roles)
		assert.ElementsMatch(t, []string{"user-management-initial"}, userContext.Groups)
	})
}

func TestParseRequest(t *testing.T) {
	authorizer, err := NewKeycloakAuthorizer(KeycloakRealmInfo{
		RealmId:               validRealm,
		AuthServerInternalUrl: validUrl,
	})
	require.NoError(t, err)
	require.NotNil(t, authorizer)

	FakeCertResponse(t, authorizer)

	t.Run("Invalid authorization header", func(t *testing.T) {
		userContext, err := authorizer.ParseRequest(context.Background(), "invalid", validOrigin)

		assert.ErrorContains(t, err, "couldn't parse authorization header")
		assert.Nil(t, userContext)
	})

	t.Run("Invalid token", func(t *testing.T) {
		userContext, err := authorizer.ParseRequest(context.Background(), "bearer invalid_token", validOrigin)

		assert.ErrorContains(t, err, "couldn't parse token")
		assert.Nil(t, userContext)
	})

	t.Run("Invalid origin", func(t *testing.T) {
		userContext, err := authorizer.ParseRequest(context.Background(), fmt.Sprintf("bearer %s", validToken), "http://invalid-origin.com")

		assert.ErrorContains(t, err, "not allowed origin")
		assert.Nil(t, userContext)
	})

	t.Run("OK without origin", func(t *testing.T) {
		userContext, err := authorizer.ParseRequest(context.Background(), fmt.Sprintf("bearer %s", validToken), "")
		require.NoError(t, err)
		require.NotNil(t, userContext)

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
		require.NotNil(t, userContext)

		assert.Equal(t, "user-management", userContext.Realm)
		assert.Equal(t, "1927ed8a-3f1f-4846-8433-db290ea5ff90", userContext.UserID)
		assert.Equal(t, "initial@host.local", userContext.EmailAddress)
		assert.Equal(t, "initial", userContext.UserName)
		assert.ElementsMatch(t, []string{"offline_access", "uma_authorization", "user", "default-roles-user-management"}, userContext.Roles)
		assert.ElementsMatch(t, []string{"user-management-initial"}, userContext.Groups)
	})
}
