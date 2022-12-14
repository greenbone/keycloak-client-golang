package auth

import (
	_ "embed"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//go:embed testdata/cert.pem
var validCert string

const (
	validRealm = "user-management"
	validUrl   = "http://localhost:28080/auth"
)

func TestNewKeycloakAuthorizer(t *testing.T) {
	t.Run("Empty realm id", func(t *testing.T) {
		authorizer, err := NewKeycloakAuthorizer("", validUrl, validCert)

		require.EqualError(t, err, "realm id cannot be empty")
		require.Nil(t, authorizer)
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
				authorizer, err := NewKeycloakAuthorizer(validRealm, test, validCert)

				require.ErrorContains(t, err, "couldn't parse auth server url")
				require.Nil(t, authorizer)
			})
		}
	})

	t.Run("Invalid certificate", func(t *testing.T) {
		tests := []string{
			"",
			"invalid-cert",
		}
		for _, test := range tests {
			t.Run(test, func(t *testing.T) {
				authorizer, err := NewKeycloakAuthorizer(validRealm, validUrl, test)

				require.ErrorContains(t, err, "couldn't parse rsa")
				require.Nil(t, authorizer)
			})
		}
	})

	t.Run("OK", func(t *testing.T) {
		authorizer, err := NewKeycloakAuthorizer(validRealm, validUrl, validCert)

		require.NoError(t, err)
		require.NotNil(t, authorizer)
	})
}

func TestParseJWT(t *testing.T) {
	authorizer, err := NewKeycloakAuthorizer(validRealm, validUrl, validCert)
	require.NoError(t, err)
	require.NotNil(t, authorizer)

	t.Run("Wrong algorithm", func(t *testing.T) {
		userContext, err := authorizer.ParseJWT(tokenHS256)

		require.ErrorContains(t, err, "validation of token failed")
		require.ErrorContains(t, err, "key is of invalid type")
		require.Nil(t, userContext)
	})
	t.Run("Wrong signature", func(t *testing.T) {
		userContext, err := authorizer.ParseJWT(tokenRS256)

		require.ErrorContains(t, err, "validation of token failed")
		require.ErrorContains(t, err, "crypto/rsa: verification error")
		require.Nil(t, userContext)
	})
	t.Run("Expired token", func(t *testing.T) {
		userContext, err := authorizer.ParseJWT(expiredToken)

		require.ErrorContains(t, err, "validation of token failed")
		require.ErrorContains(t, err, "token is expired")
		require.Nil(t, userContext)
	})
	t.Run("Invalid claims", func(t *testing.T) {
		userContext, err := authorizer.ParseJWT(invalidClaimsToken)

		require.ErrorContains(t, err, "validation of token failed")
		require.ErrorContains(t, err, "cannot unmarshal number")
		require.Nil(t, userContext)
	})
	t.Run("Invalid issuer", func(t *testing.T) {
		userContext, err := authorizer.ParseJWT(invalidIssuerToken)

		require.ErrorContains(t, err, "invalid domain of issuer")
		require.Nil(t, userContext)
	})

	t.Run("OK", func(t *testing.T) {
		userContext, err := authorizer.ParseJWT(validToken)

		require.NoError(t, err)
		require.NotNil(t, userContext)

		assert.Equal(t, "user-management", userContext.Realm)
		assert.Equal(t, "12345", userContext.UserID)
		assert.Equal(t, "some@email.com", userContext.EmailAddress)
		assert.Equal(t, "some_user", userContext.UserName)
		assert.Equal(t, []string{"some_role"}, userContext.Roles)
		assert.Equal(t, []string{"some_group"}, userContext.Groups)
	})
}

func TestParseAuthorizationHeader(t *testing.T) {
	authorizer, err := NewKeycloakAuthorizer(validRealm, validUrl, validCert)
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
				userContext, err := authorizer.ParseAuthorizationHeader(test)

				require.ErrorContains(t, err, "header contains invalid number of fields")
				require.Nil(t, userContext)
			})
		}
	})
	t.Run("Invalid token type", func(t *testing.T) {
		userContext, err := authorizer.ParseAuthorizationHeader("not_bearer some_token")

		require.ErrorContains(t, err, "header contains invalid token type")
		require.Nil(t, userContext)
	})

	t.Run("OK", func(t *testing.T) {
		userContext, err := authorizer.ParseAuthorizationHeader(fmt.Sprintf("bearer %s", validToken))

		require.NoError(t, err)
		require.NotNil(t, userContext)

		assert.Equal(t, "user-management", userContext.Realm)
		assert.Equal(t, "12345", userContext.UserID)
		assert.Equal(t, "some@email.com", userContext.EmailAddress)
		assert.Equal(t, "some_user", userContext.UserName)
		assert.Equal(t, []string{"some_role"}, userContext.Roles)
		assert.Equal(t, []string{"some_group"}, userContext.Groups)
	})
}
