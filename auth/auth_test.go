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
	validRealm  = "user-management"
	validUrl    = "http://localhost:28080/auth"
	validOrigin = "http://localhost:3000"
)

func realmInfoGetter(realm string) (KeycloakRealmInfo, error) {
	if realm == validRealm {
		return KeycloakRealmInfo{
			AuthServerUrl:    validUrl,
			PEMPublicKeyCert: validCert,
		}, nil
	}

	return KeycloakRealmInfo{}, fmt.Errorf("unknown realm: %s", realm)
}

func TestNewKeycloakAuthorizer(t *testing.T) {
	t.Run("Empty realm id", func(t *testing.T) {
		authorizer, err := NewKeycloakAuthorizer(nil)

		assert.EqualError(t, err, "realm info getter cannot be nil")
		assert.Nil(t, authorizer)
	})

	t.Run("OK", func(t *testing.T) {
		authorizer, err := NewKeycloakAuthorizer(realmInfoGetter)

		assert.NoError(t, err)
		assert.NotNil(t, authorizer)
	})
}

func TestRealmInfoGetter(t *testing.T) {
	t.Run("Invalid auth url", func(t *testing.T) {
		tests := []string{
			"",
			"invalid-url",
			":///invalid@:",
			"http:// - ",
		}
		for _, test := range tests {
			t.Run(test, func(t *testing.T) {
				authorizer, err := NewKeycloakAuthorizer(func(realm string) (KeycloakRealmInfo, error) {
					return KeycloakRealmInfo{
						AuthServerUrl:    test,
						PEMPublicKeyCert: validCert,
					}, nil
				})
				require.NoError(t, err)
				require.NotNil(t, authorizer)

				userContext, err := authorizer.ParseJWT(validToken)

				assert.ErrorContains(t, err, "invalid realm info")
				assert.ErrorContains(t, err, "couldn't parse auth server url")
				assert.Nil(t, userContext)
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
				authorizer, err := NewKeycloakAuthorizer(func(realm string) (KeycloakRealmInfo, error) {
					return KeycloakRealmInfo{
						AuthServerUrl:    validUrl,
						PEMPublicKeyCert: test,
					}, nil
				})
				require.NoError(t, err)
				require.NotNil(t, authorizer)

				userContext, err := authorizer.ParseJWT(validToken)

				assert.ErrorContains(t, err, "invalid realm info")
				assert.ErrorContains(t, err, "couldn't parse rsa")
				assert.Nil(t, userContext)
			})
		}
	})

	t.Run("OK", func(t *testing.T) {
		authorizer, err := NewKeycloakAuthorizer(realmInfoGetter)
		require.NoError(t, err)
		require.NotNil(t, authorizer)

		userContext, err := authorizer.ParseJWT(validToken)

		assert.NoError(t, err)
		assert.NotNil(t, userContext)
	})
}

func TestParseJWT(t *testing.T) {
	authorizer, err := NewKeycloakAuthorizer(realmInfoGetter)
	require.NoError(t, err)
	require.NotNil(t, authorizer)

	t.Run("No realm info", func(t *testing.T) {
		userContext, err := authorizer.ParseJWT(noRealmToken)

		assert.ErrorContains(t, err, "token doesn't contain realm info")
		assert.Nil(t, userContext)
	})

	t.Run("Wrong algorithm", func(t *testing.T) {
		userContext, err := authorizer.ParseJWT(invalidAlgorithmToken)

		assert.ErrorContains(t, err, "validation of token failed")
		assert.ErrorContains(t, err, "key is of invalid type")
		assert.Nil(t, userContext)
	})

	t.Run("Wrong signature", func(t *testing.T) {
		userContext, err := authorizer.ParseJWT(invalidSignatureToken)

		assert.ErrorContains(t, err, "validation of token failed")
		assert.ErrorContains(t, err, "crypto/rsa: verification error")
		assert.Nil(t, userContext)
	})

	t.Run("Expired token", func(t *testing.T) {
		userContext, err := authorizer.ParseJWT(expiredToken)

		assert.ErrorContains(t, err, "validation of token failed")
		assert.ErrorContains(t, err, "Token is expired")
		assert.Nil(t, userContext)
	})

	t.Run("Invalid claims", func(t *testing.T) {
		userContext, err := authorizer.ParseJWT(invalidClaimsToken)

		assert.ErrorContains(t, err, "parsing of token failed")
		assert.ErrorContains(t, err, "cannot unmarshal number")
		assert.Nil(t, userContext)
	})

	t.Run("Invalid issuer", func(t *testing.T) {
		userContext, err := authorizer.ParseJWT(invalidIssuerToken)

		assert.ErrorContains(t, err, "couldn't get info for realm")
		assert.ErrorContains(t, err, "unknown realm")
		assert.Nil(t, userContext)
	})

	t.Run("Invalid realm", func(t *testing.T) {
		userContext, err := authorizer.ParseJWT(invalidRealmToken)

		assert.ErrorContains(t, err, "invalid domain of issuer")
		assert.Nil(t, userContext)
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
	authorizer, err := NewKeycloakAuthorizer(realmInfoGetter)
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

				assert.ErrorContains(t, err, "header contains invalid number of fields")
				assert.Nil(t, userContext)
			})
		}
	})

	t.Run("Invalid token type", func(t *testing.T) {
		userContext, err := authorizer.ParseAuthorizationHeader("not_bearer some_token")

		assert.ErrorContains(t, err, "header contains invalid token type")
		assert.Nil(t, userContext)
	})

	t.Run("Invalid token", func(t *testing.T) {
		userContext, err := authorizer.ParseAuthorizationHeader("bearer " + expiredToken)

		assert.ErrorContains(t, err, "validation of token failed")
		assert.Nil(t, userContext)
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

func TestParseRequest(t *testing.T) {
	authorizer, err := NewKeycloakAuthorizer(realmInfoGetter)
	require.NoError(t, err)
	require.NotNil(t, authorizer)

	t.Run("Invalid authorization header", func(t *testing.T) {
		userContext, err := authorizer.ParseRequest("invalid", validOrigin)

		assert.ErrorContains(t, err, "couldn't parse authorization header")
		assert.Nil(t, userContext)
	})

	t.Run("Invalid token", func(t *testing.T) {
		userContext, err := authorizer.ParseRequest("bearer invalid_token", validOrigin)

		assert.ErrorContains(t, err, "couldn't parse token")
		assert.Nil(t, userContext)
	})

	t.Run("Invalid origin", func(t *testing.T) {
		userContext, err := authorizer.ParseRequest(fmt.Sprintf("bearer %s", validToken), "http:/invalid-origin.com")

		assert.ErrorContains(t, err, "not allowed origin")
		assert.Nil(t, userContext)
	})

	t.Run("OK", func(t *testing.T) {
		userContext, err := authorizer.ParseRequest(fmt.Sprintf("bearer %s", validToken), validOrigin)
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
