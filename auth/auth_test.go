package auth

import (
	_ "embed"
	"testing"

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
		a, err := NewKeycloakAuthorizer("", validUrl, validCert)

		require.EqualError(t, err, "realm id cannot be empty")
		require.Nil(t, a)
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
				a, err := NewKeycloakAuthorizer(validRealm, test, validCert)

				require.ErrorContains(t, err, "couldn't parse auth server url")
				require.Nil(t, a)
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
				a, err := NewKeycloakAuthorizer(validRealm, validUrl, test)

				require.ErrorContains(t, err, "couldn't parse rsa")
				require.Nil(t, a)
			})
		}
	})

	t.Run("OK", func(t *testing.T) {
		a, err := NewKeycloakAuthorizer(validRealm, validUrl, validCert)

		require.NoError(t, err)
		require.NotNil(t, a)
	})
}
