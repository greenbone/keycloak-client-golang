// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package client

import (
	"testing"

	"github.com/Nerzal/gocloak/v13"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockKeycloakRepository struct {
	mock.Mock
}

func (m *MockKeycloakRepository) getClientToken(clientName, clientSecret string) (*gocloak.JWT, error) {
	args := m.Called()
	return args.Get(0).(*gocloak.JWT), args.Error(1)
}

func TestKeycloakJWTReceiverCachedInMemory_GetClientToken(t *testing.T) {

	testCases := []struct {
		name             string
		cachedToken      *gocloak.JWT
		mockToken        *gocloak.JWT
		mockError        error
		expectedToken    *gocloak.JWT
		expectedError    error
		shouldFetchToken bool
	}{
		{
			name:        "No cached token",
			cachedToken: nil,
			mockToken: &gocloak.JWT{
				AccessToken: "test_token",
			},
			expectedToken: &gocloak.JWT{
				AccessToken: "test_token",
			},
			expectedError:    nil,
			shouldFetchToken: true,
		},
		{
			name: "invalid cached token",
			cachedToken: &gocloak.JWT{
				AccessToken: "not a valid token",
			},
			mockToken: &gocloak.JWT{
				AccessToken: "test_token",
			},
			expectedToken: &gocloak.JWT{
				AccessToken: "test_token",
			},
			expectedError:    nil,
			shouldFetchToken: true,
		},
		{
			name: "Expired cached token",
			cachedToken: &gocloak.JWT{
				AccessToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE1MTYyMzEwMjJ9.hsfQPY3ZVrVIV-bzI54NRoTDG6wWzORVp68lxGa3D08",
			},
			mockToken: &gocloak.JWT{
				AccessToken: "test_token",
			},
			expectedToken: &gocloak.JWT{
				AccessToken: "test_token",
			},
			expectedError:    nil,
			shouldFetchToken: true,
		},
		{
			name: "NotBefore date is in the future",
			cachedToken: &gocloak.JWT{
				AccessToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwibmJmIjo0ODczMjQyNTg3LCJleHAiOjQ4NzQyNDI1ODd9.QZeQwoWl-HRbCcuZbt_3DFnA_h-zD5DhPmcBR0TyrQw",
			},
			mockToken: &gocloak.JWT{
				AccessToken: "test_token",
			},
			expectedToken: &gocloak.JWT{
				AccessToken: "test_token",
			},
			expectedError:    nil,
			shouldFetchToken: true,
		},
		{
			name: "IssuedAt date is in the future",
			cachedToken: &gocloak.JWT{
				AccessToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0Ijo0ODczMjQyNTg3LCJleHAiOjQ4NzQyNDI1ODd9.h63qP0fMQGgx5S8eV-EHEO1zgSlBmjX3xR80iXnvhX0",
			},
			mockToken: &gocloak.JWT{
				AccessToken: "test_token",
			},
			expectedToken: &gocloak.JWT{
				AccessToken: "test_token",
			},
			expectedError:    nil,
			shouldFetchToken: true,
		},
		{
			name: "Valid cached token",
			cachedToken: &gocloak.JWT{
				AccessToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjQ4NzMyNDI1ODd9.BHuBKDS9MUC01jmo_p4AcVChkbV0aiDZBXcU-hpj8mg",
			},
			mockToken: &gocloak.JWT{
				AccessToken: "test_token",
			},
			expectedToken: &gocloak.JWT{
				AccessToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjQ4NzMyNDI1ODd9.BHuBKDS9MUC01jmo_p4AcVChkbV0aiDZBXcU-hpj8mg",
			},
			expectedError:    nil,
			shouldFetchToken: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			mockTokenReceiver := new(MockKeycloakRepository)
			cache := NewKeycloakJWTReceiverCachedInMemory(mockTokenReceiver)

			cache.cachedToken = tc.cachedToken

			mockTokenReceiver.On("getClientToken").Return(tc.mockToken, tc.mockError)

			token, err := cache.getClientToken("testClient", "testSecret")

			assert.ErrorIs(t, err, tc.expectedError)

			assert.Equal(t, tc.expectedToken, token)
			if tc.shouldFetchToken {
				mockTokenReceiver.AssertCalled(t, "getClientToken")
			}
		})
	}
}

func TestKeycloakJWTReceiverCachedInMemory_GetClientAccessToken(t *testing.T) {
	mockKeycloakRepository := new(MockKeycloakRepository)
	mockToken := &gocloak.JWT{
		AccessToken: "test_token",
		ExpiresIn:   3600,
	}

	mockKeycloakRepository.On("getClientToken").Return(mockToken, nil)

	cache := NewKeycloakJWTReceiverCachedInMemory(mockKeycloakRepository)

	accessToken, err := cache.GetClientAccessToken("testClient", "testSecret")

	assert.NoError(t, err)
	assert.Equal(t, "test_token", accessToken)
	mockKeycloakRepository.AssertCalled(t, "getClientToken")
}
