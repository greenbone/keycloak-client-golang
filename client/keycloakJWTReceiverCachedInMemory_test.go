package client

import (
	"testing"

	"github.com/Nerzal/gocloak/v12"
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

func TestKeycloakJWTCacheInMemory_GetClientToken(t *testing.T) {

	tests := []struct {
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
			name: "Expired cached token",
			cachedToken: &gocloak.JWT{
				AccessToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE1MTYyMzEwMjJ9.hsfQPY3ZVrVIV-bzI54NRoTDG6wWzORVp68lxGa3D08", // todo add actual expired token -> create one on jwt.io
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
				AccessToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			},
			mockToken: &gocloak.JWT{
				AccessToken: "test_token",
			},
			expectedToken: &gocloak.JWT{
				AccessToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			},
			expectedError:    nil,
			shouldFetchToken: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			mockTokenReceiver := new(MockKeycloakRepository)
			cache := NewKeycloakJWTReceiverCachedInMemory(mockTokenReceiver)

			cache.cachedToken = tt.cachedToken

			mockTokenReceiver.On("getClientToken").Return(tt.mockToken, tt.mockError)

			token, err := cache.getClientToken("testClient", "testSecret")

			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}

			assert.Equal(t, tt.expectedToken, token)
			if tt.shouldFetchToken {
				mockTokenReceiver.AssertCalled(t, "getClientToken")
			}
		})
	}
}

func TestKeycloakJWTCacheInMemory_GetClientAccessToken(t *testing.T) {
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
