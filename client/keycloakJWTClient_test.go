package client

import (
	"testing"

	"github.com/Nerzal/gocloak/v12"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockTokenReceiver struct {
	mock.Mock
}

func (m *MockTokenReceiver) GetAccessToken() (string, error) {
	args := m.Called()
	return args.String(0), args.Error(1)
}

func (m *MockTokenReceiver) getToken() (*gocloak.JWT, error) {
	args := m.Called()
	return args.Get(0).(*gocloak.JWT), args.Error(1)
}

func TestKeycloakJWTCacheInMemory_GetToken(t *testing.T) {

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

			mockTokenReceiver := new(MockTokenReceiver)
			cache := NewKeycloakJWTCacheInMemory(mockTokenReceiver)

			cache.cachedToken = tt.cachedToken

			mockTokenReceiver.On("getToken").Return(tt.mockToken, tt.mockError)

			token, err := cache.getToken()

			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}

			assert.Equal(t, tt.expectedToken, token)
			if tt.shouldFetchToken {
				mockTokenReceiver.AssertCalled(t, "getToken")
			}
		})
	}
}

func TestKeycloakJWTCacheInMemory_GetAccessToken(t *testing.T) {
	mockTokenReceiver := new(MockTokenReceiver)
	mockToken := &gocloak.JWT{
		AccessToken: "test_token",
		ExpiresIn:   3600,
	}

	mockTokenReceiver.On("getToken").Return(mockToken, nil)

	cache := NewKeycloakJWTCacheInMemory(mockTokenReceiver)

	accessToken, err := cache.GetAccessToken()

	assert.NoError(t, err)
	assert.Equal(t, "test_token", accessToken)
	mockTokenReceiver.AssertCalled(t, "getToken")
}
