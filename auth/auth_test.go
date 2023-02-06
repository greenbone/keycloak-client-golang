package auth

import (
	"context"
	_ "embed"
	"fmt"
	"testing"

	"github.com/Nerzal/gocloak/v11"
	"github.com/jarcoal/httpmock"
	"github.com/samber/lo"
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

// func realmInfoGetter(realm string) (KeycloakRealmInfo, error) {
// 	if realm == validRealm {
// 		return KeycloakRealmInfo{
// 			InternalAuthServerUrl: validUrl,
// 			PEMPublicKeyCert:      validCert,
// 		}, nil
// 	}

// 	return KeycloakRealmInfo{}, fmt.Errorf("unknown realm: %s", realm)
// }

// func TestNewKeycloakAuthorizer(t *testing.T) {
// 	t.Run("Empty realm id", func(t *testing.T) {
// 		authorizer, err := NewKeycloakAuthorizer(nil)

// 		assert.EqualError(t, err, "realm info getter cannot be nil")
// 		assert.Nil(t, authorizer)
// 	})

// 	t.Run("OK", func(t *testing.T) {
// 		authorizer, err := NewKeycloakAuthorizer(realmInfoGetter)

// 		assert.NoError(t, err)
// 		assert.NotNil(t, authorizer)
// 	})
// }

// func TestRealmInfoGetter(t *testing.T) {
// 	t.Run("Invalid auth url", func(t *testing.T) {
// 		tests := []string{
// 			"",
// 			"invalid-url",
// 			":///invalid@:",
// 			"http:// - ",
// 		}
// 		for _, test := range tests {
// 			t.Run(test, func(t *testing.T) {
// 				authorizer, err := NewKeycloakAuthorizer(func(realm string) (KeycloakRealmInfo, error) {
// 					return KeycloakRealmInfo{
// 						InternalAuthServerUrl: test,
// 						PEMPublicKeyCert:      validCert,
// 					}, nil
// 				})
// 				require.NoError(t, err)
// 				require.NotNil(t, authorizer)

// 				userContext, err := authorizer.ParseJWT(validToken)

// 				assert.ErrorContains(t, err, "invalid realm info")
// 				assert.ErrorContains(t, err, "couldn't parse auth server url")
// 				assert.Nil(t, userContext)
// 			})
// 		}
// 	})

// 	t.Run("Invalid certificate", func(t *testing.T) {
// 		tests := []string{
// 			"",
// 			"invalid-cert",
// 		}
// 		for _, test := range tests {
// 			t.Run(test, func(t *testing.T) {
// 				authorizer, err := NewKeycloakAuthorizer(func(realm string) (KeycloakRealmInfo, error) {
// 					return KeycloakRealmInfo{
// 						InternalAuthServerUrl: validUrl,
// 						PEMPublicKeyCert:      test,
// 					}, nil
// 				})
// 				require.NoError(t, err)
// 				require.NotNil(t, authorizer)

// 				userContext, err := authorizer.ParseJWT(validToken)

// 				assert.ErrorContains(t, err, "invalid realm info")
// 				assert.ErrorContains(t, err, "couldn't parse rsa")
// 				assert.Nil(t, userContext)
// 			})
// 		}
// 	})

// 	t.Run("OK", func(t *testing.T) {
// 		authorizer, err := NewKeycloakAuthorizer(realmInfoGetter)
// 		require.NoError(t, err)
// 		require.NotNil(t, authorizer)

// 		userContext, err := authorizer.ParseJWT(validToken)

// 		assert.NoError(t, err)
// 		assert.NotNil(t, userContext)
// 	})
// }

// func TestParseJWT(t *testing.T) {
// 	authorizer, err := NewKeycloakAuthorizer(realmInfoGetter)
// 	require.NoError(t, err)
// 	require.NotNil(t, authorizer)

// 	t.Run("No realm info", func(t *testing.T) {
// 		userContext, err := authorizer.ParseJWT(noRealmToken)

// 		assert.ErrorContains(t, err, "token doesn't contain realm info")
// 		assert.Nil(t, userContext)
// 	})

// 	t.Run("Wrong algorithm", func(t *testing.T) {
// 		userContext, err := authorizer.ParseJWT(invalidAlgorithmToken)

// 		assert.ErrorContains(t, err, "validation of token failed")
// 		assert.ErrorContains(t, err, "key is of invalid type")
// 		assert.Nil(t, userContext)
// 	})

// 	t.Run("Wrong signature", func(t *testing.T) {
// 		userContext, err := authorizer.ParseJWT(invalidSignatureToken)

// 		assert.ErrorContains(t, err, "validation of token failed")
// 		assert.ErrorContains(t, err, "crypto/rsa: verification error")
// 		assert.Nil(t, userContext)
// 	})

// 	t.Run("Expired token", func(t *testing.T) {
// 		userContext, err := authorizer.ParseJWT(expiredToken)

// 		assert.ErrorContains(t, err, "validation of token failed")
// 		assert.ErrorContains(t, err, "Token is expired")
// 		assert.Nil(t, userContext)
// 	})

// 	t.Run("Invalid claims", func(t *testing.T) {
// 		userContext, err := authorizer.ParseJWT(invalidClaimsToken)

// 		assert.ErrorContains(t, err, "parsing of token failed")
// 		assert.ErrorContains(t, err, "cannot unmarshal number")
// 		assert.Nil(t, userContext)
// 	})

// 	t.Run("Invalid issuer", func(t *testing.T) {
// 		userContext, err := authorizer.ParseJWT(invalidIssuerToken)

// 		assert.ErrorContains(t, err, "couldn't get info for realm")
// 		assert.ErrorContains(t, err, "unknown realm")
// 		assert.Nil(t, userContext)
// 	})

// 	t.Run("Invalid realm", func(t *testing.T) {
// 		userContext, err := authorizer.ParseJWT(invalidRealmToken)

// 		assert.ErrorContains(t, err, "invalid domain of issuer")
// 		assert.Nil(t, userContext)
// 	})

// 	t.Run("OK", func(t *testing.T) {
// 		userContext, err := authorizer.ParseJWT(validToken)

// 		require.NoError(t, err)
// 		require.NotNil(t, userContext)

// 		assert.Equal(t, "user-management", userContext.Realm)
// 		assert.Equal(t, "12345", userContext.UserID)
// 		assert.Equal(t, "some@email.com", userContext.EmailAddress)
// 		assert.Equal(t, "some_user", userContext.UserName)
// 		assert.Equal(t, []string{"some_role"}, userContext.Roles)
// 		assert.Equal(t, []string{"some_group"}, userContext.Groups)
// 	})
// }

// func TestParseAuthorizationHeader(t *testing.T) {
// 	authorizer, err := NewKeycloakAuthorizer(realmInfoGetter)
// 	require.NoError(t, err)
// 	require.NotNil(t, authorizer)

// 	t.Run("Invalid fields", func(t *testing.T) {
// 		tests := []string{
// 			"",
// 			"one_field",
// 			"too many fields",
// 		}
// 		for _, test := range tests {
// 			t.Run(test, func(t *testing.T) {
// 				userContext, err := authorizer.ParseAuthorizationHeader(test)

// 				assert.ErrorContains(t, err, "header contains invalid number of fields")
// 				assert.Nil(t, userContext)
// 			})
// 		}
// 	})

// 	t.Run("Invalid token type", func(t *testing.T) {
// 		userContext, err := authorizer.ParseAuthorizationHeader("not_bearer some_token")

// 		assert.ErrorContains(t, err, "header contains invalid token type")
// 		assert.Nil(t, userContext)
// 	})

// 	t.Run("Invalid token", func(t *testing.T) {
// 		userContext, err := authorizer.ParseAuthorizationHeader("bearer " + expiredToken)

// 		assert.ErrorContains(t, err, "validation of token failed")
// 		assert.Nil(t, userContext)
// 	})

// 	t.Run("OK", func(t *testing.T) {
// 		userContext, err := authorizer.ParseAuthorizationHeader(fmt.Sprintf("bearer %s", validToken))

// 		require.NoError(t, err)
// 		require.NotNil(t, userContext)

// 		assert.Equal(t, "user-management", userContext.Realm)
// 		assert.Equal(t, "12345", userContext.UserID)
// 		assert.Equal(t, "some@email.com", userContext.EmailAddress)
// 		assert.Equal(t, "some_user", userContext.UserName)
// 		assert.Equal(t, []string{"some_role"}, userContext.Roles)
// 		assert.Equal(t, []string{"some_group"}, userContext.Groups)
// 	})
// }

// func TestParseRequest(t *testing.T) {
// 	authorizer, err := NewKeycloakAuthorizer(realmInfoGetter)
// 	require.NoError(t, err)
// 	require.NotNil(t, authorizer)

// 	t.Run("Invalid authorization header", func(t *testing.T) {
// 		userContext, err := authorizer.ParseRequest("invalid", validOrigin)

// 		assert.ErrorContains(t, err, "couldn't parse authorization header")
// 		assert.Nil(t, userContext)
// 	})

// 	t.Run("Invalid token", func(t *testing.T) {
// 		userContext, err := authorizer.ParseRequest("bearer invalid_token", validOrigin)

// 		assert.ErrorContains(t, err, "couldn't parse token")
// 		assert.Nil(t, userContext)
// 	})

// 	t.Run("Invalid origin", func(t *testing.T) {
// 		userContext, err := authorizer.ParseRequest(fmt.Sprintf("bearer %s", validToken), "http:/invalid-origin.com")

// 		assert.ErrorContains(t, err, "not allowed origin")
// 		assert.Nil(t, userContext)
// 	})

// 	t.Run("OK", func(t *testing.T) {
// 		userContext, err := authorizer.ParseRequest(fmt.Sprintf("bearer %s", validToken), validOrigin)
// 		require.NoError(t, err)
// 		require.NotNil(t, userContext)

// 		assert.Equal(t, "user-management", userContext.Realm)
// 		assert.Equal(t, "12345", userContext.UserID)
// 		assert.Equal(t, "some@email.com", userContext.EmailAddress)
// 		assert.Equal(t, "some_user", userContext.UserName)
// 		assert.Equal(t, []string{"some_role"}, userContext.Roles)
// 		assert.Equal(t, []string{"some_group"}, userContext.Groups)
// 	})
// }

// func TestCache(t *testing.T) {
// 	const n = 5

// 	runCacheTest := func(t *testing.T, opts ...KeycloakAuthorizerOption) int {
// 		executionCounter := 0

// 		authorizer, err := NewKeycloakAuthorizer(func(realm string) (KeycloakRealmInfo, error) {
// 			executionCounter++
// 			return realmInfoGetter(realm)
// 		}, opts...)
// 		require.NoError(t, err)
// 		require.NotNil(t, authorizer)

// 		for i := 0; i < n; i++ {
// 			userContext, err := authorizer.ParseJWT(validToken)

// 			require.NoError(t, err)
// 			require.NotNil(t, userContext)

// 			assert.Equal(t, "user-management", userContext.Realm)
// 			assert.Equal(t, "12345", userContext.UserID)
// 			assert.Equal(t, "some@email.com", userContext.EmailAddress)
// 			assert.Equal(t, "some_user", userContext.UserName)
// 			assert.Equal(t, []string{"some_role"}, userContext.Roles)
// 			assert.Equal(t, []string{"some_group"}, userContext.Groups)
// 		}

// 		return executionCounter
// 	}

// 	t.Run("No cache", func(t *testing.T) {
// 		executionCounter := runCacheTest(t)

// 		assert.Equal(t, n, executionCounter)
// 	})

// 	t.Run("With cache", func(t *testing.T) {
// 		executionCounter := runCacheTest(t, WithRealmInfoCache())

// 		assert.Equal(t, 1, executionCounter)
// 	})
// }

// var certResponse = &gocloak.CertResponse{
// 	Keys: &[]gocloak.CertResponseKey{
// 		{
// 			Kid:    lo.ToPtr("OMTg5TWEm1TZeqeb2zuJJFX1ZxOwDs_IfPIgJ0uIFU0"),
// 			Kty:    lo.ToPtr("RSA"),
// 			Alg:    lo.ToPtr("RS256"),
// 			Use:    lo.ToPtr("sig"),
// 			N:      lo.ToPtr("zzB6P8frGGMXjYdDDv3XG-mDY5WeDd0M-ox8wIP7UrEq6zigy1yxq-YwfxVXOkdZttQ94iidSUVt9ImqxQ2HraFOyjWH_pymCR_P3f1Bc21cLKi93hjcHefHCaV5nQ6UQwu_zAaVdxusnMHisk57pt71gInikfvXciQFkThD_8YzEXcrO1SfPydLMnXfsJ6mB02qWZtO--DPpdSCPIxaSX5oiKTiUW1OqeIJF_bDdrcaVmddYdR2AHUt5OBr4LWrsxvhEfgY48rBkgO6CO7aL8_WTmmuRnnYKS1ydaL-41AWPnPbw43xfnP4xyMQeutWsgJQPrpAyQ5Q2jXn7GarGQ"),
// 			E:      lo.ToPtr("AQAB"),
// 			KeyOps: nil,
// 			X5u:    nil,
// 			X5c: &[]string{
// 				"MIICrTCCAZUCBgGGFppYejANBgkqhkiG9w0BAQsFADAaMRgwFgYDVQQDDA91c2VyLW1hbmFnZW1lbnQwHhcNMjMwMjAzMDkyNTU5WhcNMzMwMjAzMDkyNzM5WjAaMRgwFgYDVQQDDA91c2VyLW1hbmFnZW1lbnQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDPMHo/x+sYYxeNh0MO/dcb6YNjlZ4N3Qz6jHzAg/tSsSrrOKDLXLGr5jB/FVc6R1m21D3iKJ1JRW30iarFDYetoU7KNYf+nKYJH8/d/UFzbVwsqL3eGNwd58cJpXmdDpRDC7/MBpV3G6ycweKyTnum3vWAieKR+9dyJAWROEP/xjMRdys7VJ8/J0sydd+wnqYHTapZm0774M+l1II8jFpJfmiIpOJRbU6p4gkX9sN2txpWZ11h1HYAdS3k4GvgtauzG+ER+BjjysGSA7oI7tovz9ZOaa5GedgpLXJ1ov7jUBY+c9vDjfF+c/jHIxB661ayAlA+ukDJDlDaNefsZqsZAgMBAAEwDQYJKoZIhvcNAQELBQADggEBABojVjiNZHwSjDNxKBjnwR/hag2EVCNj2SgQx8orRxUC7EvOMMIhHNZD0o2h/6fvkYgYglE+Xxou26z8PY66x5iJJ8H2GCN0Crl+qJJ7UVpCNDgMv18Rw3n9+OlN25NOEoIOOyB1dwkPwPCQhrk+L3L3Wx8gS1ucDPvT3xl9RsQkGrgZQfajhWmbytUCvmf4ygDwn1rPLUUf+TGpQBorXYqFNk+DgMerdeQVQCrKgGWD8oCmhcEpEJmUWYOUd580ea2N103t2DXDwjwdpF0k+BKGQlq7qTYboavBlNyo38SZmMnbplXu0Ub8GIhZMNAa6htUsy69UQ9oCAWd38ORLc8=",
// 			},
// 			X5t:     lo.ToPtr("375oZ1H6JwVJ2OaiPcsl3sE-HRc"),
// 			X5tS256: lo.ToPtr("ARsoOgtwOXg1iSjivmMpo2H8ZYnQyDSMdQ7cKw9yR68"),
// 		},
// 		{
// 			Kid:    lo.ToPtr("M9Ysmw8jiy3aKMlbsvkwveaB_K_0hREvoEfeZWzuJOA"),
// 			Kty:    lo.ToPtr("RSA"),
// 			Alg:    lo.ToPtr("RSA-OAEP"),
// 			Use:    lo.ToPtr("enc"),
// 			N:      lo.ToPtr("p7nohAUYwvEdmP4HjPZIOmIDohJlZahQbuQgJU-IXOrruhD4AfXJV_sMdNKsWLF1I0DWpCBnnLf2xJm2-_9g847mfRxVmUClO8lcYVqLj2rWYCtFXqQDypfChwzbCcNJ2Ny_ktlJ_HnIOkLHWqtLkvzX27higYcXTSHRbQxmZF_-ygfQS05UeZ4SUJtkNIsTUS8wGwLVmy-WDd1kc06L_RRwm9vDJ7EKWLhqYqVCgP2Hb03ggS1uIiNsIUDxzczikV9AOCCCORWi2w2-B0CH5qarbguchrK67Q9IDKiC6rQUkZdlgFfHvZNMc-iwf0ev3UhflythxHyk4UAjcvmcCw"),
// 			E:      lo.ToPtr("AQAB"),
// 			KeyOps: nil,
// 			X5u:    nil,
// 			X5c: &[]string{
// 				"MIICrTCCAZUCBgGGFppaOTANBgkqhkiG9w0BAQsFADAaMRgwFgYDVQQDDA91c2VyLW1hbmFnZW1lbnQwHhcNMjMwMjAzMDkyNTU5WhcNMzMwMjAzMDkyNzM5WjAaMRgwFgYDVQQDDA91c2VyLW1hbmFnZW1lbnQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCnueiEBRjC8R2Y/geM9kg6YgOiEmVlqFBu5CAlT4hc6uu6EPgB9clX+wx00qxYsXUjQNakIGect/bEmbb7/2DzjuZ9HFWZQKU7yVxhWouPatZgK0VepAPKl8KHDNsJw0nY3L+S2Un8ecg6Qsdaq0uS/NfbuGKBhxdNIdFtDGZkX/7KB9BLTlR5nhJQm2Q0ixNRLzAbAtWbL5YN3WRzTov9FHCb28MnsQpYuGpipUKA/YdvTeCBLW4iI2whQPHNzOKRX0A4III5FaLbDb4HQIfmpqtuC5yGsrrtD0gMqILqtBSRl2WAV8e9k0xz6LB/R6/dSF+XK2HEfKThQCNy+ZwLAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAIQYArErZLqNuoYrk2l3mBWnnZddlsSaSoC0UoB8+NMc5XWxjhsZulEh4r0gJoiYfn9fGJT6klKQj7zzrfyfGqhCuzdTewmG4aHyvu2eWs8Sq9jAFzoIB02k/fzzliiuHEGYVket7xRYph9eM7gYx4Rm3SdUeU21rj+F4Y4RP8daoobuN7rInz2yidAdyajTtqN6Sbs4/RrY/6BV/+oOheY3541LiIXZ60Yk5HcVn6yumv+8GP8sJ4+IUQt1ZIMSXgUkAGNfrq4V/qn0TamIbnF0EwRsAcVxpXh17fDjuDTaYEDtRJ2XKQzYFbm+ZRsKW3x7EIwWvSn1gn6a2FKeywY=",
// 			},
// 			X5t:     lo.ToPtr("37WwoW_CKPcL3UMbCWGaBhMn_Xo"),
// 			X5tS256: lo.ToPtr("iwgsBLnUBzsrD37C6IHCRjcJmuVfKzY91ydlwziICQM"),
// 		},
// 	},
// }

// const sampleToken = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJPTVRnNVRXRW0xVFplcWViMnp1SkpGWDFaeE93RHNfSWZQSWdKMHVJRlUwIn0.eyJleHAiOjE2NzU0MTgyNTksImlhdCI6MTY3NTQxNzk1OSwianRpIjoiNGI0NmFkNjItYmE1MS00ZmFiLWIyM2YtN2RiNDEwMmE1Y2JhIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDoyODA4MC9hdXRoL3JlYWxtcy91c2VyLW1hbmFnZW1lbnQiLCJhdWQiOiJhY2NvdW50Iiwic3ViIjoiMTkyN2VkOGEtM2YxZi00ODQ2LTg0MzMtZGIyOTBlYTVmZjkwIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoibG9jYWwtd2ViIiwic2Vzc2lvbl9zdGF0ZSI6IjQxYTFiMmQ5LTE3NTQtNGEwZi1hMWVlLTQzNjE2NDE0NThlMCIsImFjciI6IjEiLCJhbGxvd2VkLW9yaWdpbnMiOlsiaHR0cDovL2xvY2FsaG9zdDo4MDgxIiwiaHR0cDovL2xvY2FsaG9zdDozMDAwIl0sInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIiwidXNlciIsImRlZmF1bHQtcm9sZXMtdXNlci1tYW5hZ2VtZW50Il19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJwcm9maWxlIGVtYWlsIiwic2lkIjoiNDFhMWIyZDktMTc1NC00YTBmLWExZWUtNDM2MTY0MTQ1OGUwIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsInJvbGVzIjpbIm9mZmxpbmVfYWNjZXNzIiwidW1hX2F1dGhvcml6YXRpb24iLCJ1c2VyIiwiZGVmYXVsdC1yb2xlcy11c2VyLW1hbmFnZW1lbnQiXSwiZ3JvdXBzIjpbInVzZXItbWFuYWdlbWVudC1pbml0aWFsIl0sInByZWZlcnJlZF91c2VybmFtZSI6ImluaXRpYWwiLCJlbWFpbCI6ImluaXRpYWxAaG9zdC5sb2NhbCJ9.Wj507LTa6IVh-A-6_qcnH-UsiP4UQ3KWjr8kcwUYDJ6RRV6pFcRvib597DiWSSi5_Noeo8vhVZWbOWqMVd1f7snxgZxwRtqSE6tTtsgrp2Vt4w2PvOFlUn6IEJRBVvhod0VRt_YNqi5eB_G-5dm0ZD9f1baMBWIEvMZI1O9CycjhCos694Fl0dQshRL7DKi6AXbORZRsJSDAIj9R12yU_vao2d5Id5iK6uUnDECq4TrTr5AsRRRzTsjUECd4P2r9XCGRSqn2foWdofTaMUiYjFNWsIpGaYUeVsnq5o0wnTcZ8Zsh58uKKbVXe1bcAaxzb-g7uU820pUKUj8gnOxsGw" //nolint:gosec

func TestParseJWT(t *testing.T) {
	authorizer, err := NewKeycloakAuthorizer(KeycloakRealmInfo{
		RealmId:               validRealm,
		AuthServerInternalUrl: validUrl,
	})
	require.NoError(t, err)
	require.NotNil(t, authorizer)

	certResponse := &gocloak.CertResponse{
		Keys: &[]gocloak.CertResponseKey{
			{
				Kid: lo.ToPtr(publicKeyID),
				Alg: lo.ToPtr(publicKeyALG),
				N:   lo.ToPtr(getBase64N(publicKey.N)),
				E:   lo.ToPtr(getBase64E(publicKey.E)),
			},
		},
	}

	httpmock.ActivateNonDefault(authorizer.client.RestyClient().GetClient())
	defer httpmock.DeactivateAndReset()

	t.Run("OK", func(t *testing.T) {
		httpmock.Reset()
		certResponder, err := httpmock.NewJsonResponder(200, certResponse)
		require.NoError(t, err)
		httpmock.RegisterResponder("GET", fmt.Sprintf("%s/realms/%s/protocol/openid-connect/certs", validUrl, validRealm), certResponder)

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
