package auth_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"

	"github.com/Nerzal/gocloak/v12"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/jarcoal/httpmock"
	"github.com/samber/lo"

	"github.com/greenbone/user-management-api/auth"
)

func setupToken() (token string, clean func()) {
	privateKey := newPrivateKey()

	validToken := getToken(jwt.MapClaims{
		"iss":                "http://localhost:28080/auth/realms/user-management",
		"sub":                "1927ed8a-3f1f-4846-8433-db290ea5ff90",
		"email":              "initial@host.local",
		"preferred_username": "initial",
		"roles":              []string{"offline_access", "uma_authorization", "user", "default-roles-user-management"},
		"groups":             []string{"user-management-initial"},
		"allowed-origins":    []string{"http://localhost:3000"},
	}, privateKey)

	cleanUp := mockKeycloak(privateKey.PublicKey)

	return validToken, cleanUp
}

func ExampleNewKeycloakAuthorizer() {
	validToken, clean := setupToken()
	defer clean()

	var (
		realmId   = "user-management"             // keycloak realm name
		authUrl   = "http://keycloak:8080/auth"   // keycloak server internal url
		publicUrl = "http://localhost:28080/auth" // keycloak server public url (jwt issuer)
		origin    = "http://localhost:3000"       // request origin, note: it is optional, if request doesn't have Origin header it is not validated
	)

	realmInfo := auth.KeycloakRealmInfo{
		RealmId:               realmId,
		AuthServerInternalUrl: authUrl,
		AuthServerPublicUrl:   publicUrl,
	}

	authorizer, err := auth.NewKeycloakAuthorizer(realmInfo, authorizerKeycloakMock) // NOTE: authorizerKeycloakMock only used for mocking keycloak cert response in this example, do not use outside tests!
	if err != nil {
		log.Fatal(fmt.Errorf("error creating keycloak token authorizer: %w", err))
		return
	}

	userContext1, err := authorizer.ParseJWT(context.TODO(), validToken) // pass jwt token here
	if err != nil {
		log.Fatal(fmt.Errorf("error parsing token: %w", err))
		return
	}

	fmt.Printf("%#v\n", userContext1)

	userContext2, err := authorizer.ParseAuthorizationHeader(context.TODO(), "bearer "+validToken) // pass authorization header here
	if err != nil {
		log.Fatal(fmt.Errorf("error parsing token: %w", err))
		return
	}

	fmt.Printf("%#v\n", userContext2)

	userContext3, err := authorizer.ParseRequest(context.TODO(), "bearer "+validToken, origin) // pass authorization and origin headers here
	if err != nil {
		log.Fatal(fmt.Errorf("error parsing token: %w", err))
		return
	}

	fmt.Printf("%#v\n", userContext3)
	// Output:
	// auth.UserContext{Realm:"user-management", UserID:"1927ed8a-3f1f-4846-8433-db290ea5ff90", UserName:"initial", EmailAddress:"initial@host.local", Roles:[]string{"offline_access", "uma_authorization", "user", "default-roles-user-management"}, Groups:[]string{"user-management-initial"}, AllowedOrigins:[]string{"http://localhost:3000"}}
	// auth.UserContext{Realm:"user-management", UserID:"1927ed8a-3f1f-4846-8433-db290ea5ff90", UserName:"initial", EmailAddress:"initial@host.local", Roles:[]string{"offline_access", "uma_authorization", "user", "default-roles-user-management"}, Groups:[]string{"user-management-initial"}, AllowedOrigins:[]string{"http://localhost:3000"}}
	// auth.UserContext{Realm:"user-management", UserID:"1927ed8a-3f1f-4846-8433-db290ea5ff90", UserName:"initial", EmailAddress:"initial@host.local", Roles:[]string{"offline_access", "uma_authorization", "user", "default-roles-user-management"}, Groups:[]string{"user-management-initial"}, AllowedOrigins:[]string{"http://localhost:3000"}}
}

func ExampleNewGinAuthMiddleware() {
	validToken, clean := setupToken()
	defer clean()

	var (
		realmId   = "user-management"             // keycloak realm name
		authUrl   = "http://keycloak:8080/auth"   // keycloak server internal url
		publicUrl = "http://localhost:28080/auth" // keycloak server public url (jwt issuer)
		origin    = "http://localhost:3000"       // request origin, note: it is optional, if request doesn't have Origin header it is not validated
	)

	realmInfo := auth.KeycloakRealmInfo{
		RealmId:               realmId,
		AuthServerInternalUrl: authUrl,
		AuthServerPublicUrl:   publicUrl,
	}

	authorizer, err := auth.NewKeycloakAuthorizer(realmInfo, authorizerKeycloakMock) // NOTE: authorizerKeycloakMock only used for mocking keycloak cert response in this example, do not use outside tests!
	if err != nil {
		log.Fatal(fmt.Errorf("error creating keycloak token authorizer: %w", err))
		return
	}

	authMiddleware, err := auth.NewGinAuthMiddleware(authorizer.ParseRequest)
	if err != nil {
		log.Fatal(fmt.Errorf("error creating keycloak auth middleware: %w", err))
		return
	}

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(authMiddleware) // wire up middleware

	router.GET("/test", func(c *gin.Context) {
		userContext, err := auth.GetUserContext(c)
		if err != nil {
			_ = c.AbortWithError(http.StatusInternalServerError, err)
			return
		}

		c.String(http.StatusOK, fmt.Sprintf("%#v", userContext))
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Add("Authorization", fmt.Sprintf("bearer %s", validToken))
	req.Header.Add("Origin", origin)
	router.ServeHTTP(w, req)

	fmt.Print(w.Body.String())
	// Output:
	// auth.UserContext{Realm:"user-management", UserID:"1927ed8a-3f1f-4846-8433-db290ea5ff90", UserName:"initial", EmailAddress:"initial@host.local", Roles:[]string{"offline_access", "uma_authorization", "user", "default-roles-user-management"}, Groups:[]string{"user-management-initial"}, AllowedOrigins:[]string{"http://localhost:3000"}}
}

const (
	publicKeyID  = "OMTg5TWEm1TZeqeb2zuJJFX1ZxOwDs_IfPIgJ0uIFU0"
	publicKeyALG = "RS256"
)

func newPrivateKey() *rsa.PrivateKey {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return privateKey
}

func getToken(claims jwt.MapClaims, privateKey *rsa.PrivateKey) string {
	token := jwt.NewWithClaims(jwt.GetSigningMethod(publicKeyALG), claims)
	token.Header["kid"] = publicKeyID

	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		panic(err)
	}

	return tokenString
}

func getBase64E(e int) string {
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.BigEndian, int32(e))
	res := base64.RawURLEncoding.EncodeToString(buf.Bytes())

	return res
}

func getBase64N(n *big.Int) string {
	res := base64.RawURLEncoding.EncodeToString(n.Bytes())

	return res
}

var authorizerKeycloakMock func(*auth.KeycloakAuthorizer)

func mockKeycloak(publicKey rsa.PublicKey) (clean func()) {
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

	certResponder, err := httpmock.NewJsonResponder(200, certResponse)
	if err != nil {
		panic(err)
	}
	httpmock.RegisterResponder("GET", "http://keycloak:8080/auth/realms/user-management/protocol/openid-connect/certs", certResponder)

	authorizerKeycloakMock = auth.ConfigureGoCloak(func(c *gocloak.GoCloak) {
		httpmock.ActivateNonDefault(c.RestyClient().GetClient())
	})

	return httpmock.DeactivateAndReset
}
