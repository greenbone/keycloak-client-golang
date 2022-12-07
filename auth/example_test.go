package auth_test

import (
	_ "embed"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"

	"github.com/greenbone/user-management-api/auth"
)

//go:embed testdata/cert.pem
var publicCertPEM string

//go:embed testdata/key.pem
var privateKeyPEM []byte

var validToken string

func init() {
	var err error
	secret, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyPEM)
	if err != nil {
		panic(err)
	}

	validToken, err = jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":                "http://localhost:28080/auth/realms/user-management",
		"sub":                "12345",
		"email":              "some@email.com",
		"preferred_username": "some_user",
		"roles":              []string{"some_role"},
		"groups":             []string{"some_group"},
	}).SignedString(secret)
	if err != nil {
		panic(err)
	}
}

func ExampleNewKeycloakAuthorizer() {
	var (
		realmId       = "user-management"             // keycloak realm name
		authServerUrl = "http://localhost:28080/auth" // keycloak server url
		pubCertPEM    = publicCertPEM                 // PEM formated public cert for keycloak token validation
	)

	authorizer, err := auth.NewKeycloakAuthorizer(realmId, authServerUrl, pubCertPEM)
	if err != nil {
		log.Fatal(fmt.Errorf("error creating keycloak token authorizer: %w", err))
		return
	}

	userContext, err := authorizer.ParseJWT(validToken) // pass jwt token here
	if err != nil {
		log.Fatal(fmt.Errorf("error parsing token: %w", err))
		return
	}

	fmt.Printf("%#v", userContext)
	// Output: &auth.UserContext{KeycloakUserID:"12345", UserName:"some_user", EmailAddress:"some@email.com", Roles:[]string{"some_role"}, Groups:[]string{"some_group"}}
}

func ExampleNewGinAuthMiddleware() {
	var (
		realmId       = "user-management"             // keycloak realm name
		authServerUrl = "http://localhost:28080/auth" // keycloak server url
		pubCertPEM    = publicCertPEM                 // PEM formated public cert for keycloak token validation
	)

	authorizer, err := auth.NewKeycloakAuthorizer(realmId, authServerUrl, pubCertPEM)
	if err != nil {
		log.Fatal(fmt.Errorf("error creating keycloak token authorizer: %w", err))
		return
	}

	authMiddleware, err := auth.NewGinAuthMiddleware(authorizer.ParseAuthorizationHeader)
	if err != nil {
		log.Fatal(fmt.Errorf("error creating keycloak auth middleware: %w", err))
		return
	}

	gin.SetMode(gin.TestMode)
	router := gin.Default()
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
	router.ServeHTTP(w, req)

	fmt.Print(w.Body.String())
	// Output: &auth.UserContext{KeycloakUserID:"12345", UserName:"some_user", EmailAddress:"some@email.com", Roles:[]string{"some_role"}, Groups:[]string{"some_group"}}
}