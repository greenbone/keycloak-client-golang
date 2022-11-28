# User management modules

This repository contains reusable user management modules.

## Authorization

See [auth/example_test.go](auth/example_test.go) for example usage or snippet below:

```go
import "github.com/greenbone/user-management-api/auth"

const (
    realmId       = "user-management"             // keycloak realm name
    authServerUrl = "http://localhost:28080/auth" // keycloak server url
    pubCertPEM    = "..."                         // PEM formated public cert for keycloak token validation
)

func main() {
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
    router.Use(authMiddleware) // wire up auth middleware

    router.GET("/test", func(c *gin.Context) {
        userContext, err := auth.GetUserContext(c)
        if err != nil {
            _ = c.AbortWithError(http.StatusInternalServerError, err)
            return
        }

        c.String(http.StatusOK, fmt.Sprintf("%#v", userContext))
    })
}
```

*Steps:*

- create keycloak authorizer via `auth.NewKeycloakAuthorizer`. Pass keycloak params obtained from realm creation event
- create gin middleware via `auth.NewGinAuthMiddleware` that will use above keycloak authorizer to check `Authorization` header and put decoded claims into gin context
- wire up auth middleware to routes you decide
- inside routes use `auth.GetUserContext` to get decoded token claims as a user context object from gin context

