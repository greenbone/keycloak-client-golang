# User management modules

This repository contains reusable user management modules.

## Authorization

See [auth/example_test.go](auth/example_test.go) for example usage or snippet below:

```go
import "github.com/greenbone/user-management-api/auth"

func main() {
    realmInfoGetter := func(realm string) (auth.KeycloakRealmInfo, error) {
        ...  // fetch data from database or other source for given `realm`
        if ok {
            return auth.KeycloakRealmInfo{
                AuthServerUrl:    "http://localhost:28080/auth", // keycloak server url
                PEMPublicKeyCert: "..."                          // PEM formated public cert for keycloak token validation
            }, nil
        }

        return auth.KeycloakRealmInfo{}, fmt.Errorf("unknown realm: %s", realm)
    }

    authorizer, err := auth.NewKeycloakAuthorizer(realmInfoGetter, auth.WithRealmInfoCache()) // WithRealmInfoCache enables persistent realm info cache, meaning you can safely query db in it and it will always get called only once per realm
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
        // Output:
        //
        // &auth.UserContext{
        //     Realm: "user-management", 
        //     UserID: "12345", 
        //     UserName: "some_user", 
        //     EmailAddress: "some@email.com", 
        //     Roles: []string{"some_role"}, 
        //     Groups: []string{"some_group"}, 
        //     AllowedOrigins: []string{"http://localhost:3000"},
        // }
    })
}
```

*Steps:*

- create a realm info getter function `func(realm string) (auth.KeycloakRealmInfo, error)` that will reaturn keycloak auth url and PEM formatted public key for token signature validation. This data can be obtained from realm creation event and should be stored in your local database
- create keycloak authorizer via `auth.NewKeycloakAuthorizer` and pass the realm info getter function. Suggested usage with `auth.WithRealmInfoCache()` option on to cache calls to realm info getter only once per realm per whole app lifetime.
- create gin middleware via `auth.NewGinAuthMiddleware` that will use above keycloak authorizer to check `Authorization` header for the bearer token and `Origin` header for an allowed origin. It will put decoded claims into gin context
- wire up auth middleware to routes you decide
- inside routes use `auth.GetUserContext` to get decoded token claims as a user context object from gin context
