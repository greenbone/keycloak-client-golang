![Greenbone Logo](https://www.greenbone.net/wp-content/uploads/gb_new-logo_horizontal_rgb_small.png)

[![GitHub releases](https://img.shields.io/github/release/greenbone/keycloak-client-golang.svg)](https://github.com/greenbone/keycloak-client-golang/releases)

# User management modules

This repository contains reusable user management modules.

## Authorization

See [auth/example_test.go](auth/example_test.go) for example usage or snippet below:

```go
import "github.com/greenbone/keycloak-client-golang/auth"

func main() {
    realmInfo := auth.KeycloakRealmInfo{
        RealmId:               "user-management",             // keycloak realm name
        AuthServerInternalUrl: "http://keycloak:8080/auth",   // keycloak server internal url
        AuthServerPublicUrl:   "http://localhost:28080/auth", // keycloak server public url (jwt issuer)
    }
    
    authorizer, err := auth.NewKeycloakAuthorizer(realmInfo)
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
        //     UserID: "1927ed8a-3f1f-4846-8433-db290ea5ff90", 
        //     UserName: "initial", 
        //     EmailAddress: "initial@host.local", 
        //     Roles: []string{""offline_access", "uma_authorization", "user", "default-roles-user-management"}, 
        //     Groups: []string{"user-management-initial"}, 
        //     AllowedOrigins: []string{"http://localhost:3000"},
        // }
    })
}
```

*Steps:*

- create a realm info struct with realm id and keycloak internal url (inside docker/k8s) from environment variables,
- create keycloak authorizer via `auth.NewKeycloakAuthorizer` and pass the realm info,
- create gin middleware via `auth.NewGinAuthMiddleware` with `ParseRequest` method of the authorizer. It will check `Authorization` header for the bearer token and `Origin` header for an allowed origin. It will put decoded claims into gin context
- wire up auth middleware to routes you decide
- inside routes use `auth.GetUserContext` to get decoded token claims as a user context object from gin context


## Maintainer

This project is maintained by [Greenbone AG][Greenbone Networks]

## Contributing

Your contributions are highly appreciated. Please
[create a pull request](https://github.com/greenbone/keycloak-client-golang/pulls)
on GitHub. Bigger changes need to be discussed with the development team via the
[issues section at GitHub](https://github.com/greenbone/keycloak-client-golang/issues)
first.

## License

Copyright (C) 2020-2023 [Greenbone AG][Greenbone Networks]

Licensed under the [GNU General Public License v3.0 or later](LICENSE).

[Greenbone Networks]: https://www.greenbone.net/
