package main

import (
	"fmt"
	api "github.com/greenbone/user-management-api/authorization/jwtTokenService"
)

func main() {
	pkey := "foo"

	t := "baz"
	api.SetAuthorizationData("user-management", pkey, "http://localhost:28080/auth")
	userData, err := api.EvaluateJwtToken(t)
	fmt.Println(userData, err)
}
