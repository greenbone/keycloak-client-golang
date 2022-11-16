package main

import (
	"fmt"
	api "user-management-api/keycloakService"
)

func main() {
	t := "foo"
	adapter := api.GetKeycloakClient("http://localhost:28080/auth")
	userData, err := adapter.EvaluateJwtToken("http://localhost:28080/auth", "user-management", t)
	fmt.Println(userData, err)
}
