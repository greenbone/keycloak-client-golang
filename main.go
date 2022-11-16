package main

import (
	"fmt"
	api "github.com/greenbone/user-management-api/keycloakService"
)

func main() {
	t := "foo"
	client := api.GetKeycloakClient("http://localhost:28080/auth")
	userData, err := client.EvaluateJwtToken("http://localhost:28080/auth", "user-management", t)
	fmt.Println(userData, err)
}
