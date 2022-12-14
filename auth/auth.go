package auth

import (
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v4"
)

type customClaims struct {
	jwt.RegisteredClaims
	UserId   string   `json:"sub"`
	Email    string   `json:"email"`
	UserName string   `json:"preferred_username"`
	Roles    []string `json:"roles"`
	Groups   []string `json:"groups"`
}

func parseAuthorizationHeader(authHeader string) (string, error) {
	fields := strings.Fields(authHeader)
	if len(fields) != 2 {
		return "", fmt.Errorf("header contains invalid number of fields: %d", len(fields))
	}
	if strings.ToLower(fields[0]) != "bearer" {
		return "", fmt.Errorf("header contains invalid token type: %q", fields[0])
	}
	return fields[1], nil
}
