package keycloakService

import (
	"context"
	"fmt"
	"github.com/Nerzal/gocloak/v11"
	"github.com/golang-jwt/jwt/v4"
)

type KeycloakClient struct {
	client gocloak.GoCloak
}

type UserData struct {
	UserName       string
	EmailAddress   string
	KeycloakUserID string
	Roles          []string
	Groups         []string
}

func GetKeycloakAdapter(AuthServerUrl string) KeycloakClient {
	client := gocloak.NewClient(
		AuthServerUrl,
		gocloak.SetAuthRealms("realms"),
		gocloak.SetAuthAdminRealms("admin/realms"),
	)
	return KeycloakClient{client}
}

func (c KeycloakClient) EvaluateJwtToken(AuthServerUrl string, realmId string, token string) (UserData, error) {
	type customClaims struct {
		PreferredUsername string   `json:"preferred_username"`
		Email             string   `json:"email"`
		UserId            string   `json:"sub"`
		Roles             []string `json:"Role"`
		Groups            []string `json:"Group"`
		jwt.RegisteredClaims
	}

	jwtToken, err := c.client.DecodeAccessTokenCustomClaims(context.Background(), token, realmId, &customClaims{})
	if err != nil {
		return UserData{}, fmt.Errorf("validation of token failed: %w", err)
	}
	if !jwtToken.Valid {
		return UserData{}, fmt.Errorf("validation of token failed: invalid token")
	}
	if jwtToken.Header["alg"] == nil {
		return UserData{}, fmt.Errorf("validation of token failed: alg must be defined")
	}
	myClaims, ok := jwtToken.Claims.(*customClaims)
	if !ok {
		return UserData{}, fmt.Errorf("validation of token failed: invalid claims")
	}
	if myClaims.RegisteredClaims.Issuer != AuthServerUrl+"/realms/"+realmId {
		return UserData{}, fmt.Errorf("validation of token failed: wrong domain")
	}

	return UserData{myClaims.PreferredUsername, myClaims.Email, myClaims.UserId, myClaims.Roles, myClaims.Groups}, nil
}
