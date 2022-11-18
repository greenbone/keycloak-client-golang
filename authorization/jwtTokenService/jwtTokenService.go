package jwtTokenService

import (
	"crypto/rsa"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"strings"
)

type authorizationData struct {
	realmId        string
	tokenPublicKey *rsa.PublicKey
	authServerUrl  string
}

var authData = authorizationData{"", nil, ""}

type UserData struct {
	UserName       string
	EmailAddress   string
	KeycloakUserID string
	Roles          []string
	Groups         []string
}

func SetAuthorizationData(realmId string, publicKey string, authServerUrl string) error {
	var err error
	authData.realmId = realmId
	authData.authServerUrl = authServerUrl
	authData.tokenPublicKey, err = jwt.ParseRSAPublicKeyFromPEM([]byte(publicKey))
	return err
}

func EvaluateJwtToken(token string) (UserData, error) {
	type customClaims struct {
		PreferredUsername string   `json:"preferred_username"`
		Email             string   `json:"email"`
		UserId            string   `json:"sub"`
		Roles             []string `json:"Role"`
		Groups            []string `json:"Group"`
		jwt.RegisteredClaims
	}

	tokenFields := strings.Fields(token)
	if len(tokenFields) < 2 {
		return UserData{}, fmt.Errorf("validation of token failed: incomplete token")
	}
	jwtToken, err := jwt.ParseWithClaims(tokenFields[1], &customClaims{}, func(token *jwt.Token) (interface{}, error) {
		return authData.tokenPublicKey, nil
	})
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
	if myClaims.RegisteredClaims.Issuer != authData.authServerUrl+"/realms/"+authData.realmId {
		return UserData{}, fmt.Errorf("validation of token failed: wrong domain")
	}

	return UserData{myClaims.PreferredUsername, myClaims.Email, myClaims.UserId, myClaims.Roles, myClaims.Groups}, nil
}
