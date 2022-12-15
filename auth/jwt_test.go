package auth

import (
	_ "embed"

	"github.com/golang-jwt/jwt/v4"
)

//go:embed testdata/key.pem
var privateKeyPEM []byte

var (
	expiredToken          string
	noRealmToken          string
	invalidClaimsToken    string
	invalidIssuerToken    string
	invalidRealmToken     string
	invalidAlgorithmToken string
	invalidSignatureToken string
	validToken            string
)

func init() {
	var err error
	secret, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyPEM)
	if err != nil {
		panic(err)
	}

	expiredToken, err = jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": validUrl + "/realms/" + validRealm,
		"iat": 1500000000,
		"exp": 1600000000,
	}).SignedString(secret)
	if err != nil {
		panic(err)
	}

	invalidClaimsToken, err = jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"email":  12345,
		"roles":  1,
		"groups": 2,
	}).SignedString(secret)
	if err != nil {
		panic(err)
	}

	invalidIssuerToken, err = jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": "invalid_issuer",
	}).SignedString(secret)
	if err != nil {
		panic(err)
	}

	invalidRealmToken, err = jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": "http://invalid_url/realms/" + validRealm,
	}).SignedString(secret)
	if err != nil {
		panic(err)
	}

	noRealmToken, err = jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": "",
	}).SignedString(secret)
	if err != nil {
		panic(err)
	}

	invalidAlgorithmToken, err = jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": validUrl + "/realms/" + validRealm,
	}).SignedString([]byte("SOME_KEY"))
	if err != nil {
		panic(err)
	}

	invalidSignatureToken, err = jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": validUrl + "/realms/" + validRealm,
	}).SignedString(secret)
	if err != nil {
		panic(err)
	}
	invalidSignatureToken += "XX" // malform signature

	validClaims := jwt.MapClaims{
		"iss":                validUrl + "/realms/" + validRealm,
		"sub":                "12345",
		"email":              "some@email.com",
		"preferred_username": "some_user",
		"roles":              []string{"some_role"},
		"groups":             []string{"some_group"},
		"allowed-origins":    []string{"http://localhost:3000"},
	}

	validToken, err = jwt.NewWithClaims(jwt.SigningMethodRS256, validClaims).SignedString(secret)
	if err != nil {
		panic(err)
	}
}
