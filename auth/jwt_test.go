package auth

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/big"
	"os"

	"github.com/golang-jwt/jwt/v4"
)

var (
	expiredToken          string
	noRealmToken          string
	invalidClaimsToken    string
	invalidIssuerToken    string
	invalidRealmToken     string
	invalidAlgorithmToken string
	invalidSignatureToken string
	validToken            string
	publicKey             rsa.PublicKey
)

const (
	publicKeyID  = "OMTg5TWEm1TZeqeb2zuJJFX1ZxOwDs_IfPIgJ0uIFU0"
	publicKeyALG = "RS256"
)

func init() {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Printf("Cannot generate RSA key\n")
		os.Exit(1)
	}
	publicKey = privateKey.PublicKey

	getToken := func(claims jwt.MapClaims) (string, error) {
		token := jwt.NewWithClaims(jwt.GetSigningMethod(publicKeyALG), claims)
		token.Header["kid"] = publicKeyID

		return token.SignedString(privateKey) //nolint
	}

	invalidAlgorithmToken, err = jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": validUrl + "/realms/" + validRealm,
	}).SignedString([]byte("SOME_KEY"))
	if err != nil {
		panic(err)
	}

	expiredToken, err = getToken(jwt.MapClaims{
		"kid": publicKeyID,
		"iss": validUrl + "/realms/" + validRealm,
		"iat": 1500000000,
		"exp": 1600000000,
	})
	if err != nil {
		panic(err)
	}

	invalidClaimsToken, err = getToken(jwt.MapClaims{
		"kid":    publicKeyID,
		"email":  12345,
		"roles":  1,
		"groups": 2,
	})
	if err != nil {
		panic(err)
	}

	invalidIssuerToken, err = getToken(jwt.MapClaims{
		"kid": publicKeyID,
		"iss": "invalid_issuer",
	})
	if err != nil {
		panic(err)
	}

	invalidRealmToken, err = getToken(jwt.MapClaims{
		"kid": publicKeyID,
		"iss": "http://invalid_url/realms/" + validRealm,
	})
	if err != nil {
		panic(err)
	}

	noRealmToken, err = getToken(jwt.MapClaims{
		"kid": publicKeyID,
		"iss": "",
	})
	if err != nil {
		panic(err)
	}

	invalidSignatureToken, err = getToken(jwt.MapClaims{
		"kid": publicKeyID,
		"iss": validUrl + "/realms/" + validRealm,
	})
	if err != nil {
		panic(err)
	}
	invalidSignatureToken += "XX" // malform signature

	validClaims := jwt.MapClaims{
		"kid":                publicKeyID,
		"iss":                validUrl + "/realms/" + validRealm,
		"sub":                "1927ed8a-3f1f-4846-8433-db290ea5ff90",
		"email":              "initial@host.local",
		"preferred_username": "initial",
		"roles":              []string{"offline_access", "uma_authorization", "user", "default-roles-user-management"},
		"groups":             []string{"user-management-initial"},
		"allowed-origins":    []string{validOrigin},
	}

	validToken, err = getToken(validClaims)
	if err != nil {
		panic(err)
	}
}

func getBase64E(e int) string {
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.BigEndian, int32(e))
	res := base64.RawURLEncoding.EncodeToString(buf.Bytes())

	return res
}

func getBase64N(n *big.Int) string {
	res := base64.RawURLEncoding.EncodeToString(n.Bytes())

	return res
}
