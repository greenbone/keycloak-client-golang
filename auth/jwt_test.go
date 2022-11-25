package auth

import (
	_ "embed"

	"github.com/golang-jwt/jwt/v4"
)

//go:embed testdata/key.pem
var privateKeyPEM []byte

//nolint:gosec
const (
	tokenHS256 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	tokenRS256 = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImFscGhhIjoibGI1ZTYxYWV4OGkwYmxqaGl2MnYwOGwifQ.eyJpc3MiOiJEaW5vQ2hpZXNhLmdpdGh1Yi5pbyIsInN1YiI6InNoZW5pcXVhIiwiYXVkIjoiYXJ5YSIsImlhdCI6MTY2OTM1OTM5MiwiZXhwIjoxNjY5MzU5OTkyLCJ2ZXJzaW9uIjoidDVrOXNrbTlja2t1ZTVvaG95ZmMifQ.nCy4B_nU7QOp2vX-9WF01fwEKl0bwZx-RK1K_2ZmLPDTepaJAfbrCxy8uX2xvvBODRQhCSSPKPZLrCB5t9J02amchHqwy0t0dTt_lAUyQ5pEdp8GIUnpafZYBaKuDOY6o5TQbgrKwZYSxIFijJFIrEyv1Pi8Svmf3wZ9UAHgSrmsMidc15GA1nDREwK7Qcy70X4Gw20buDt7SQNB2R9ovxNtWkECHDGl_B2D1EDOAPut5leLlbzg58ZJmS8ExeYHbo0euL6PXJIWbUjk_C5yWSvXWlzv3Yhin_FU7-skCJ-PnGByixB4rQRXjUFInoDay_55E0yCg7cdzvBx5bxN7w"
)

var (
	expiredToken       string
	invalidClaimsToken string
	invalidIssuerToken string
	validToken         string
)

func init() {
	var err error
	secret, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyPEM)
	if err != nil {
		panic(err)
	}

	expiredToken, err = jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
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
		"iss": "not what we expect",
	}).SignedString(secret)
	if err != nil {
		panic(err)
	}

	validToken, err = jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":                validUrl + "/realms/" + validRealm,
		"sub":                "12345",
		"email":              "some@email.com",
		"preferred_username": "some_user",
		"roles":              []string{"some_role"},
		"groups":             []string{"some_group"},
	}).SignedString(secret)
	if err != nil {
		panic(err)
	}
}
