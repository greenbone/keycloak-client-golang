package main

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"math/big"
	"net/http"

	"github.com/Nerzal/gocloak/v12"
	"github.com/go-chi/chi/v5"
	"github.com/samber/lo"
)

func handleCert(w http.ResponseWriter, r *http.Request) {
	realm := chi.URLParam(r, "realm")
	_, _ = w.Write([]byte(realm))
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

func getCertResponse(publicKey rsa.PublicKey) *gocloak.CertResponse {
	certResponse := &gocloak.CertResponse{
		Keys: &[]gocloak.CertResponseKey{
			{
				// Kid: lo.ToPtr(publicKeyID),
				// Alg: lo.ToPtr(publicKeyALG),
				N: lo.ToPtr(getBase64N(publicKey.N)),
				E: lo.ToPtr(getBase64E(publicKey.E)),
			},
		},
	}
	return certResponse
}
