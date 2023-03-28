package main

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"

	"github.com/Nerzal/gocloak/v12"
	"github.com/go-chi/chi/v5"
	"github.com/samber/lo"
)

func handleCert(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	realm := chi.URLParam(r, "realm")
	if realm == "" {
		writeError(w, http.StatusBadRequest, errors.New("realm cannot be empty"))
		return
	}

	realmData, err := getRealmData(realm)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Errorf("get realm data: %w", err))
		return
	}

	certResponse := getCertResponse(realmData.accessPrivateKey.PublicKey, realmData.accessKeyID)

	b, err := json.Marshal(certResponse)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Errorf("marshal response: %w", err))
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
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

func getCertResponse(publicKey rsa.PublicKey, keyID string) *gocloak.CertResponse {
	return &gocloak.CertResponse{
		Keys: &[]gocloak.CertResponseKey{
			{
				Kid: lo.ToPtr(keyID),
				Alg: lo.ToPtr(accessKeyALG),
				N:   lo.ToPtr(getBase64N(publicKey.N)),
				E:   lo.ToPtr(getBase64E(publicKey.E)),
			},
		},
	}
}
