package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/Nerzal/gocloak/v12"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/golang-jwt/jwt/v4"
	"github.com/samber/lo"
)

type realm struct {
	pubKey rsa.PublicKey
	prvKey rsa.PrivateKey
}

var (
	realms = make(map[string]realm)
	mu     sync.Mutex
)

func main() {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(3 * time.Second))

	r.Get("/auth/realms/{realm}/protocol/openid-connect/certs", func(w http.ResponseWriter, r *http.Request) {
		realm := chi.URLParam(r, "realm")
		w.Write([]byte(realm))
	})
	r.Post("/auth/realms/{realm}/protocol/openid-connect/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseMultipartForm(0)
		realm := chi.URLParam(r, "realm")
		userName := r.FormValue("username")
		fmt.Fprintf(w, "%s - %v", realm, userName)
	})

	srv := &http.Server{
		Addr:         ":3333",
		ReadTimeout:  1 * time.Second,
		WriteTimeout: 1 * time.Second,
		IdleTimeout:  3 * time.Second,
		Handler:      r,
	}

	log.Println("HTTP server starting on:", srv.Addr)
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	<-ctx.Done()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer shutdownCancel()

	log.Println("HTTP server shuting down...")
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("HTTP server shutdown error: %v", err)
	}
}

const (
	publicKeyID  = "OMTg5TWEm1TZeqeb2zuJJFX1ZxOwDs_IfPIgJ0uIFU0"
	publicKeyALG = "RS256"
)

func newPrivateKey() *rsa.PrivateKey {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return privateKey
}

func getToken(claims jwt.MapClaims, privateKey *rsa.PrivateKey) string {
	token := jwt.NewWithClaims(jwt.GetSigningMethod(publicKeyALG), claims)
	token.Header["kid"] = publicKeyID

	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		panic(err)
	}

	return tokenString
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

func getKeyID() (string, error) {
	keyID := make([]byte, 32)
	if _, err := rand.Read(keyID); err != nil {
		return "", fmt.Errorf("random read: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(keyID), nil
}

func getCertResponse(publicKey rsa.PublicKey) *gocloak.CertResponse {
	certResponse := &gocloak.CertResponse{
		Keys: &[]gocloak.CertResponseKey{
			{
				Kid: lo.ToPtr(publicKeyID),
				Alg: lo.ToPtr(publicKeyALG),
				N:   lo.ToPtr(getBase64N(publicKey.N)),
				E:   lo.ToPtr(getBase64E(publicKey.E)),
			},
		},
	}
	return certResponse
}
