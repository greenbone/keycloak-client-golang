package main

import (
	"context"
	"crypto/rsa"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
)

const (
	accessKeyALG  = "RS256"
	refreshKeyALG = "HS256"
)

var (
	realms  = make(map[string]*realmData)
	userIDs = make(map[string]string)
	mu      sync.Mutex
)

var (
	ServerPort        = getEnvOrDefaultInt("PORT", 8080)
	KeycloakPublicUrl = getEnvOrDefaultString("KEYCLOAK_PUBLIC_URL", "http://localhost:8080/auth")
	AllowedOrigin     = getEnvOrDefaultString("FRONTEND_URL", "http://localhost:3000")
	EmailDomain       = getEnvOrDefaultString("USER_EMAIL_DOMAIN", "host.local")
)

func main() {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(3 * time.Second))

	r.Get("/auth/realms/{realm}/protocol/openid-connect/certs", handleCert)
	r.Post("/auth/realms/{realm}/protocol/openid-connect/token", handleToken)

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", ServerPort),
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

type realmData struct {
	accessPrivateKey *rsa.PrivateKey
	accessKeyID      string
	refreshSecret    []byte
	refreshKeyID     string
}

func getRealmData(realm string) (*realmData, error) {
	mu.Lock()
	defer mu.Unlock()

	if data, ok := realms[realm]; ok {
		return data, nil
	}

	data, err := newRealmData()
	if err != nil {
		return nil, fmt.Errorf("generate new realm data: %w", err)
	}
	realms[realm] = data

	return data, nil
}

func getUserID(userName string) string {
	mu.Lock()
	defer mu.Unlock()

	if id, ok := userIDs[userName]; ok {
		return id
	}

	userID := uuid.NewString()
	userIDs[userName] = userID

	return userID
}
