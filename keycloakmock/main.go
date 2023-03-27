package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
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
	"github.com/google/uuid"
	"github.com/samber/lo"
)

var (
	realms  = make(map[string]*realmData)
	userIDs = make(map[string]string)
	mu      sync.Mutex
)

type realmData struct {
	accessPrivateKey *rsa.PrivateKey
	accessKeyID      string
	refreshSecret    []byte
	refreshKeyID     string
}

// todo: to env vars
const (
	KeycloakPublicUrl = "http://localhost:28080/auth"
	EmailDomain       = "host.local"
	AllowedOrigin     = "http://localhost:3000"
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
		w.Header().Set("Content-Type", "application/json")

		r.ParseMultipartForm(0)

		realm := chi.URLParam(r, "realm")
		if realm == "" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, `{"error":"%s"}`, "realm cannot be empty")
			return
		}

		userName := r.FormValue("username")
		if userName == "" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, `{"error":"%s"}`, "username cannot be empty")
			return
		}

		clientId := r.FormValue("client_id")
		if clientId == "" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, `{"error":"%s"}`, "client_id cannot be empty")
			return
		}

		mu.Lock()

		var realmData *realmData
		if data, ok := realms[realm]; ok {
			realmData = data
		} else {
			data, err := newRealmData()
			if err != nil {
				err = fmt.Errorf("generate new realm data: %w", err)
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprintf(w, `{"error":"%s"}`, err.Error())
				return
			}
			realms[realm] = data
			realmData = data
		}

		var userID string
		if id, ok := userIDs[userName]; ok {
			userID = id
		} else {
			userID = uuid.NewString()
			userIDs[userName] = userID
		}

		mu.Unlock()

		issuer := fmt.Sprintf("%s/realms/%s", KeycloakPublicUrl, realm)
		sessionID := uuid.NewString()
		roles := []string{
			"default-roles-" + realm,
			"offline_access",
			"uma_authorization",
			"user",
		}
		now := time.Now().Unix()
		lifetime := int64(60 * 60 * 24)

		accessToken, err := getAccessToken(accessClaims{
			ExpiresAt:                  now + lifetime,
			IssuedAt:                   now,
			ID:                         uuid.NewString(),
			Issuer:                     issuer,
			Audience:                   "account",
			Subject:                    userID,
			Type:                       "Bearer",
			AuthorizedParty:            clientId,
			SessionState:               sessionID,
			AuthenticationContextClass: "1",
			AllowedOrigins:             []string{"http://localhost:3000", AllowedOrigin},
			RealmAccess: rolesAccess{
				Roles: roles,
			},
			ResourceAccess: resourceAccess{
				Account: rolesAccess{
					Roles: []string{
						"manage-account",
						"manage-account-links",
						"view-profile",
					},
				},
			},
			Scope:         "profile email",
			SessionID:     sessionID,
			EmailVerified: true,
			Roles:         roles,
			Groups:        []string{"default-group-" + realm},
			UserName:      userName,
			Email:         fmt.Sprintf("%s@%s", userName, EmailDomain),
		}, realmData.accessPrivateKey, realmData.accessKeyID)
		if err != nil {
			err = fmt.Errorf("generate access token: %w", err)
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, `{"error":"%s"}`, err.Error())
			return
		}

		refreshToken, err := getRefreshToken(refreshClaims{
			ExpiresAt:       now + lifetime,
			IssuedAt:        now,
			ID:              uuid.NewString(),
			Issuer:          issuer,
			Audience:        issuer,
			Subject:         userID,
			Type:            "Refresh",
			AuthorizedParty: clientId,
			SessionState:    sessionID,
			Scope:           "profile email",
			SessionID:       sessionID,
		}, realmData.refreshSecret, realmData.refreshKeyID)
		if err != nil {
			err = fmt.Errorf("generate refresh token: %w", err)
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, `{"error":"%s"}`, err.Error())
			return
		}

		res := token{
			AccessToken:      accessToken,
			RefreshToken:     refreshToken,
			TokenType:        "Bearer",
			ExpiresIn:        lifetime,
			RefreshExpiresIn: lifetime,
			NotBeforePolicy:  0,
			SessionState:     sessionID,
			Scope:            "profile email",
		}
		b, err := json.Marshal(res)
		if err != nil {
			err = fmt.Errorf("marshal response: %w", err)
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, `{"error":"%s"}`, err.Error())
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write(b)
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
	accessKeyALG  = "RS256"
	refreshKeyALG = "HS256"
)

func newRealmData() (*realmData, error) {
	accessPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("access rsa rand gen: %w", err)
	}

	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("access rand read: %w", err)
	}
	accessKeyID := base64.RawURLEncoding.EncodeToString(b)

	refreshSecret := make([]byte, 32)
	if _, err := rand.Read(refreshSecret); err != nil {
		return nil, fmt.Errorf("refresh rand read: %w", err)
	}

	refreshKeyID := uuid.NewString()

	return &realmData{
		accessPrivateKey: accessPrivateKey,
		accessKeyID:      accessKeyID,
		refreshSecret:    refreshSecret,
		refreshKeyID:     refreshKeyID,
	}, nil
}

func getAccessToken(claims jwt.Claims, privateKey *rsa.PrivateKey, keyID string) (string, error) {
	token := jwt.NewWithClaims(jwt.GetSigningMethod(accessKeyALG), claims)
	token.Header["kid"] = keyID

	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return "", fmt.Errorf("access token sign: %w", err)
	}

	return tokenString, nil
}

func getRefreshToken(claims jwt.Claims, secret []byte, keyID string) (string, error) {
	token := jwt.NewWithClaims(jwt.GetSigningMethod(refreshKeyALG), claims)
	token.Header["kid"] = keyID

	tokenString, err := token.SignedString(secret)
	if err != nil {
		return "", fmt.Errorf("refresh token sign: %w", err)
	}

	return tokenString, nil
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
				Kid: lo.ToPtr(publicKeyID),
				Alg: lo.ToPtr(publicKeyALG),
				N:   lo.ToPtr(getBase64N(publicKey.N)),
				E:   lo.ToPtr(getBase64E(publicKey.E)),
			},
		},
	}
	return certResponse
}

type accessClaims struct {
	ExpiresAt                  int64          `json:"exp"`
	IssuedAt                   int64          `json:"iat"`
	ID                         string         `json:"jti"`
	Issuer                     string         `json:"iss"`
	Audience                   string         `json:"aud"`
	Subject                    string         `json:"sub"`
	Type                       string         `json:"typ"`
	AuthorizedParty            string         `json:"azp"`
	SessionState               string         `json:"session_state"`
	AuthenticationContextClass string         `json:"acr"`
	AllowedOrigins             []string       `json:"allowed-origins"`
	RealmAccess                rolesAccess    `json:"realm_access"`
	ResourceAccess             resourceAccess `json:"resource_access"`
	Scope                      string         `json:"scope"`
	SessionID                  string         `json:"sid"`
	EmailVerified              bool           `json:"email_verified"`
	Roles                      []string       `json:"roles"`
	Groups                     []string       `json:"groups"`
	UserName                   string         `json:"preffered_username"`
	Email                      string         `json:"email"`
}

func (accessClaims) Valid() error { return nil }

type rolesAccess struct {
	Roles []string `json:"roles"`
}
type resourceAccess struct {
	Account rolesAccess `json:"account"`
}

type refreshClaims struct {
	ExpiresAt       int64  `json:"exp"`
	IssuedAt        int64  `json:"iat"`
	ID              string `json:"jti"`
	Issuer          string `json:"iss"`
	Audience        string `json:"aud"`
	Subject         string `json:"sub"`
	Type            string `json:"typ"`
	AuthorizedParty string `json:"azp"`
	SessionState    string `json:"session_state"`
	Scope           string `json:"scope"`
	SessionID       string `json:"sid"`
}

func (refreshClaims) Valid() error { return nil }

type token struct {
	AccessToken      string `json:"access_token"`
	ExpiresIn        int64  `json:"expires_in"`
	RefreshExpiresIn int64  `json:"refresh_expires_in"`
	RefreshToken     string `json:"refresh_token"`
	TokenType        string `json:"token_type"`
	NotBeforePolicy  int    `json:"not-before-policy"`
	SessionState     string `json:"session_state"`
	Scope            string `json:"scope"`
}
