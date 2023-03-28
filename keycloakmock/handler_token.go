package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
)

func handleToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("read form data: %w", err))
		return
	}

	realm := chi.URLParam(r, "realm")
	if realm == "" {
		writeError(w, http.StatusBadRequest, errors.New("realm cannot be empty"))
		return
	}

	userName := r.FormValue("username")
	if userName == "" {
		writeError(w, http.StatusBadRequest, errors.New("username cannot be empty"))
		return
	}

	clientId := r.FormValue("client_id")
	if clientId == "" {
		writeError(w, http.StatusBadRequest, errors.New("client_id cannot be empty"))
		return
	}

	mu.Lock()

	var realmData *realmData
	if data, ok := realms[realm]; ok {
		realmData = data
	} else {
		data, err := newRealmData()
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("generate new realm data: %w", err))
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
		writeError(w, http.StatusInternalServerError, fmt.Errorf("generate access token: %w", err))
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
		writeError(w, http.StatusInternalServerError, fmt.Errorf("generate refresh token: %w", err))
		return
	}

	res := tokenResponse{
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
		writeError(w, http.StatusInternalServerError, fmt.Errorf("marshal response: %w", err))
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
}

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

type tokenResponse struct {
	AccessToken      string `json:"access_token"`
	ExpiresIn        int64  `json:"expires_in"`
	RefreshExpiresIn int64  `json:"refresh_expires_in"`
	RefreshToken     string `json:"refresh_token"`
	TokenType        string `json:"token_type"`
	NotBeforePolicy  int    `json:"not-before-policy"`
	SessionState     string `json:"session_state"`
	Scope            string `json:"scope"`
}
