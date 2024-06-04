// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-3.0-or-later

package client

import (
	"fmt"

	"github.com/Nerzal/gocloak/v12"
	"github.com/golang-jwt/jwt/v4"
	"github.com/rs/zerolog/log"
)

type KeycloakJWTReceiverCachedInMemory struct {
	keycloakRepository IKeycloakRepository
	cachedToken        *gocloak.JWT
}

func NewKeycloakJWTReceiverCachedInMemory(keycloakRepository IKeycloakRepository) *KeycloakJWTReceiverCachedInMemory {
	return &KeycloakJWTReceiverCachedInMemory{
		keycloakRepository: keycloakRepository,
	}
}

func isTokenValid(token *gocloak.JWT) bool {
	if token == nil {
		return false
	}

	parser := jwt.NewParser()
	claims := &jwt.MapClaims{}

	_, _, err := parser.ParseUnverified(token.AccessToken, claims)
	if err != nil {
		log.Error().Msgf("couldn't parse ID token: %v", err)
		return false
	}

	err = claims.Valid()
	if err != nil {
		log.Debug().Msgf("ID token is invalid: %v", err)
		return false
	}

	return true
}

func (k *KeycloakJWTReceiverCachedInMemory) getClientToken(clientName, clientSecret string) (*gocloak.JWT, error) {
	if k.cachedToken == nil || !isTokenValid(k.cachedToken) {
		token, err := k.keycloakRepository.getClientToken(clientName, clientSecret)
		if err != nil {
			return nil, fmt.Errorf("couldn't fetch ID token: %w", err)
		}
		k.cachedToken = token
	}

	return k.cachedToken, nil
}

func (k *KeycloakJWTReceiverCachedInMemory) GetClientAccessToken(clientName, clientSecret string) (string, error) {
	token, err := k.getClientToken(clientName, clientSecret)
	if err != nil {
		return "", err
	}

	return token.AccessToken, nil
}
