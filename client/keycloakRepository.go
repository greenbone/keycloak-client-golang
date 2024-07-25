// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package client

import (
	"context"

	"github.com/Nerzal/gocloak/v13"
)

type IKeycloakRepository interface {
	getClientToken(clientName, clientSecret string) (*gocloak.JWT, error)
	// Append keycloak functions here
}

type KeycloakRepository struct {
	client *gocloak.GoCloak
	realm  string
}

var _ IKeycloakRepository = &KeycloakRepository{}

func NewKeycloakRepository(basePath, realm string) *KeycloakRepository {
	return &KeycloakRepository{
		client: gocloak.NewClient(basePath),
		realm:  realm,
	}
}

func (r *KeycloakRepository) getClientToken(clientName, clientSecret string) (*gocloak.JWT, error) {
	return r.client.LoginClient(context.Background(), clientName, clientSecret, r.realm)
}
