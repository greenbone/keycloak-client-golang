package client

import (
	"context"
	"github.com/Nerzal/gocloak/v12"
)

type IKeycloakRepository interface {
	GetClientAccessToken(clientName, clientSecret, realm string) (*gocloak.JWT, error)
}

type KeycloakRepository struct {
	client *gocloak.GoCloak
}

var _ IKeycloakRepository = &KeycloakRepository{}

func NewKeycloakRepository(basePath string) *KeycloakRepository {
	return &KeycloakRepository{
		client: gocloak.NewClient(basePath),
	}
}

func (r *KeycloakRepository) GetClientAccessToken(clientName, clientSecret, realm string) (*gocloak.JWT, error) {
	return r.client.LoginClient(context.Background(), clientName, clientSecret, realm)
}
