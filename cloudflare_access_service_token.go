package cloudflare

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	cloudflareAccessTokenType = "cloudflare_access_service_token"
)

type cloudflareAccessToken struct {
	TokenName    string `json:"token_name"`
	TokenID      string `json:"token_id"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

func (b *cloudflareAccessBackend) cloudflareAccessToken() *framework.Secret {
	return &framework.Secret{
		Type: cloudflareAccessTokenType,
		Fields: map[string]*framework.FieldSchema{
			"client_id": {
				Type:        framework.TypeString,
				Description: "The Client ID for the service token",
			},
			"client_secret": {
				Type:        framework.TypeString,
				Description: "The Client Secret for the service token",
			},
		},
		Revoke: b.tokenRevoke,
		Renew:  b.tokenRenew,
	}
}

func deleteToken(ctx context.Context, c *cloudflareAccessClient, zoneID string, tokenID string) error {
	_, err := c.API.DeleteZoneLevelAccessServiceToken(ctx, zoneID, tokenID)
	if err != nil {
		return err
	}

	return nil
}

func (b *cloudflareAccessBackend) tokenRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("error getting client: %w", err)
	}

	tokenID := ""
	tokenIDRaw, ok := req.Secret.InternalData["token_id"]
	if ok {
		tokenID, ok = tokenIDRaw.(string)
		if !ok {
			return nil, fmt.Errorf("invalid value for token in secret internal data")
		}
	}

	roleRaw, ok := req.Secret.InternalData["role"]
	if !ok {
		return nil, fmt.Errorf("secret is missing role internal data")
	}

	role := roleRaw.(string)
	roleEntry, err := b.getRole(ctx, req.Storage, role)
	if err != nil {
		return nil, fmt.Errorf("error retrieving role: %w", err)
	}
	if roleEntry == nil {
		return nil, errors.New("error retrieving role: role is nil")
	}

	if err := deleteToken(ctx, client, roleEntry.ZoneID, tokenID); err != nil {
		return nil, fmt.Errorf("error revoking user token: %w", err)
	}

	return nil, nil
}

func createToken(ctx context.Context, c *cloudflareAccessClient, zoneID string) (*cloudflareAccessToken, error) {
	tokenName := fmt.Sprintf("Managed by Vault (%v)", uuid.New().String())
	response, err := c.API.CreateZoneLevelAccessServiceToken(ctx, zoneID, tokenName)
	if err != nil {
		return nil, fmt.Errorf("error from API when creating token: %w", err)
	}

	return &cloudflareAccessToken{
		TokenName:    response.Name,
		TokenID:      response.ID,
		ClientID:     response.ClientID,
		ClientSecret: response.ClientSecret,
	}, nil
}

func (b *cloudflareAccessBackend) tokenRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleRaw, ok := req.Secret.InternalData["role"]
	if !ok {
		return nil, fmt.Errorf("secret is missing role internal data")
	}

	role := roleRaw.(string)
	roleEntry, err := b.getRole(ctx, req.Storage, role)
	if err != nil {
		return nil, fmt.Errorf("error retrieving role: %w", err)
	}
	if roleEntry == nil {
		return nil, errors.New("error retrieving role: role is nil")
	}

	resp := &logical.Response{Secret: req.Secret}

	if roleEntry.TTL > 0 {
		resp.Secret.TTL = roleEntry.TTL
	}

	if roleEntry.MaxTTL > 0 {
		resp.Secret.MaxTTL = roleEntry.MaxTTL
	}

	return resp, nil
}
