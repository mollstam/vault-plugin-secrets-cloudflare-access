package secretsengine

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathCredentials(b *cloudflareAccessBackend) *framework.Path {
	return &framework.Path{
		Pattern: "creds/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeLowerCaseString,
				Description: "Name of the role",
				Required:    true,
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   b.pathCredentialsRead,
			logical.UpdateOperation: b.pathCredentialsRead,
		},
		HelpSynopsis:    pathCredentialsHelpSyn,
		HelpDescription: pathCredentialsHelpDesc,
	}
}

func (b *cloudflareAccessBackend) createToken(ctx context.Context, s logical.Storage, roleEntry *cloudflareAccessRoleEntry) (*cloudflareAccessToken, error) {
	client, err := b.getClient(ctx, s)
	if err != nil {
		return nil, err
	}

	var token *cloudflareAccessToken

	token, err = createToken(ctx, client, roleEntry.ZoneID)
	if err != nil {
		return nil, fmt.Errorf("error creating Cloudflare Access Service Token for role '%v': %w", roleEntry.Name, err)
	}

	if token == nil {
		return nil, errors.New("error creating Cloudflare Access Service Token")
	}

	return token, nil
}

func (b *cloudflareAccessBackend) createUserCreds(ctx context.Context, req *logical.Request, role *cloudflareAccessRoleEntry) (*logical.Response, error) {
	token, err := b.createToken(ctx, req.Storage, role)
	if err != nil {
		return nil, err
	}

	resp := b.Secret(cloudflareAccessTokenType).Response(map[string]interface{}{
		"token_name":    token.TokenName,
		"token_id":      token.TokenID,
		"client_id":     token.ClientID,
		"client_secret": token.ClientSecret,
	}, map[string]interface{}{
		"token_id": token.TokenID,
		"role":     role.Name,
	})

	if role.TTL > 0 {
		resp.Secret.TTL = role.TTL
	}

	if role.MaxTTL > 0 {
		resp.Secret.MaxTTL = role.MaxTTL
	}

	return resp, nil
}

func (b *cloudflareAccessBackend) pathCredentialsRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName := d.Get("name").(string)

	roleEntry, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, fmt.Errorf("error retrieving role: %w", err)
	}

	if roleEntry == nil {
		return nil, errors.New("error retrieving role: role is nil")
	}

	return b.createUserCreds(ctx, req, roleEntry)
}

const pathCredentialsHelpSyn = `
Generate a Cloudflare Access Service Token from a specific Vault role.
`

const pathCredentialsHelpDesc = `
This path generates a Cloudflare Access Service Token based on a particular role.
`
