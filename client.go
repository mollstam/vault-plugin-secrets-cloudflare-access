package secretsengine

import (
	"errors"

	"github.com/cloudflare/cloudflare-go"
)

type cloudflareAccessClient struct {
	*cloudflare.API
}

func newClient(config *cloudflareAccessConfig) (*cloudflareAccessClient, error) {
	if config == nil {
		return nil, errors.New("client configuration was nil")
	}

	if config.ApiToken == "" {
		return nil, errors.New("client api token was not defined")
	}

	api, err := cloudflare.NewWithAPIToken(config.ApiToken)
	if err != nil {
		return nil, err
	}

	return &cloudflareAccessClient{api}, nil
}
