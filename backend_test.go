package secretsengine

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/helper/logging"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

const (
	envVarRunAccTests        = "VAULT_ACC"
	envVarCloudflareApiToken = "TEST_CLOUDFLARE_TOKEN"
	envVarCloudflareZoneID   = "TEST_CLOUDFLARE_ZONE_ID"
)

var runAcceptanceTests = os.Getenv(envVarRunAccTests) == "1"

type testEnv struct {
	ApiToken string
	ZoneID   string

	Backend logical.Backend
	Context context.Context
	Storage logical.Storage

	SecretToken string

	Tokens []string
}

func newAcceptanceTestEnv() (*testEnv, error) {
	ctx := context.Background()

	maxLease, _ := time.ParseDuration("60s")
	defaultLease, _ := time.ParseDuration("30s")
	conf := &logical.BackendConfig{
		System: &logical.StaticSystemView{
			DefaultLeaseTTLVal: defaultLease,
			MaxLeaseTTLVal:     maxLease,
		},
		Logger: logging.NewVaultLogger(hclog.Debug),
	}
	b, err := Factory(ctx, conf)
	if err != nil {
		return nil, err
	}

	return &testEnv{
		ApiToken: os.Getenv(envVarCloudflareApiToken),
		ZoneID:   os.Getenv(envVarCloudflareZoneID),
		Backend:  b,
		Context:  ctx,
		Storage:  &logical.InmemStorage{},
	}, nil
}

func TestAcceptanceServiceToken(t *testing.T) {
	if !runAcceptanceTests {
		t.SkipNow()
	}

	acceptanceTestEnv, err := newAcceptanceTestEnv()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("add config", acceptanceTestEnv.AddConfig)
	t.Run("read config", acceptanceTestEnv.ReadConfig)
	t.Run("add service token role", acceptanceTestEnv.AddServiceTokenRole)
	t.Run("read service token cred", acceptanceTestEnv.ReadServiceToken)
	t.Run("read service token cred", acceptanceTestEnv.ReadServiceToken)
	t.Run("cleanup service tokens", acceptanceTestEnv.CleanupServiceTokens)
}

func (e *testEnv) AddConfig(t *testing.T) {
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   e.Storage,
		Data: map[string]interface{}{
			"api_token": e.ApiToken,
		},
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	require.Nil(t, resp)
	require.Nil(t, err)
}

func (e *testEnv) ReadConfig(t *testing.T) {
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
		Storage:   e.Storage,
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	require.Nil(t, err)
	require.NotNil(t, resp)

	// allow api_token to be included, but it shouldn't show the actual secret value!
	if _, ok := resp.Data["api_token"]; ok {
		require.NotEqual(t, e.ApiToken, resp.Data["api_token"])
	}
}

func (e *testEnv) AddServiceTokenRole(t *testing.T) {
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/test-service-token",
		Storage:   e.Storage,
		Data: map[string]interface{}{
			"zone_id": e.ZoneID,
		},
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	require.Nil(t, resp)
	require.Nil(t, err)
}

func (e *testEnv) ReadServiceToken(t *testing.T) {
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/test-service-token",
		Storage:   e.Storage,
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	require.Nil(t, err)
	require.NotNil(t, resp)

	if t, ok := resp.Data["token_id"]; ok {
		e.Tokens = append(e.Tokens, t.(string))
	}
	require.NotEmpty(t, resp.Data["token_id"])

	if e.SecretToken != "" {
		require.NotEqual(t, e.SecretToken, resp.Data["token_id"])
	}

	// collect secret IDs to revoke at end of test
	require.NotNil(t, resp.Secret)
	if t, ok := resp.Secret.InternalData["token_id"]; ok {
		e.SecretToken = t.(string)
	}
}

func (e *testEnv) CleanupServiceTokens(t *testing.T) {
	if len(e.Tokens) == 0 {
		t.Fatalf("expected 2 tokens, got: %d", len(e.Tokens))
	}

	for _, token := range e.Tokens {
		b := e.Backend.(*cloudflareAccessBackend)
		client, err := b.getClient(e.Context, e.Storage)
		if err != nil {
			t.Fatal("fatal getting client")
		}

		_, err = client.API.DeleteZoneLevelAccessServiceToken(e.Context, e.ZoneID, token)
		if err != nil {
			t.Fatalf("unexpected error deleting token: %s", err)
		}

	}
}
