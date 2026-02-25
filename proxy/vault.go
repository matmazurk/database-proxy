package proxy

import (
	"fmt"

	vaultapi "github.com/hashicorp/vault/api"
)

type DBCredentials struct {
	Username string
	Password string
}

type VaultClient struct {
	client *vaultapi.Client
}

func NewVaultClient(addr, caCert, clientCert, clientKey string) (*VaultClient, error) {
	vaultCfg := vaultapi.DefaultConfig()
	vaultCfg.Address = addr

	tlsCfg := &vaultapi.TLSConfig{
		CACert:     caCert,
		ClientCert: clientCert,
		ClientKey:  clientKey,
	}
	if err := vaultCfg.ConfigureTLS(tlsCfg); err != nil {
		return nil, fmt.Errorf("configuring Vault TLS: %w", err)
	}

	client, err := vaultapi.NewClient(vaultCfg)
	if err != nil {
		return nil, fmt.Errorf("creating Vault client: %w", err)
	}
	client.ClearToken()

	return &VaultClient{client: client}, nil
}

// GetDBCredentials authenticates to Vault using TLS cert auth and fetches
// dynamic database credentials for the given role.
func (v *VaultClient) GetDBCredentials(role string) (*DBCredentials, error) {
	// Authenticate via TLS cert auth
	secret, err := v.client.Logical().Write("auth/cert/login", nil)
	if err != nil {
		return nil, fmt.Errorf("cert auth login: %w", err)
	}
	if secret == nil || secret.Auth == nil {
		return nil, fmt.Errorf("no auth info returned from cert login")
	}
	v.client.SetToken(secret.Auth.ClientToken)

	// Fetch DB credentials
	creds, err := v.client.Logical().Read("database/creds/" + role)
	if err != nil {
		return nil, fmt.Errorf("fetching DB credentials: %w", err)
	}
	if creds == nil || creds.Data == nil {
		return nil, fmt.Errorf("no credentials returned for role %s", role)
	}

	username, ok := creds.Data["username"].(string)
	if !ok {
		return nil, fmt.Errorf("unexpected username type")
	}
	password, ok := creds.Data["password"].(string)
	if !ok {
		return nil, fmt.Errorf("unexpected password type")
	}

	return &DBCredentials{
		Username: username,
		Password: password,
	}, nil
}
