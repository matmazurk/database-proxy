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

func NewVaultClient(addr, token string) (*VaultClient, error) {
	vaultCfg := vaultapi.DefaultConfig()
	vaultCfg.Address = addr

	client, err := vaultapi.NewClient(vaultCfg)
	if err != nil {
		return nil, fmt.Errorf("creating Vault client: %w", err)
	}
	client.SetToken(token)

	return &VaultClient{client: client}, nil
}

// GetDBCredentials fetches dynamic database credentials from Vault for the given role.
func (v *VaultClient) GetDBCredentials(role string) (*DBCredentials, error) {
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
