package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"

	vaultapi "github.com/hashicorp/vault/api"
)

type DBCredentials struct {
	Username string
	Password string
}

type VaultClient struct {
	addr string
}

func NewVaultClient(addr string) *VaultClient {
	return &VaultClient{addr: addr}
}

// GetDBCredentials authenticates to Vault using the client cert via TLS cert auth,
// then fetches dynamic database credentials for the given role.
func (v *VaultClient) GetDBCredentials(clientCert *x509.Certificate, clientKey interface{}, role string) (*DBCredentials, error) {
	// Build a TLS certificate from the raw client cert + key
	tlsCert := tls.Certificate{
		Certificate: [][]byte{clientCert.Raw},
		PrivateKey:  clientKey,
	}

	// Create Vault client with custom TLS transport presenting the client cert
	vaultCfg := vaultapi.DefaultConfig()
	vaultCfg.Address = v.addr
	vaultCfg.HttpClient = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates:       []tls.Certificate{tlsCert},
				InsecureSkipVerify: true, // PoC only - Vault in dev mode
			},
		},
	}

	client, err := vaultapi.NewClient(vaultCfg)
	if err != nil {
		return nil, fmt.Errorf("creating Vault client: %w", err)
	}

	// Authenticate via TLS cert auth method
	secret, err := client.Logical().Write("auth/cert/login", nil)
	if err != nil {
		return nil, fmt.Errorf("Vault cert auth: %w", err)
	}
	if secret == nil || secret.Auth == nil {
		return nil, fmt.Errorf("Vault cert auth returned no token")
	}
	client.SetToken(secret.Auth.ClientToken)

	// Fetch dynamic DB credentials
	creds, err := client.Logical().Read("database/creds/" + role)
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
