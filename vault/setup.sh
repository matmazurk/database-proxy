#!/bin/sh
set -e

# Install jq for JSON parsing
apk add --no-cache jq > /dev/null

# Initialize Vault (single key share for simplicity)
INIT_OUTPUT=$(vault operator init -key-shares=1 -key-threshold=1 -format=json)
UNSEAL_KEY=$(echo "$INIT_OUTPUT" | jq -r '.unseal_keys_b64[0]')
ROOT_TOKEN=$(echo "$INIT_OUTPUT" | jq -r '.root_token')

# Unseal Vault
vault operator unseal "$UNSEAL_KEY" > /dev/null

# Authenticate with root token for setup
export VAULT_TOKEN="$ROOT_TOKEN"

# Enable cert auth
vault auth enable cert

# Configure cert auth role with the CA
vault write auth/cert/certs/proxy-client \
  display_name="proxy-client" \
  policies="db-policy" \
  certificate=@/certs/ca.crt

# Create policy for database creds
vault policy write db-policy - <<EOF
path "database/creds/readonly" {
  capabilities = ["read"]
}
EOF

# Enable database secrets engine
vault secrets enable database

# Configure PostgreSQL connection
vault write database/config/postgres \
  plugin_name=postgresql-database-plugin \
  allowed_roles="readonly" \
  connection_url="postgresql://{{username}}:{{password}}@postgres:5432/testdb?sslmode=disable" \
  username="postgres" \
  password="postgres"

# Create readonly role
vault write database/roles/readonly \
  db_name=postgres \
  creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";" \
  default_ttl="1h" \
  max_ttl="24h"

echo "Vault setup complete"
