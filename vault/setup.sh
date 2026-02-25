#!/bin/sh
set -e

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
