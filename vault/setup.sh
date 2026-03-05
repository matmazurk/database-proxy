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

# Create policy for database creds (wildcard to cover all roles)
vault policy write db-policy - <<EOF
path "database/creds/*" {
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

# Create PostgreSQL readonly role
vault write database/roles/readonly \
  db_name=postgres \
  creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";" \
  default_ttl="1h" \
  max_ttl="24h"

# Register Oracle plugin
ORACLE_PLUGIN_SHA=$(sha256sum /vault/plugins/vault-plugin-database-oracle | cut -d' ' -f1)
vault plugin register -sha256="$ORACLE_PLUGIN_SHA" \
  database vault-plugin-database-oracle

# Configure Oracle connection
vault write database/config/oracle \
  plugin_name=vault-plugin-database-oracle \
  allowed_roles="oracle-readonly" \
  connection_url="{{username}}/{{password}}@//oracle:1521/FREEPDB1" \
  username="SYSTEM" \
  password="oracle"

# Create Oracle readonly role
vault write database/roles/oracle-readonly \
  db_name=oracle \
  creation_statements='CREATE USER {{username}} IDENTIFIED BY "{{password}}"; GRANT CONNECT TO {{username}}; GRANT CREATE SESSION TO {{username}};' \
  default_ttl="1h" \
  max_ttl="24h"

# Configure MySQL connection
vault write database/config/mysql \
  plugin_name=mysql-database-plugin \
  connection_url="{{username}}:{{password}}@tcp(mysql:3306)/" \
  allowed_roles="mysql-readonly" \
  username="root" \
  password="mysql"

# Create MySQL readonly role
# IDENTIFIED WITH mysql_native_password ensures the proxy's SHA1-based auth works.
vault write database/roles/mysql-readonly \
  db_name=mysql \
  creation_statements="CREATE USER '{{name}}'@'%' IDENTIFIED WITH mysql_native_password BY '{{password}}'; GRANT SELECT ON *.* TO '{{name}}'@'%';" \
  default_ttl="1h" \
  max_ttl="24h"

echo "Vault setup complete"
