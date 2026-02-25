# Database Proxy - Design Document

## Problem

Applications need database credentials to connect to PostgreSQL (and eventually Oracle, MySQL). This proxy eliminates that by injecting credentials from HashiCorp Vault, using the client's TLS certificate as the sole identity.

## Approach: Auth Intercept + Raw TCP Relay

The proxy only parses the PostgreSQL wire protocol during the authentication phase. Once both sides are authenticated, it switches to bidirectional `io.Copy` relay.

## Architecture

```
Client --TLS+client cert--> Proxy --TCP/TLS--> PostgreSQL
                              |
                              +-TLS cert auth--> Vault
```

Single Go binary. Each client connection:

1. Accepts TLS connection requiring client certificate
2. Extracts client cert, authenticates to Vault via TLS cert auth method
3. Requests dynamic PostgreSQL credentials from Vault database secrets engine
4. Opens connection to PostgreSQL, performs startup + auth with Vault credentials
5. Sends AuthenticationOk + ReadyForQuery to the client (accepts any client credentials)
6. Two goroutines doing `io.Copy` in each direction until either side closes

## PostgreSQL Wire Protocol Handling

### Client-facing (inbound)

1. Client sends SSLRequest -> proxy responds `S` -> TLS handshake with client cert requirement
2. Client sends StartupMessage -> proxy extracts database name and username
3. Proxy sends AuthenticationOk + ReadyForQuery immediately (no real auth)

### Server-facing (outbound)

1. Proxy sends SSLRequest to PostgreSQL -> if `S`, upgrades to TLS
2. Proxy sends StartupMessage with Vault-issued username
3. Proxy handles PostgreSQL SCRAM-SHA-256 auth challenge using Vault-issued password
4. Waits for ReadyForQuery from PostgreSQL

### After both sides ready

- Two goroutines: client->server and server->client via `io.Copy`
- Either side closing tears down both connections

## Vault Integration

- **Auth:** Extract client cert from TLS connection, use Vault TLS cert auth (`/auth/cert/login`), receive Vault token
- **Credentials:** Use token to request from `/database/creds/<role>`, get dynamic username/password
- **No caching or lease renewal** for the PoC - each connection gets fresh credentials
- **Role mapping:** Single Vault database role configured via environment variable or flag

## PoC Docker Setup

Three Docker Compose services:

- **PostgreSQL** - stock `postgres` image with test database
- **Vault** - dev mode, configured with TLS cert auth + database secrets engine + PostgreSQL plugin
- **Proxy** - built from Go source

Supporting files:

- `vault/setup.sh` - Vault initialization (enable auth, configure DB plugin, create roles, load CA)
- `certs/generate.sh` - CA + client cert generation via openssl

## Project Structure

```
database-proxy/
├── main.go
├── go.mod / go.sum
├── proxy/
│   ├── proxy.go          # listener, accept loop, connection handler
│   ├── postgres.go       # PG wire protocol (startup + auth only)
│   └── vault.go          # Vault TLS cert auth + credential fetch
├── docker-compose.yml
├── vault/
│   └── setup.sh
├── certs/
│   └── generate.sh
└── Makefile
```

## Testing

- **Integration test:** `docker compose up`, connect with `psql` using client cert + arbitrary credentials, run a query
- **Manual verification:** Check Vault audit log for cert auth, check `pg_stat_activity` for Vault-issued username
