# MySQL Proxy - Design Document

## Goal

Add MySQL support to the database proxy using the same pattern as PostgreSQL and Oracle: TLS client cert identity, Vault-issued credentials, raw TCP relay after auth.

## Architecture

```
Client --TLS+client cert--> Proxy --TCP--> MySQL
                              |
                              +-TLS cert auth--> Vault
```

Same 4-step flow as existing handlers:

1. **HandleClient** — proxy acts as MySQL server: sends fake Initial Handshake to client, client upgrades to TLS, proxy reads HandshakeResponse, extracts database name, ignores client credentials
2. **getDBCredentials** — Vault TLS cert auth + fetch dynamic MySQL credentials
3. **ConnectAndAuth** — `go-sql-driver/mysql` Ping to validate creds; raw TCP to MySQL, full manual handshake with Vault credentials
4. **AcceptClient** — send OK to client, return raw connection for relay

## MySQL Protocol Handling

### Packet framing

All MySQL packets: 3-byte payload length (little-endian) + 1-byte sequence number + payload.

### HandleClient (proxy acting as MySQL server to client)

1. Send fabricated Initial Handshake (protocol v10, fake server version, 20 random challenge bytes, capability flags including `CLIENT_SSL | CLIENT_PLUGIN_AUTH`, auth plugin `mysql_native_password`)
2. Read SSL Request from client
3. TLS handshake requiring client certificate; log CN from cert
4. Read `HandshakeResponse41` over TLS — extract database name; ignore username/password
5. Store database name on connection wrapper

### ConnectAndAuth (proxy→MySQL)

1. `go-sql-driver/mysql` `db.Ping()` with Vault creds to validate credentials
2. Raw `net.Dial` to MySQL
3. Read MySQL's Initial Handshake — capture 20-byte challenge nonce and auth plugin name
4. Send HandshakeResponse with Vault username, `mysql_native_password` response: `SHA1(password) XOR SHA1(nonce + SHA1(SHA1(password)))`, and database name
5. Handle optional AuthSwitchRequest, then read OK

### AcceptClient

Send OK packet (sequence 2) to client; return raw MySQL `net.Conn` for relay.

## Auth Plugin Strategy

Vault role creation uses `IDENTIFIED WITH mysql_native_password BY '{{password}}'` so Vault-issued users always authenticate with `mysql_native_password`. This means only SHA1-based auth is needed on the proxy→MySQL leg — no RSA or `caching_sha2_password` complexity.

## TLS

- **Client→Proxy:** TLS with required client certificate (existing `tlsConfig` from proxy.Config)
- **Proxy→MySQL:** Plain TCP for now; TLS can be added later following the Oracle pattern

## New Files

- `mysql/handler.go` — `Handler` struct implementing `proxy.DBHandler`
- `mysql/myproto.go` — packet helpers, fake handshake builder, `mysql_native_password` computation, OK packet builder

## Modified Files

- `main.go` — add `case "mysql": handler = &mysql.Handler{}`
- `docker-compose.yml` — add `mysql:8.0` service with healthcheck
- `vault/setup.sh` — add `database/config/mysql` + `database/roles/mysql-readonly`

## Environment Variables

No new variables needed. Use existing: `DB_TYPE=mysql`, `DB_ADDR=mysql:3306`, `VAULT_DB_ROLE=mysql-readonly`.
