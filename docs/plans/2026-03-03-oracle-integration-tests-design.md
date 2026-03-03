# Oracle Integration Tests Design

**Date:** 2026-03-03

## Goal

Add end-to-end integration tests for the Oracle DB path of the database-proxy. Tests verify
that the full stack — client → proxy → Vault → Oracle — works correctly.

## Scope

- Full end-to-end (client uses go-ora driver, hits the proxy, proxy gets Vault dynamic
  credentials, proxy relays to Oracle)
- Tests assume the Docker Compose stack is already running in Oracle mode
- Three scenarios: happy path query, invalid client handling, connection cleanup

## Stack Requirements

Start the stack in Oracle mode before running tests:

```
DB_TYPE=oracle DB_ADDR=oracle:1521 VAULT_DB_ROLE=oracle-readonly docker-compose up --build
```

## File Structure

```
integration/
└── oracle_test.go   (package integration)
```

## Test Design

### TestMain

Dials `localhost:5555` with a 1-second timeout. If unreachable, prints a message and exits 0
(no false failures when the stack isn't running). All tests are skipped automatically.

### TestOracleProxy_HappyPath

- Opens a go-ora connection to `localhost:5555/FREEPDB1` using `SYSTEM/oracle` credentials
  (the Oracle container's root user, password set via `ORACLE_PASSWORD=oracle`)
- Executes `SELECT 1 FROM DUAL`
- Verifies the result is `1`
- Closes the connection

The Oracle handler uses plain TCP (no TLS on the client side — the handler ignores the
`tlsConfig` parameter). No client certificate loading is needed.

### TestOracleProxy_InvalidClient

- Opens a raw `net.Conn` to `localhost:5555` and writes garbage bytes (not a valid TNS CONNECT)
- Expects the proxy to close the connection (read returns EOF or error)
- Verifies the proxy is still alive afterward by dialing `localhost:5555` again successfully

### TestOracleProxy_ConnectionCleanup

- Opens 3 sequential go-ora connections through the proxy
- Runs `SELECT 1 FROM DUAL` on each and closes each connection
- After all 3, verifies the proxy still accepts new connections
- Tests that proxy goroutines clean up correctly after client disconnect

## Known Design Consideration

The oracle handler's `ConnectAndAuth` opens a raw TCP connection to Oracle for the relay,
but the comment "We'll forward the client's CONNECT directly" suggests the original TNS
CONNECT packet should be forwarded to Oracle before the relay begins. This is not yet
implemented in the code. The happy path test will reveal whether the end-to-end flow works
or whether the handler needs a fix to forward the CONNECT packet through the relay.

## Connection Details

| Component    | Address            |
|--------------|--------------------|
| Proxy        | localhost:5555     |
| Oracle       | localhost:1521 (via docker) |
| Service name | FREEPDB1           |
| Test user    | SYSTEM / oracle    |
| Vault role   | oracle-readonly    |
