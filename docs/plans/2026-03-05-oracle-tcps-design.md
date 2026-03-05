# Oracle TCPS Design

**Date:** 2026-03-05
**Goal:** Encrypt both legs of Oracle communication — client→proxy (TCPS) and proxy→Oracle (TCPS) — using the project's existing self-signed CA.

---

## Context

Currently all Oracle traffic is unencrypted TCP. The proxy already supports TLS on the Postgres leg (client→proxy). This design extends TLS to both legs of the Oracle path:

- **Client→Proxy:** proxy wraps the accepted `net.Conn` with `tls.Server` (already done for Postgres; Oracle needs the same)
- **Proxy→Oracle:** proxy dials Oracle with `tls.Dial` instead of `net.Dial`

---

## Section 1 — Certificate Changes

`certs/generate.sh` adds two new artifacts:

- **`oracle-server.key` / `oracle-server.crt`** — Oracle server certificate signed by the existing project CA, with `SAN=DNS:oracle`
- **`oracle.p12`** — PKCS12 bundle (oracle key + cert + CA cert) for Oracle wallet population, with empty passphrase

No new CA or trust anchor is needed. The proxy already loads the project CA for Vault mTLS; it reuses it as `RootCAs` when verifying Oracle's cert.

---

## Section 2 — Oracle TCPS Docker Setup

New directory `oracle/tcps/` with three files:

**`oracle/tcps/sqlnet.ora`:**
```
SQLNET.AUTHENTICATION_SERVICES=(NONE)
SSL_CLIENT_AUTHENTICATION=FALSE
WALLET_LOCATION=(SOURCE=(METHOD=FILE)(METHOD_DATA=(DIRECTORY=/opt/oracle/wallet)))
```

**`oracle/tcps/listener.ora`:**
```
LISTENER =
  (DESCRIPTION_LIST =
    (DESCRIPTION =
      (ADDRESS = (PROTOCOL=TCPS)(HOST=0.0.0.0)(PORT=2484))
    )
  )

SSL_CLIENT_AUTHENTICATION=FALSE
WALLET_LOCATION=(SOURCE=(METHOD=FILE)(METHOD_DATA=(DIRECTORY=/opt/oracle/wallet)))
```

**`oracle/tcps/setup-tcps.sh`** (init script run inside the container via `/container-entrypoint-initdb.d/`):
```sh
#!/bin/bash
mkdir -p /opt/oracle/wallet
orapki wallet create -wallet /opt/oracle/wallet -auto_login_only
orapki wallet import_pkcs12 -wallet /opt/oracle/wallet -auto_login_only \
  -pkcs12file /tcps-certs/oracle.p12 -pkcs12pwd ""
cp /tcps-config/sqlnet.ora /opt/oracle/oradata/tns/sqlnet.ora
cp /tcps-config/listener.ora /opt/oracle/oradata/tns/listener.ora
lsnrctl reload
```

`docker-compose.yml` oracle service changes:
- Mount `./certs/out:/tcps-certs:ro`
- Mount `./oracle/tcps:/tcps-config:ro`
- Mount `./oracle/tcps/setup-tcps.sh:/container-entrypoint-initdb.d/01-setup-tcps.sh:ro`
- Add port `2484:2484`

Proxy service: change `DB_ADDR` to `oracle:2484`.

---

## Section 3 — Proxy Code Changes

**`oracle/handler.go`:**

`Handler` struct gains one field:
```go
oracleTLS *tls.Config  // nil = plain TCP (for non-Oracle or testing)
```

`ConnectAndAuth` replaces `net.Dial` with `tls.Dial` when `oracleTLS` is non-nil:
```go
if h.oracleTLS != nil {
    conn, err = tls.Dial("tcp", h.oracleAddr, h.oracleTLS)
} else {
    conn, err = net.Dial("tcp", h.oracleAddr)
}
```

**`main.go`** builds `oracleTLS` from existing env vars:
```go
oracleTLS := &tls.Config{
    RootCAs:    caPool,      // already loaded from TLS_CA
    ServerName: "oracle",    // matches SAN on oracle-server.crt
}
```

No new env vars. Oracle addr changes via existing `DB_ADDR=oracle:2484`.

---

## Section 4 — Integration Test Changes

**`integration/oracle_test.go`** — `oracleDB` helper adds SSL options:
```go
connStr := go_ora.BuildUrl(host, portNum, serviceName, oracleUser, oraclePass, map[string]string{
    "CID":        "(CID=(PROGRAM=test)(HOST=test)(USER=test))",
    "SSL":        "TRUE",
    "SSL VERIFY": "FALSE",  // test talks to proxy, not Oracle directly
})
```

`TestOracleProxy_UnknownServiceName` — raw TCP dial becomes TLS:
```go
tlsCfg := &tls.Config{InsecureSkipVerify: true}
conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", proxyAddr, tlsCfg)
```

`SSL VERIFY=FALSE` is acceptable for integration tests because the security property being tested is the proxy↔Oracle leg, not the test client↔proxy leg.

---

## Summary

| Component | Change |
|---|---|
| `certs/generate.sh` | Add `oracle-server.key/crt` + `oracle.p12` |
| `oracle/tcps/` | New dir: `sqlnet.ora`, `listener.ora`, `setup-tcps.sh` |
| `docker-compose.yml` | Oracle: mounts + port 2484; Proxy: `DB_ADDR=oracle:2484` |
| `oracle/handler.go` | `oracleTLS` field; `tls.Dial` in `ConnectAndAuth` |
| `main.go` | Build `oracleTLS` config from existing CA |
| `integration/oracle_test.go` | `SSL=TRUE`; raw dial → TLS dial |
