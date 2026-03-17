# Oracle Proxy — PoC Overview

## What it does

A TCP proxy that sits between Oracle clients and an Oracle database. It authenticates clients using TLS client certificates and injects short-lived Vault-issued credentials for the actual database connection — clients never see or supply database passwords.

```mermaid
flowchart LR
    subgraph Client
        C["Client app<br/>with TLS client cert"]
    end

    subgraph Proxy["Database Proxy"]
        direction TB
        P1["HandleClient<br/>TLS + cert identity"]
        P2["clientCertAndKey<br/>resolve cert by CN"]
        P3["getDBCredentials<br/>Vault cert auth (per-conn)"]
        P4["ConnectAndAuth<br/>TNS handshake"]
        P5["AcceptClient<br/>OK + relay"]
        P1 --> P2 --> P3 --> P4 --> P5
    end

    subgraph Vault["HashiCorp Vault"]
        V1[TLS cert auth]
        V2["Dynamic credentials<br/>Oracle role"]
        V1 --> V2
    end

    subgraph Oracle["Oracle DB"]
        O1["TNS Listener<br/>TCPS / plain"]
    end

    C -- "TCP / TLS + client cert" --> P1
    P3 -- "mTLS (client cert by CN)" --> V1
    V2 -- "short-lived user + password" --> P4
    P4 -- "TCP / TNS CONNECT" --> O1
    P5 -- "raw relay" --> O1
```

```mermaid
sequenceDiagram
    participant C as Client app
    participant P as Proxy
    participant V as Vault
    participant O as Oracle DB

    Note over C,P: Step 1 — Client authentication
    C->>P: TCP connect
    P->>C: TNS ACCEPT (fake)
    C->>P: TLS ClientHello (client cert)
    P->>C: TLS ServerHello + Proxy cert
    Note over P: Verify client cert CN
    C->>P: TLS finished
    C->>P: TNS CONNECT (database name)
    Note over P: Extract database name

    Note over P,V: Step 2 — Vault credential fetch
    Note over P: Resolve client cert by CN (ClientCertDir)
    P->>V: mTLS cert auth (client cert, per-connection)
    V->>P: Auth OK + token
    P->>V: GET /v1/database/creds/oracle-readonly
    V->>P: username + password (short-lived)

    Note over P,O: Step 3a — Credential validation (ping, discarded)
    P->>O: TCP connect (go-ora driver)
    P->>O: TLS handshake
    P->>O: TNS CONNECT + auth (Vault creds)
    O->>P: Auth OK
    P-xO: Connection closed (ping only)

    Note over P,O: Step 3b — Raw relay connection
    P->>O: TCP connect
    P->>O: TLS handshake #1
    P->>O: TNS CONNECT
    O->>P: TNS RESEND (flag 0x08 — redo TLS)
    P->>O: TLS handshake #2 (same TCP socket)
    P->>O: TNS CONNECT (re-send over new TLS)
    O->>P: TNS ACCEPT
    P->>O: Authentication (Vault creds)
    O->>P: Auth OK

    Note over C,P: Step 4 — Accept client
    P->>C: OK packet

    Note over C,O: Step 5 — Raw relay
    C-->>P: SQL query
    P-->>O: SQL query (pass-through)
    O-->>P: Result set
    P-->>C: Result set (pass-through)
```

**Connection flow:**

1. Client connects over TLS presenting a client certificate — the proxy validates the cert (CN is logged for identity)
2. Proxy resolves the client's cert/key by CN from `ClientCertDir`, creates a per-connection Vault client authenticated with that cert, and fetches a short-lived Oracle username/password (falls back to the proxy's own cert when `ClientCertDir` is unset)
3. Proxy connects to Oracle, completes the TNS handshake with Vault credentials
4. Proxy sends TNS ACCEPT to the client; raw bidirectional relay begins

After the handshake, the proxy is transparent — it does not inspect or modify SQL traffic.

---

## What is achieved

- **Zero-password clients** — applications connect with only a TLS certificate; no database password is configured anywhere on the client side
- **Short-lived credentials** — Vault creates a new Oracle user per connection (default TTL 1h), automatically revoked on expiry
- **TCPS support** — the proxy→Oracle leg performs the Oracle-specific TLS renegotiation (TNS RESEND with flag `0x08`) that Oracle requires before accepting a CONNECT over SSL
- **Identity logging** — client certificate CN is captured at connect time, providing an audit trail of who connected

---

## Known issues and trade-offs

**Two DB connections per client**
Each client causes two TCP connections to Oracle: one via `go-ora` `db.Ping()` to validate Vault credentials, and a second raw TCP connection for the actual relay. The driver does not expose its underlying socket, so auth and relay cannot share one connection. A production implementation would authenticate directly on the raw socket and skip the `Ping()`.

**SSL VERIFY disabled on the Ping connection**
`go-ora` cannot be passed a custom CA cert at runtime, so `SSL VERIFY=FALSE` is used for the credential-check connection. The relay connection uses full TLS verification via a custom CA. This means the credential check is susceptible to MITM for that one short-lived call.

**Oracle ACCEPT payload is not mirrored from Oracle**
The TNS ACCEPT sent to the client is constructed from the client's own CONNECT packet rather than forwarded from Oracle's ACCEPT. Oracle's negotiated SDU/TDU values are not propagated — this works in practice but is not spec-compliant.

**No client certificate identity is forwarded**
The client CN is logged but not passed to Oracle as a proxy user or application context (`DBMS_SESSION.SET_IDENTIFIER`). Oracle audit logs show the Vault-issued username, not the original client identity.

**Plain-TCP Oracle not supported**
`HandleClient` requires TCPS — the proxy immediately does a TLS handshake on accept. Plain-TCP Oracle listeners are not supported without code changes.

**No connection pooling**
One Vault lease and one Oracle session are created per client connection. Under high connection rates this will exhaust Vault's lease limit and Oracle's session limit quickly.

**PoC scope — not production-ready**
No connection timeouts, no metrics, no graceful shutdown, no lease renewal, and no handling of Oracle `REDIRECT` packets (used by RAC and some load balancers).
