# Oracle Proxy — Connection Flow Narration

## Step 1 — Client authentication

1. **Client → Proxy: TCP connect** — the app opens a plain TCP socket to the proxy's listen port
2. **Proxy → Client: TLS ServerHello + Proxy cert** — proxy starts a TLS handshake immediately; Oracle clients are not asked for a client certificate (`tls.NoClientCert`)
3. **Client → Proxy: TLS finished** — TLS session is established; all further traffic is encrypted
4. **Client → Proxy: TNS CONNECT (service name)** — client sends the standard Oracle CONNECT packet containing the service name it wants to reach
5. **Proxy: Extract service name** — proxy reads the SERVICE_NAME from the TNS CONNECT payload and stores it for later use

---

## Step 2 — Vault credential fetch

6. **Proxy: Select Vault auth cert** — proxy calls `clientCertAndKey`; because Oracle clients present no TLS client certificate, `clientCN` returns an error and the proxy falls back to its own cert/key
7. **Proxy → Vault: mTLS cert auth (per-connection client)** — proxy creates a fresh Vault client for this connection and authenticates using the proxy's own certificate
8. **Vault → Proxy: Auth OK + token** — Vault issues a short-lived token scoped to the database role
9. **Proxy → Vault: GET /v1/database/creds/oracle-readonly** — proxy requests dynamic credentials for the Oracle role
10. **Vault → Proxy: username + password (short-lived)** — Vault creates a new Oracle user on the fly and returns the credentials; TTL is typically 1 hour

---

## Step 3a — Credential validation (ping, discarded)

11. **Proxy → Oracle: TCP connect (go-ora driver)** — proxy opens a connection to Oracle using the go-ora driver to verify the Vault credentials actually work before committing to the relay
12. **Proxy → Oracle: TLS handshake (SSL VERIFY=FALSE)** — go-ora negotiates TLS; SSL verification is disabled because go-ora cannot accept a custom CA at runtime
13. **Proxy → Oracle: Full TNS auth (Vault creds)** — go-ora performs the complete Oracle authentication with the Vault-issued username and password
14. **Oracle → Proxy: Auth OK** — Oracle confirms the credentials are valid
15. **Proxy ✕ Oracle: Connection closed (ping only)** — this connection is immediately discarded via `defer db.Close()`; its only purpose was credential validation; the driver does not expose the underlying socket for reuse

---

## Step 3b — Raw relay connection

16. **Proxy → Oracle: TCP connect** — proxy opens a second, raw TCP connection to Oracle for the actual relay
17. **Proxy → Oracle: TLS handshake #1** — proxy calls `tls.Dial`, performing the initial TLS handshake on the new connection
18. **Proxy → Oracle: TNS CONNECT** — proxy sends the CONNECT packet (the original payload captured in step 5) over the first TLS session
19. **Oracle → Proxy: TNS RESEND (flag 0x08 — redo TLS)** — Oracle responds with RESEND and flag `0x08`, signalling that it wants a fresh TLS session on the same TCP socket before it will accept the CONNECT; this is Oracle TCPS-specific behaviour
20. **Proxy → Oracle: TLS handshake #2 (same TCP socket)** — proxy extracts the raw TCP socket from the first `*tls.Conn` via `NetConn()` and negotiates a brand-new TLS session on it
21. **Proxy → Oracle: TNS CONNECT (re-send over new TLS)** — proxy re-sends the same CONNECT packet inside the second TLS session
22. **Oracle → Proxy: TNS ACCEPT** — Oracle accepts the session; the raw relay socket is now ready

---

## Step 4 — Accept client

23. **Proxy: Build ACCEPT payload** — proxy constructs the TNS ACCEPT payload from the client's original CONNECT packet (echoing version, SDU/TDU sizes, and flags); Oracle's actual negotiated values are not mirrored
24. **Proxy → Client: TNS ACCEPT** — proxy sends the fabricated ACCEPT to the client, completing the client-side handshake; from the client's perspective it is now connected to Oracle

---

## Step 5 — Raw relay

25–28. **SQL query / Result set (pass-through)** — proxy stops interpreting the protocol entirely; it copies bytes in both directions unchanged. The client talks directly to Oracle through a transparent pipe.
