# Oracle Proxy — Connection Flow Narration

## Step 1 — Client authentication

1. **Client → Proxy: TCP connect** — the app opens a plain TCP socket to the proxy's listen port
2. **Proxy → Client: TNS ACCEPT (fake)** — proxy immediately sends a fabricated TNS ACCEPT to make the Oracle client believe it has reached a real Oracle listener and proceed to TLS
3. **Client → Proxy: TLS ClientHello (client cert)** — client starts TLS and presents its certificate; this is the identity claim
4. **Proxy → Client: TLS ServerHello + Proxy cert** — proxy responds with its own certificate so the client can verify it is talking to a trusted proxy
5. **Proxy: Verify client cert CN** — proxy checks the client certificate against its CA; the CN is logged as the caller's identity
6. **Client → Proxy: TLS finished** — TLS session is established; all further traffic is encrypted
7. **Client → Proxy: TNS CONNECT (database name)** — client sends the standard Oracle CONNECT packet containing the service name it wants to reach
8. **Proxy: Extract database name** — proxy reads the service name from the TNS CONNECT and stores it; the client's credentials (if any) are ignored

---

## Step 2 — Vault credential fetch

9. **Proxy: Resolve cert for Vault auth** — proxy reads the CN from the client's TLS certificate (established in step 5) and looks up `<ClientCertDir>/<cn>.crt` and `<ClientCertDir>/<cn>.key`; if `ClientCertDir` is unset or the lookup fails, the proxy's own cert/key are used as a fallback
10. **Proxy → Vault: mTLS cert auth (per-connection client)** — proxy creates a fresh Vault client for this connection and authenticates using the resolved certificate; this scopes the Vault request to the client's identity rather than the proxy's shared identity
11. **Vault → Proxy: Auth OK + token** — Vault issues a short-lived token scoped to the database role
12. **Proxy → Vault: GET /v1/database/creds/oracle-readonly** — proxy requests dynamic credentials for the Oracle role
13. **Vault → Proxy: username + password (short-lived)** — Vault creates a new Oracle user on the fly and returns the credentials; TTL is typically 1 hour

---

## Step 3a — Credential validation (ping, discarded)

14. **Proxy → Oracle: TCP connect (go-ora driver)** — proxy opens a connection to Oracle using the go-ora driver to verify the Vault credentials actually work before committing to the relay
15. **Proxy → Oracle: TLS handshake** — Oracle requires TLS; driver negotiates it
16. **Proxy → Oracle: TNS CONNECT + auth (Vault creds)** — driver performs the full Oracle authentication with the Vault-issued username and password
17. **Oracle → Proxy: Auth OK** — Oracle confirms the credentials are valid
18. **Proxy ✕ Oracle: Connection closed (ping only)** — this connection is immediately discarded; its only purpose was credential validation; the driver does not expose the underlying socket for reuse

---

## Step 3b — Raw relay connection

19. **Proxy → Oracle: TCP connect** — proxy opens a second, raw TCP connection to Oracle for the actual relay
20. **Proxy → Oracle: TLS handshake #1** — proxy initiates TLS; Oracle accepts but does not yet allow a CONNECT inside this session
21. **Proxy → Oracle: TNS CONNECT** — proxy sends the CONNECT packet (with the service name extracted in step 8) over the first TLS session
22. **Oracle → Proxy: TNS RESEND (flag 0x08 — redo TLS)** — Oracle responds with RESEND and flag `0x08`, signalling that it wants a fresh TLS session on the same TCP socket before it will accept the CONNECT; this is Oracle TCPS-specific behaviour
23. **Proxy → Oracle: TLS handshake #2 (same TCP socket)** — proxy abandons the first TLS session, extracts the raw TCP socket, and negotiates a brand new TLS session on it
24. **Proxy → Oracle: TNS CONNECT (re-send over new TLS)** — proxy re-sends the same CONNECT packet, now inside the second TLS session
25. **Oracle → Proxy: TNS ACCEPT** — Oracle accepts the connection
26. **Proxy → Oracle: Authentication (Vault creds)** — proxy authenticates with the Vault username and password
27. **Oracle → Proxy: Auth OK** — Oracle confirms; the session is ready

---

## Step 4 — Accept client

28. **Proxy → Client: OK packet** — proxy sends a TNS ACCEPT back to the client, completing the client-side handshake; from the client's perspective it is now connected and authenticated to Oracle

---

## Step 5 — Raw relay

29–32. **SQL query / Result set (pass-through)** — proxy stops interpreting the protocol entirely; it copies bytes in both directions unchanged. The client talks directly to Oracle through a transparent pipe.
