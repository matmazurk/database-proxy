# Database Proxy Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a PoC database proxy that injects Vault-sourced PostgreSQL credentials using the client's TLS certificate for Vault authentication.

**Architecture:** Auth intercept + raw TCP relay. The proxy parses PostgreSQL wire protocol only during startup/auth, then switches to bidirectional `io.Copy`. Vault's TLS cert auth method authenticates clients, and Vault's database secrets engine provides dynamic PostgreSQL credentials.

**Tech Stack:** Go, PostgreSQL wire protocol, HashiCorp Vault (TLS cert auth + database secrets engine), Docker Compose

---

### Task 1: Project Scaffolding

**Files:**
- Create: `go.mod`
- Create: `main.go`
- Create: `Makefile`

**Step 1: Initialize Go module**

Run: `go mod init github.com/matmazurk/database-proxy`

**Step 2: Create minimal main.go**

```go
package main

import "fmt"

func main() {
	fmt.Println("database-proxy")
}
```

**Step 3: Create Makefile**

```makefile
.PHONY: build run

build:
	go build -o bin/database-proxy .

run: build
	./bin/database-proxy
```

**Step 4: Verify it builds**

Run: `make build`
Expected: binary at `bin/database-proxy`

**Step 5: Commit**

```bash
git add go.mod main.go Makefile
git commit -m "scaffold project"
```

---

### Task 2: Certificate Generation Script

**Files:**
- Create: `certs/generate.sh`

**Step 1: Write the certificate generation script**

This script generates:
- A CA key + cert
- A server cert for the proxy (SAN: localhost)
- A client cert signed by the CA (for client connections to the proxy)

```bash
#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
OUT="$DIR/out"
rm -rf "$OUT"
mkdir -p "$OUT"

# CA
openssl genrsa -out "$OUT/ca.key" 2048
openssl req -new -x509 -key "$OUT/ca.key" -out "$OUT/ca.crt" -days 365 \
  -subj "/CN=database-proxy-ca"

# Proxy server cert
openssl genrsa -out "$OUT/proxy-server.key" 2048
openssl req -new -key "$OUT/proxy-server.key" -out "$OUT/proxy-server.csr" \
  -subj "/CN=localhost"
openssl x509 -req -in "$OUT/proxy-server.csr" -CA "$OUT/ca.crt" -CAkey "$OUT/ca.key" \
  -CAcreateserial -out "$OUT/proxy-server.crt" -days 365 \
  -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1")

# Client cert (used by psql to connect to proxy, and by proxy to auth to Vault)
openssl genrsa -out "$OUT/client.key" 2048
openssl req -new -key "$OUT/client.key" -out "$OUT/client.csr" \
  -subj "/CN=test-client"
openssl x509 -req -in "$OUT/client.csr" -CA "$OUT/ca.crt" -CAkey "$OUT/ca.key" \
  -CAcreateserial -out "$OUT/client.crt" -days 365

# Cleanup CSRs
rm -f "$OUT"/*.csr "$OUT"/*.srl

echo "Certificates generated in $OUT/"
ls -la "$OUT/"
```

**Step 2: Run and verify**

Run: `chmod +x certs/generate.sh && certs/generate.sh`
Expected: Files in `certs/out/`: `ca.key`, `ca.crt`, `proxy-server.key`, `proxy-server.crt`, `client.key`, `client.crt`

**Step 3: Add .gitignore for generated certs**

Create `certs/.gitignore`:
```
out/
```

**Step 4: Commit**

```bash
git add certs/generate.sh certs/.gitignore
git commit -m "add certificate generation script"
```

---

### Task 3: PostgreSQL Wire Protocol Messages

**Files:**
- Create: `proxy/pgproto.go`

Implement the minimal set of PostgreSQL wire protocol message types needed for startup and auth. Reference: https://www.postgresql.org/docs/current/protocol-message-formats.html

**Step 1: Write message types and parsing**

```go
package proxy

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

// SSLRequest is the magic number clients send to request TLS.
const sslRequestCode = 80877103

// ReadStartupOrSSL reads the first message from a client.
// Returns (isSSL, params map, error).
// If isSSL is true, params is nil - caller should upgrade to TLS and read again.
func ReadStartupOrSSL(r io.Reader) (bool, map[string]string, error) {
	// First 4 bytes: message length (including self)
	var length int32
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return false, nil, fmt.Errorf("reading length: %w", err)
	}

	// Next 4 bytes: protocol version or SSL request code
	var code int32
	if err := binary.Read(r, binary.BigEndian, &code); err != nil {
		return false, nil, fmt.Errorf("reading code: %w", err)
	}

	if code == sslRequestCode {
		return true, nil, nil
	}

	// It's a StartupMessage. Read the rest as null-terminated key-value pairs.
	remaining := make([]byte, length-8) // subtract length(4) + code(4)
	if _, err := io.ReadFull(r, remaining); err != nil {
		return false, nil, fmt.Errorf("reading params: %w", err)
	}

	params := make(map[string]string)
	parts := bytes.Split(remaining, []byte{0})
	for i := 0; i+1 < len(parts); i += 2 {
		key := string(parts[i])
		val := string(parts[i+1])
		if key == "" {
			break
		}
		params[key] = val
	}

	return false, params, nil
}

// WriteSSLAccept writes the 'S' byte indicating SSL is supported.
func WriteSSLAccept(w io.Writer) error {
	_, err := w.Write([]byte{'S'})
	return err
}

// WriteAuthenticationOk sends AuthenticationOk (type 'R', status 0).
func WriteAuthenticationOk(w io.Writer) error {
	// Type 'R' + length 8 + status 0
	msg := []byte{'R', 0, 0, 0, 8, 0, 0, 0, 0}
	_, err := w.Write(msg)
	return err
}

// WriteReadyForQuery sends ReadyForQuery with 'I' (idle) status.
func WriteReadyForQuery(w io.Writer) error {
	// Type 'Z' + length 5 + status 'I'
	msg := []byte{'Z', 0, 0, 0, 5, 'I'}
	_, err := w.Write(msg)
	return err
}

// BuildStartupMessage creates a StartupMessage for the server connection.
func BuildStartupMessage(user, database string) []byte {
	var buf bytes.Buffer

	// Placeholder for length
	buf.Write([]byte{0, 0, 0, 0})

	// Protocol version 3.0
	binary.Write(&buf, binary.BigEndian, int32(196608))

	// Parameters
	buf.WriteString("user")
	buf.WriteByte(0)
	buf.WriteString(user)
	buf.WriteByte(0)
	buf.WriteString("database")
	buf.WriteByte(0)
	buf.WriteString(database)
	buf.WriteByte(0)

	// Terminating null
	buf.WriteByte(0)

	// Write length
	msg := buf.Bytes()
	binary.BigEndian.PutUint32(msg[0:4], uint32(len(msg)))
	return msg
}

// ReadMessage reads a single protocol message (type byte + length + payload).
// Returns (msgType, payload, error). Payload does not include the type or length bytes.
func ReadMessage(r io.Reader) (byte, []byte, error) {
	var msgType [1]byte
	if _, err := io.ReadFull(r, msgType[:]); err != nil {
		return 0, nil, err
	}

	var length int32
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return 0, nil, err
	}

	payload := make([]byte, length-4) // length includes itself
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}

	return msgType[0], payload, nil
}

// WriteMessage writes a protocol message (type byte + length + payload).
func WriteMessage(w io.Writer, msgType byte, payload []byte) error {
	length := int32(len(payload) + 4)
	if _, err := w.Write([]byte{msgType}); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, length); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}
```

**Step 2: Verify it compiles**

Run: `go build ./proxy/...`
Expected: no errors

**Step 3: Commit**

```bash
git add proxy/pgproto.go
git commit -m "add PostgreSQL wire protocol message types"
```

---

### Task 4: SCRAM-SHA-256 Client Implementation

**Files:**
- Create: `proxy/scram.go`

The proxy acts as a SCRAM-SHA-256 **client** when authenticating to PostgreSQL. PostgreSQL sends AuthenticationSASL, the proxy responds with SASLInitialResponse + SASLResponse messages.

Reference: https://www.postgresql.org/docs/current/sasl-authentication.html and RFC 5802.

**Step 1: Implement SCRAM client**

Use the `github.com/xdg-go/scram` library for the SCRAM conversation.

```go
package proxy

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/xdg-go/scram"
)

// PerformSCRAMAuth performs SCRAM-SHA-256 authentication on a server connection.
// The caller has already sent StartupMessage and read back an AuthenticationSASL
// message (msgType 'R', status 10) whose payload lists supported mechanisms.
func PerformSCRAMAuth(conn io.ReadWriter, password string, saslPayload []byte) error {
	// Verify SCRAM-SHA-256 is offered
	if !containsMechanism(saslPayload, "SCRAM-SHA-256") {
		return fmt.Errorf("server does not support SCRAM-SHA-256")
	}

	client, err := scram.SHA256.NewClient("", password, "")
	if err != nil {
		return fmt.Errorf("creating SCRAM client: %w", err)
	}
	conv := client.NewConversation()

	// Step 1: client-first-message
	clientFirst, err := conv.Step("")
	if err != nil {
		return fmt.Errorf("SCRAM step 1: %w", err)
	}

	// Send SASLInitialResponse (password message type 'p')
	if err := writeSASLInitialResponse(conn, "SCRAM-SHA-256", []byte(clientFirst)); err != nil {
		return fmt.Errorf("sending SASLInitialResponse: %w", err)
	}

	// Read AuthenticationSASLContinue (type 'R', status 11)
	msgType, payload, err := ReadMessage(conn)
	if err != nil {
		return fmt.Errorf("reading SASLContinue: %w", err)
	}
	if msgType != 'R' || binary.BigEndian.Uint32(payload[:4]) != 11 {
		return fmt.Errorf("expected AuthenticationSASLContinue, got type=%c status=%d", msgType, binary.BigEndian.Uint32(payload[:4]))
	}
	serverFirst := string(payload[4:])

	// Step 2: client-final-message
	clientFinal, err := conv.Step(serverFirst)
	if err != nil {
		return fmt.Errorf("SCRAM step 2: %w", err)
	}

	// Send SASLResponse (password message type 'p')
	if err := WriteMessage(conn, 'p', []byte(clientFinal)); err != nil {
		return fmt.Errorf("sending SASLResponse: %w", err)
	}

	// Read AuthenticationSASLFinal (type 'R', status 12)
	msgType, payload, err = ReadMessage(conn)
	if err != nil {
		return fmt.Errorf("reading SASLFinal: %w", err)
	}
	if msgType != 'R' || binary.BigEndian.Uint32(payload[:4]) != 12 {
		return fmt.Errorf("expected AuthenticationSASLFinal, got type=%c status=%d", msgType, binary.BigEndian.Uint32(payload[:4]))
	}
	serverFinal := string(payload[4:])

	// Step 3: validate server signature
	_, err = conv.Step(serverFinal)
	if err != nil {
		return fmt.Errorf("SCRAM step 3 (server validation): %w", err)
	}

	// Read AuthenticationOk (type 'R', status 0)
	msgType, payload, err = ReadMessage(conn)
	if err != nil {
		return fmt.Errorf("reading AuthenticationOk: %w", err)
	}
	if msgType != 'R' || binary.BigEndian.Uint32(payload[:4]) != 0 {
		return fmt.Errorf("expected AuthenticationOk, got type=%c status=%d", msgType, binary.BigEndian.Uint32(payload[:4]))
	}

	return nil
}

func containsMechanism(payload []byte, mech string) bool {
	// After the 4-byte status code, mechanisms are null-terminated strings
	data := payload[4:]
	for len(data) > 0 {
		idx := 0
		for idx < len(data) && data[idx] != 0 {
			idx++
		}
		if string(data[:idx]) == mech {
			return true
		}
		if idx < len(data) {
			data = data[idx+1:]
		} else {
			break
		}
	}
	return false
}

func writeSASLInitialResponse(w io.Writer, mechanism string, data []byte) error {
	var buf []byte
	buf = append(buf, mechanism...)
	buf = append(buf, 0) // null terminator for mechanism name
	// 4-byte length of client-first-message
	lenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBytes, uint32(len(data)))
	buf = append(buf, lenBytes...)
	buf = append(buf, data...)
	return WriteMessage(w, 'p', buf)
}
```

**Step 2: Add dependency**

Run: `go get github.com/xdg-go/scram`

**Step 3: Verify it compiles**

Run: `go build ./proxy/...`
Expected: no errors

**Step 4: Commit**

```bash
git add proxy/scram.go go.mod go.sum
git commit -m "add SCRAM-SHA-256 auth client"
```

---

### Task 5: Vault Client

**Files:**
- Create: `proxy/vault.go`

**Step 1: Implement Vault client**

Uses Vault HTTP API directly (no Vault SDK to keep dependencies minimal).

```go
package proxy

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
)

type VaultClient struct {
	addr   string
	client *http.Client
}

type DBCredentials struct {
	Username string
	Password string
}

func NewVaultClient(addr string) *VaultClient {
	return &VaultClient{
		addr:   addr,
		client: &http.Client{},
	}
}

// AuthWithCert authenticates to Vault using the TLS cert auth method.
// Takes the client certificate from the proxy's TLS connection.
// Returns a Vault token.
func (v *VaultClient) AuthWithCert(clientCert *x509.Certificate) (string, error) {
	// Encode cert to PEM
	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: clientCert.Raw,
	})

	body, _ := json.Marshal(map[string]string{})
	req, err := http.NewRequest("POST", v.addr+"/v1/auth/cert/login", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("creating request: %w", err)
	}

	// For TLS cert auth, we need to present the client cert in the TLS connection to Vault.
	// Create a custom transport with the client cert.
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // PoC only - Vault in dev mode
			Certificates: []tls.Certificate{
				{
					Certificate: [][]byte{clientCert.Raw},
				},
			},
		},
	}
	_ = pemBlock // cert is passed via TLS, not in request body
	client := &http.Client{Transport: transport}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("auth request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("auth failed (status %d): %s", resp.StatusCode, respBody)
	}

	var result struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decoding response: %w", err)
	}

	return result.Auth.ClientToken, nil
}

// GetDBCredentials requests dynamic database credentials from Vault.
func (v *VaultClient) GetDBCredentials(token, role string) (*DBCredentials, error) {
	req, err := http.NewRequest("GET", v.addr+"/v1/database/creds/"+role, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("X-Vault-Token", token)

	resp, err := v.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("creds request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("creds failed (status %d): %s", resp.StatusCode, respBody)
	}

	var result struct {
		Data struct {
			Username string `json:"username"`
			Password string `json:"password"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return &DBCredentials{
		Username: result.Data.Username,
		Password: result.Data.Password,
	}, nil
}
```

**Step 2: Verify it compiles**

Run: `go build ./proxy/...`
Expected: no errors

**Step 3: Commit**

```bash
git add proxy/vault.go
git commit -m "add Vault client for cert auth and credential fetch"
```

---

### Task 6: Proxy Core - Connection Handler

**Files:**
- Create: `proxy/proxy.go`

**Step 1: Implement the proxy listener and connection handler**

```go
package proxy

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
)

type Config struct {
	ListenAddr  string
	TLSCert     string
	TLSKey      string
	TLSCA       string
	PGAddr      string
	VaultAddr   string
	VaultDBRole string
}

type Proxy struct {
	cfg         Config
	tlsConfig   *tls.Config
	vaultClient *VaultClient
}

func New(cfg Config) (*Proxy, error) {
	tlsCert, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
	if err != nil {
		return nil, fmt.Errorf("loading TLS cert: %w", err)
	}

	caCert, err := os.ReadFile(cfg.TLSCA)
	if err != nil {
		return nil, fmt.Errorf("reading CA cert: %w", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA cert")
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}

	return &Proxy{
		cfg:         cfg,
		tlsConfig:   tlsConfig,
		vaultClient: NewVaultClient(cfg.VaultAddr),
	}, nil
}

func (p *Proxy) Listen() error {
	ln, err := net.Listen("tcp", p.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer ln.Close()

	log.Printf("proxy listening on %s", p.cfg.ListenAddr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		go p.handleConnection(conn)
	}
}

func (p *Proxy) handleConnection(clientRaw net.Conn) {
	defer clientRaw.Close()

	// 1. Read SSLRequest from client
	isSSL, _, err := ReadStartupOrSSL(clientRaw)
	if err != nil {
		log.Printf("reading initial message: %v", err)
		return
	}
	if !isSSL {
		log.Printf("client did not send SSLRequest, rejecting")
		return
	}

	// 2. Accept SSL and upgrade
	if err := WriteSSLAccept(clientRaw); err != nil {
		log.Printf("writing SSL accept: %v", err)
		return
	}

	clientTLS := tls.Server(clientRaw, p.tlsConfig)
	if err := clientTLS.Handshake(); err != nil {
		log.Printf("TLS handshake failed: %v", err)
		return
	}
	defer clientTLS.Close()

	// 3. Extract client certificate
	state := clientTLS.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		log.Printf("no client certificate provided")
		return
	}
	clientCert := state.PeerCertificates[0]
	log.Printf("client connected: CN=%s", clientCert.Subject.CommonName)

	// 4. Read StartupMessage from client
	_, params, err := ReadStartupOrSSL(clientTLS)
	if err != nil {
		log.Printf("reading startup message: %v", err)
		return
	}
	database := params["database"]
	log.Printf("client requests database: %s", database)

	// 5. Auth to Vault and get DB credentials
	vaultToken, err := p.vaultClient.AuthWithCert(clientCert)
	if err != nil {
		log.Printf("Vault auth failed: %v", err)
		return
	}

	creds, err := p.vaultClient.GetDBCredentials(vaultToken, p.cfg.VaultDBRole)
	if err != nil {
		log.Printf("Vault get creds failed: %v", err)
		return
	}
	log.Printf("got Vault credentials: user=%s", creds.Username)

	// 6. Connect to PostgreSQL
	pgConn, err := net.Dial("tcp", p.cfg.PGAddr)
	if err != nil {
		log.Printf("connecting to PostgreSQL: %v", err)
		return
	}
	defer pgConn.Close()

	// 7. Send StartupMessage to PostgreSQL
	startupMsg := BuildStartupMessage(creds.Username, database)
	if _, err := pgConn.Write(startupMsg); err != nil {
		log.Printf("sending startup to PG: %v", err)
		return
	}

	// 8. Handle SCRAM auth with PostgreSQL
	msgType, payload, err := ReadMessage(pgConn)
	if err != nil {
		log.Printf("reading auth request from PG: %v", err)
		return
	}
	if msgType != 'R' {
		log.Printf("unexpected message type from PG: %c", msgType)
		return
	}
	authType := binary.BigEndian.Uint32(payload[:4])
	if authType != 10 { // AuthenticationSASL
		log.Printf("expected SASL auth (10), got: %d", authType)
		return
	}

	if err := PerformSCRAMAuth(pgConn, creds.Password, payload); err != nil {
		log.Printf("SCRAM auth failed: %v", err)
		return
	}

	// 9. Read until ReadyForQuery from PostgreSQL
	for {
		msgType, _, err := ReadMessage(pgConn)
		if err != nil {
			log.Printf("reading from PG: %v", err)
			return
		}
		if msgType == 'Z' { // ReadyForQuery
			break
		}
		// Skip ParameterStatus ('S') and BackendKeyData ('K') messages
	}

	// 10. Tell client auth succeeded
	if err := WriteAuthenticationOk(clientTLS); err != nil {
		log.Printf("writing AuthOk to client: %v", err)
		return
	}
	if err := WriteReadyForQuery(clientTLS); err != nil {
		log.Printf("writing ReadyForQuery to client: %v", err)
		return
	}

	// 11. Bidirectional relay
	log.Printf("starting relay")
	errc := make(chan error, 2)
	go func() { _, err := io.Copy(pgConn, clientTLS); errc <- err }()
	go func() { _, err := io.Copy(clientTLS, pgConn); errc <- err }()
	<-errc
	log.Printf("connection closed")
}
```

Note: this file will need `"crypto/x509"`, `"encoding/binary"`, and `"os"` imports added.

**Step 2: Verify it compiles**

Run: `go build ./proxy/...`
Expected: no errors (fix any import issues)

**Step 3: Commit**

```bash
git add proxy/proxy.go
git commit -m "add proxy core connection handler"
```

---

### Task 7: Main Entry Point

**Files:**
- Modify: `main.go`

**Step 1: Wire up main.go with flags**

```go
package main

import (
	"flag"
	"log"

	"github.com/matmazurk/database-proxy/proxy"
)

func main() {
	cfg := proxy.Config{}
	flag.StringVar(&cfg.ListenAddr, "listen", ":5555", "proxy listen address")
	flag.StringVar(&cfg.TLSCert, "tls-cert", "", "path to proxy TLS certificate")
	flag.StringVar(&cfg.TLSKey, "tls-key", "", "path to proxy TLS private key")
	flag.StringVar(&cfg.TLSCA, "tls-ca", "", "path to CA certificate for client cert verification")
	flag.StringVar(&cfg.PGAddr, "pg-addr", "localhost:5432", "PostgreSQL address")
	flag.StringVar(&cfg.VaultAddr, "vault-addr", "http://localhost:8200", "Vault address")
	flag.StringVar(&cfg.VaultDBRole, "vault-db-role", "readonly", "Vault database role name")
	flag.Parse()

	p, err := proxy.New(cfg)
	if err != nil {
		log.Fatalf("creating proxy: %v", err)
	}

	log.Fatal(p.Listen())
}
```

**Step 2: Verify it compiles**

Run: `go build .`
Expected: binary builds successfully

**Step 3: Commit**

```bash
git add main.go
git commit -m "wire up main entry point with flags"
```

---

### Task 8: Docker Compose + Vault Setup

**Files:**
- Create: `docker-compose.yml`
- Create: `vault/setup.sh`
- Create: `Dockerfile`

**Step 1: Create Dockerfile**

```dockerfile
FROM golang:1.23-alpine AS build
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o /database-proxy .

FROM alpine:3.19
COPY --from=build /database-proxy /database-proxy
ENTRYPOINT ["/database-proxy"]
```

**Step 2: Create docker-compose.yml**

```yaml
services:
  postgres:
    image: postgres:16
    environment:
      POSTGRES_PASSWORD: postgres
      POSTGRES_DB: testdb
    ports:
      - "5432:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 2s
      timeout: 5s
      retries: 10

  vault:
    image: hashicorp/vault:1.15
    cap_add:
      - IPC_LOCK
    environment:
      VAULT_DEV_ROOT_TOKEN_ID: root
      VAULT_DEV_LISTEN_ADDRESS: "0.0.0.0:8200"
    ports:
      - "8200:8200"
    volumes:
      - ./certs/out:/certs:ro
      - ./vault:/vault-setup:ro
    healthcheck:
      test: ["CMD", "vault", "status"]
      interval: 2s
      timeout: 5s
      retries: 10

  vault-setup:
    image: hashicorp/vault:1.15
    depends_on:
      vault:
        condition: service_healthy
      postgres:
        condition: service_healthy
    environment:
      VAULT_ADDR: "http://vault:8200"
      VAULT_TOKEN: root
    volumes:
      - ./certs/out:/certs:ro
      - ./vault:/vault-setup:ro
    entrypoint: /bin/sh
    command: /vault-setup/setup.sh
    restart: "no"

  proxy:
    build: .
    depends_on:
      vault-setup:
        condition: service_completed_successfully
    ports:
      - "5555:5555"
    volumes:
      - ./certs/out:/certs:ro
    command:
      - "-listen=:5555"
      - "-tls-cert=/certs/proxy-server.crt"
      - "-tls-key=/certs/proxy-server.key"
      - "-tls-ca=/certs/ca.crt"
      - "-pg-addr=postgres:5432"
      - "-vault-addr=http://vault:8200"
      - "-vault-db-role=readonly"
```

**Step 3: Create vault/setup.sh**

```bash
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
```

**Step 4: Update Makefile**

Add Docker targets:

```makefile
.PHONY: build run certs up down

build:
	go build -o bin/database-proxy .

run: build
	./bin/database-proxy

certs:
	./certs/generate.sh

up: certs
	docker compose up --build

down:
	docker compose down -v
```

**Step 5: Commit**

```bash
git add Dockerfile docker-compose.yml vault/setup.sh Makefile
git commit -m "add Docker Compose setup with Vault and PostgreSQL"
```

---

### Task 9: Integration Test

**Step 1: Test the full flow**

Run: `make up`

Wait for all services to start, then in another terminal:

```bash
PGPASSWORD=anything psql \
  "host=localhost port=5555 dbname=testdb user=ignored sslmode=verify-ca sslrootcert=certs/out/ca.crt sslcert=certs/out/client.crt sslkey=certs/out/client.key" \
  -c "SELECT current_user;"
```

Expected: The query succeeds and `current_user` shows a Vault-generated username (like `v-cert-readonly-...`), **not** `ignored` or `postgres`.

**Step 2: Verify in PostgreSQL**

```bash
PGPASSWORD=postgres psql "host=localhost port=5432 dbname=testdb user=postgres" \
  -c "SELECT usename FROM pg_stat_activity WHERE datname='testdb';"
```

Expected: See the Vault-generated username in the active connections.

**Step 3: Tear down**

Run: `make down`
