# MySQL Proxy Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a MySQL handler to the database proxy so clients can connect via TLS+client cert, with credentials injected from Vault, using the same `DBHandler` interface as PostgreSQL and Oracle.

**Architecture:** Proxy fabricates a fake MySQL Initial Handshake to the client, forces TLS upgrade (requiring client cert), reads the `HandshakeResponse41` to extract the database name (ignoring client credentials), then validates Vault credentials via `go-sql-driver/mysql` Ping and opens a raw TCP connection to MySQL performing the full handshake with `mysql_native_password` auth. Vault users are created with `IDENTIFIED WITH mysql_native_password` so SHA1-based auth is always used on the proxy→MySQL leg.

**Tech Stack:** Go 1.25, `github.com/go-sql-driver/mysql` (new dependency), standard `crypto/sha1`, `crypto/tls`, `net`.

---

### Task 1: MySQL packet helpers and auth computation

**Files:**
- Create: `mysql/myproto.go`
- Create: `mysql/myproto_test.go`

**Background:** All MySQL packets have a 4-byte header: 3 bytes payload length (little-endian) + 1 byte sequence number. `mysql_native_password` auth token = `SHA1(password) XOR SHA1(challenge + SHA1(SHA1(password)))` where challenge is the 20-byte nonce from the server.

**Step 1: Create `mysql/myproto.go` with packet framing and auth**

```go
package mysql

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"io"
)

// Capability flags used in handshake packets.
const (
	capLongPassword    = uint32(0x00000001)
	capLongFlag        = uint32(0x00000004)
	capConnectWithDB   = uint32(0x00000008)
	capProtocol41      = uint32(0x00000200)
	capSSL             = uint32(0x00000800)
	capSecureConn      = uint32(0x00008000)
	capPluginAuth      = uint32(0x00080000)
)

// readPacket reads one MySQL packet and returns (sequenceID, payload, error).
func readPacket(r io.Reader) (byte, []byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		return 0, nil, fmt.Errorf("reading packet header: %w", err)
	}
	length := int(uint32(header[0]) | uint32(header[1])<<8 | uint32(header[2])<<16)
	seq := header[3]
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, fmt.Errorf("reading packet payload: %w", err)
	}
	return seq, payload, nil
}

// writePacket writes a MySQL packet with the given sequence number and payload.
func writePacket(w io.Writer, seq byte, payload []byte) error {
	header := make([]byte, 4)
	length := len(payload)
	header[0] = byte(length)
	header[1] = byte(length >> 8)
	header[2] = byte(length >> 16)
	header[3] = seq
	if _, err := w.Write(header); err != nil {
		return fmt.Errorf("writing packet header: %w", err)
	}
	if _, err := w.Write(payload); err != nil {
		return fmt.Errorf("writing packet payload: %w", err)
	}
	return nil
}

// nativePasswordAuth computes the mysql_native_password auth response:
//
//	token = SHA1(password) XOR SHA1(challenge + SHA1(SHA1(password)))
//
// Returns nil for an empty password.
func nativePasswordAuth(password string, challenge []byte) []byte {
	if password == "" {
		return nil
	}
	h1 := sha1.Sum([]byte(password))
	h2 := sha1.Sum(h1[:])
	h := sha1.New()
	h.Write(challenge)
	h.Write(h2[:])
	h3 := h.Sum(nil)
	token := make([]byte, sha1.Size)
	for i := range token {
		token[i] = h1[i] ^ h3[i]
	}
	return token
}

// buildInitialHandshake builds a Protocol::HandshakeV10 payload.
// challenge must be exactly 20 bytes.
// Advertises CLIENT_SSL so the client will send an SSLRequest before HandshakeResponse.
func buildInitialHandshake(connID uint32, challenge []byte) []byte {
	caps := capLongPassword | capLongFlag | capConnectWithDB |
		capProtocol41 | capSSL | capSecureConn | capPluginAuth

	var b bytes.Buffer
	b.WriteByte(10)                                                     // protocol version
	b.WriteString("8.0.0-proxy\x00")                                   // server version
	binary.Write(&b, binary.LittleEndian, connID)                      // connection id
	b.Write(challenge[:8])                                             // auth-plugin-data-part-1
	b.WriteByte(0x00)                                                  // filler
	binary.Write(&b, binary.LittleEndian, uint16(caps))                // capability flags (lower 2 bytes)
	b.WriteByte(0x21)                                                  // character set: utf8
	binary.Write(&b, binary.LittleEndian, uint16(0x0002))              // status flags: SERVER_STATUS_AUTOCOMMIT
	binary.Write(&b, binary.LittleEndian, uint16(caps>>16))            // capability flags (upper 2 bytes)
	b.WriteByte(21)                                                    // auth plugin data length (20 bytes + null)
	b.Write(make([]byte, 10))                                          // reserved
	b.Write(challenge[8:])                                             // auth-plugin-data-part-2 (12 bytes)
	b.WriteByte(0x00)                                                  // null terminator for part-2
	b.WriteString("mysql_native_password\x00")                        // auth plugin name
	return b.Bytes()
}

// parseHandshakeResponse extracts the database name from a HandshakeResponse41 payload.
// It ignores the username and auth data (the client's credentials are not verified).
func parseHandshakeResponse(payload []byte) (string, error) {
	if len(payload) < 32 {
		return "", fmt.Errorf("HandshakeResponse payload too short: %d bytes", len(payload))
	}
	caps := binary.LittleEndian.Uint32(payload[0:4])
	offset := 32 // skip: caps(4) + maxPkt(4) + charset(1) + reserved(23)

	// Skip username (null-terminated string)
	end := bytes.IndexByte(payload[offset:], 0x00)
	if end < 0 {
		return "", fmt.Errorf("no null terminator after username")
	}
	offset += end + 1

	// Skip auth response
	if caps&capSecureConn != 0 {
		if offset >= len(payload) {
			return "", fmt.Errorf("truncated at auth length")
		}
		authLen := int(payload[offset])
		offset += 1 + authLen
	} else {
		end = bytes.IndexByte(payload[offset:], 0x00)
		if end < 0 {
			return "", fmt.Errorf("no null terminator after auth response")
		}
		offset += end + 1
	}

	// Read database name (null-terminated, if CLIENT_CONNECT_WITH_DB)
	if caps&capConnectWithDB == 0 || offset >= len(payload) {
		return "", nil
	}
	end = bytes.IndexByte(payload[offset:], 0x00)
	if end < 0 {
		return string(payload[offset:]), nil
	}
	return string(payload[offset : offset+end]), nil
}

// serverHandshake holds the data extracted from MySQL's Initial Handshake packet.
type serverHandshake struct {
	challenge  []byte // 20 bytes
	pluginName string
}

// parseInitialHandshake parses a Protocol::HandshakeV10 payload from the MySQL server.
func parseInitialHandshake(payload []byte) (*serverHandshake, error) {
	if len(payload) < 1 || payload[0] != 10 {
		return nil, fmt.Errorf("expected protocol v10, got %d", payload[0])
	}
	// Skip server version (null-terminated)
	versionEnd := bytes.IndexByte(payload[1:], 0x00)
	if versionEnd < 0 {
		return nil, fmt.Errorf("no null terminator after server version")
	}
	offset := 1 + versionEnd + 1

	// Skip connection id (4 bytes)
	if offset+4 > len(payload) {
		return nil, fmt.Errorf("packet too short for connection id")
	}
	offset += 4

	// Auth plugin data part-1 (8 bytes)
	if offset+8 > len(payload) {
		return nil, fmt.Errorf("packet too short for auth-plugin-data-part-1")
	}
	challenge := make([]byte, 20)
	copy(challenge[:8], payload[offset:offset+8])
	offset += 8

	// Filler (1 byte)
	offset++

	// Capability flags lower (2 bytes)
	if offset+2 > len(payload) {
		return nil, fmt.Errorf("packet too short for capability flags lower")
	}
	capsLower := uint32(binary.LittleEndian.Uint16(payload[offset : offset+2]))
	offset += 2

	// Charset (1 byte), status flags (2 bytes)
	offset += 3

	// Capability flags upper (2 bytes)
	if offset+2 > len(payload) {
		return nil, fmt.Errorf("packet too short for capability flags upper")
	}
	capsUpper := uint32(binary.LittleEndian.Uint16(payload[offset:offset+2])) << 16
	caps := capsLower | capsUpper
	offset += 2

	// Auth plugin data length (1 byte)
	if offset >= len(payload) {
		return nil, fmt.Errorf("packet too short for auth plugin data length")
	}
	authDataLen := int(payload[offset])
	offset++

	// Reserved (10 bytes)
	offset += 10

	// Auth plugin data part-2: max(13, authDataLen-8) bytes
	part2Len := authDataLen - 8
	if part2Len < 13 {
		part2Len = 13
	}
	if offset+part2Len > len(payload) {
		return nil, fmt.Errorf("packet too short for auth-plugin-data-part-2")
	}
	copy(challenge[8:], payload[offset:offset+12]) // only first 12 bytes are the actual nonce
	offset += part2Len

	// Auth plugin name (null-terminated, if CLIENT_PLUGIN_AUTH)
	var pluginName string
	if caps&capPluginAuth != 0 && offset < len(payload) {
		end := bytes.IndexByte(payload[offset:], 0x00)
		if end >= 0 {
			pluginName = string(payload[offset : offset+end])
		}
	}
	return &serverHandshake{challenge: challenge, pluginName: pluginName}, nil
}

// buildHandshakeResponse builds the client HandshakeResponse41 payload for the
// proxy→MySQL leg (no CLIENT_SSL — the proxy connects to MySQL over plain TCP).
func buildHandshakeResponse(username string, authData []byte, dbName string) []byte {
	caps := capLongPassword | capLongFlag | capConnectWithDB |
		capProtocol41 | capSecureConn | capPluginAuth

	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, caps)
	binary.Write(&b, binary.LittleEndian, uint32(16777216)) // max packet size
	b.WriteByte(0x21)                                       // charset utf8
	b.Write(make([]byte, 23))                               // reserved
	b.WriteString(username)
	b.WriteByte(0x00)
	b.WriteByte(byte(len(authData)))
	b.Write(authData)
	b.WriteString(dbName)
	b.WriteByte(0x00)
	b.WriteString("mysql_native_password\x00")
	return b.Bytes()
}

// buildOKPacket builds a minimal OK_Packet payload.
func buildOKPacket() []byte {
	return []byte{
		0x00,       // OK header
		0x00,       // affected rows (length-encoded int = 0)
		0x00,       // last insert id (length-encoded int = 0)
		0x02, 0x00, // status flags: SERVER_STATUS_AUTOCOMMIT
		0x00, 0x00, // warnings
	}
}

// extractErrMessage extracts the human-readable message from an ERR_Packet payload.
func extractErrMessage(payload []byte) string {
	// ERR: 0xFF(1) + error_code(2) + '#'(1) + sql_state(5) + message
	if len(payload) < 9 {
		return fmt.Sprintf("(short error packet, %d bytes)", len(payload))
	}
	return string(payload[9:])
}
```

**Step 2: Create `mysql/myproto_test.go`**

```go
package mysql

import (
	"bytes"
	"testing"
)

func TestReadWritePacket_RoundTrip(t *testing.T) {
	want := []byte("hello, MySQL")
	var buf bytes.Buffer
	if err := writePacket(&buf, 3, want); err != nil {
		t.Fatalf("writePacket: %v", err)
	}
	seq, got, err := readPacket(&buf)
	if err != nil {
		t.Fatalf("readPacket: %v", err)
	}
	if seq != 3 {
		t.Fatalf("seq: want 3, got %d", seq)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("payload mismatch: want %q, got %q", want, got)
	}
}

func TestNativePasswordAuth_EmptyPassword(t *testing.T) {
	result := nativePasswordAuth("", []byte("12345678901234567890"))
	if result != nil {
		t.Fatalf("expected nil for empty password, got %v", result)
	}
}

func TestNativePasswordAuth_Length(t *testing.T) {
	challenge := []byte("12345678901234567890") // 20 bytes
	result := nativePasswordAuth("password", challenge)
	if len(result) != 20 {
		t.Fatalf("expected 20-byte token, got %d bytes", len(result))
	}
}

func TestNativePasswordAuth_Deterministic(t *testing.T) {
	challenge := []byte("abcdefghijklmnopqrst") // 20 bytes
	r1 := nativePasswordAuth("secret", challenge)
	r2 := nativePasswordAuth("secret", challenge)
	if !bytes.Equal(r1, r2) {
		t.Fatalf("nativePasswordAuth not deterministic")
	}
}

func TestBuildInitialHandshake_SSLCapability(t *testing.T) {
	challenge := make([]byte, 20)
	payload := buildInitialHandshake(1, challenge)
	if len(payload) == 0 {
		t.Fatal("empty initial handshake")
	}
	// Protocol version must be 10
	if payload[0] != 10 {
		t.Fatalf("expected protocol version 10, got %d", payload[0])
	}
	// Parse out capability flags (lower 2 bytes are at offset 1+12+4+8+1 = 26)
	// server version "8.0.0-proxy\x00" = 12 bytes, conn id = 4 bytes, part1 = 8 bytes, filler = 1 byte
	offset := 1 + 12 + 4 + 8 + 1 // = 26
	capsLow := uint32(payload[offset]) | uint32(payload[offset+1])<<8
	capsHigh := uint32(payload[offset+5]) | uint32(payload[offset+6])<<8 // after charset(1)+status(2) = +3, upper caps at +5
	caps := capsLow | capsHigh<<16
	if caps&capSSL == 0 {
		t.Fatal("CLIENT_SSL capability not set in initial handshake")
	}
}

func TestParseHandshakeResponse_ExtractsDBName(t *testing.T) {
	// Build a synthetic HandshakeResponse41 payload with CLIENT_SECURE_CONNECTION | CLIENT_CONNECT_WITH_DB | CLIENT_PLUGIN_AUTH
	caps := capProtocol41 | capSecureConn | capConnectWithDB | capPluginAuth

	var b bytes.Buffer
	writeU32LE := func(v uint32) {
		b.Write([]byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)})
	}
	writeU32LE(caps)
	writeU32LE(16777216)    // max packet size
	b.WriteByte(0x21)       // charset
	b.Write(make([]byte, 23)) // reserved

	b.WriteString("testuser\x00")    // username
	authResp := []byte{1, 2, 3, 4}  // fake auth response
	b.WriteByte(byte(len(authResp)))
	b.Write(authResp)
	b.WriteString("mydb\x00") // database name
	b.WriteString("mysql_native_password\x00")

	dbName, err := parseHandshakeResponse(b.Bytes())
	if err != nil {
		t.Fatalf("parseHandshakeResponse: %v", err)
	}
	if dbName != "mydb" {
		t.Fatalf("expected dbName %q, got %q", "mydb", dbName)
	}
}
```

**Step 3: Run tests to verify they pass**

```bash
go test ./mysql/... -v -run TestReadWritePacket_RoundTrip
go test ./mysql/... -v -run TestNativePasswordAuth
go test ./mysql/... -v -run TestBuildInitialHandshake
go test ./mysql/... -v -run TestParseHandshakeResponse
```

Expected: all PASS.

**Step 4: Commit**

```bash
git add mysql/myproto.go mysql/myproto_test.go
git commit -m "add MySQL packet helpers and native password auth"
```

---

### Task 2: HandleClient — TLS upgrade and HandshakeResponse parsing

**Files:**
- Create: `mysql/handler.go`

**Background:** `HandleClient` must act as a MySQL server to the incoming client. Sequence:
1. Send fake Initial Handshake (seq=0) — includes CLIENT_SSL so the client sends SSLRequest next.
2. Read SSLRequest (seq=1, 32-byte payload with capability flags only).
3. Upgrade to TLS using `tlsConfig`, require client certificate.
4. Read HandshakeResponse41 (seq=2) over TLS — extract database name.
5. Return a `*clientConn_` wrapper storing the TLS connection, database name, and HandshakeResponse sequence ID (needed for AcceptClient to send OK with the correct seq).

**Step 1: Create `mysql/handler.go`**

```go
package mysql

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"

	"github.com/matmazurk/database-proxy/proxy"
	_ "github.com/go-sql-driver/mysql"
)

// Handler implements proxy.DBHandler for MySQL.
type Handler struct{}

func (h *Handler) HandleClient(clientConn net.Conn, tlsConfig *tls.Config) (io.ReadWriteCloser, string, error) {
	// Generate 20-byte random challenge for the fake Initial Handshake.
	challenge := make([]byte, 20)
	if _, err := rand.Read(challenge); err != nil {
		return nil, "", fmt.Errorf("generating challenge: %w", err)
	}

	// Send fake Initial Handshake (seq=0).
	if err := writePacket(clientConn, 0, buildInitialHandshake(1, challenge)); err != nil {
		return nil, "", fmt.Errorf("sending initial handshake: %w", err)
	}

	// Read SSLRequest (seq=1). It is exactly 32 bytes: caps(4)+maxpkt(4)+charset(1)+reserved(23).
	_, payload, err := readPacket(clientConn)
	if err != nil {
		return nil, "", fmt.Errorf("reading SSL request: %w", err)
	}
	if len(payload) < 4 {
		return nil, "", fmt.Errorf("SSL request too short: %d bytes", len(payload))
	}
	clientCaps := binary.LittleEndian.Uint32(payload[0:4])
	if clientCaps&capSSL == 0 {
		return nil, "", fmt.Errorf("client did not request SSL (caps=0x%08x)", clientCaps)
	}

	// TLS upgrade — require client certificate.
	serverTLS := tlsConfig.Clone()
	serverTLS.ClientAuth = tls.RequireAndVerifyClientCert
	tlsConn := tls.Server(clientConn, serverTLS)
	if err := tlsConn.Handshake(); err != nil {
		return nil, "", fmt.Errorf("TLS handshake: %w", err)
	}
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) > 0 {
		log.Printf("mysql client connected: CN=%s", state.PeerCertificates[0].Subject.CommonName)
	}

	// Read HandshakeResponse41 (seq=2) over TLS.
	seq, payload, err := readPacket(tlsConn)
	if err != nil {
		return nil, "", fmt.Errorf("reading HandshakeResponse: %w", err)
	}
	dbName, err := parseHandshakeResponse(payload)
	if err != nil {
		return nil, "", fmt.Errorf("parsing HandshakeResponse: %w", err)
	}
	log.Printf("mysql client requests database: %q", dbName)

	return &clientConn_{Conn: tlsConn, dbName: dbName, handshakeSeq: seq}, dbName, nil
}

// clientConn_ wraps the client TLS connection and stores handshake metadata
// so AcceptClient can send OK with the correct sequence number.
type clientConn_ struct {
	net.Conn
	dbName       string
	handshakeSeq byte // sequence ID of the HandshakeResponse41 received from client
}
```

**Step 2: Verify it compiles (no ConnectAndAuth/AcceptClient yet — add stubs)**

Add these stubs at the bottom of `mysql/handler.go` temporarily so `go build` passes:

```go
func (h *Handler) ConnectAndAuth(dbAddr string, creds *proxy.DBCredentials, dbName string) (net.Conn, error) {
	return nil, fmt.Errorf("not implemented")
}

func (h *Handler) AcceptClient(clientIO io.ReadWriteCloser, dbConn net.Conn) (net.Conn, error) {
	return nil, fmt.Errorf("not implemented")
}
```

**Step 3: Add go-sql-driver dependency**

```bash
go get github.com/go-sql-driver/mysql
```

Expected: `go.mod` and `go.sum` updated.

**Step 4: Verify the package compiles**

```bash
go build ./mysql/...
```

Expected: no errors.

**Step 5: Commit**

```bash
git add mysql/handler.go go.mod go.sum
git commit -m "add MySQL HandleClient with TLS upgrade and HandshakeResponse parsing"
```

---

### Task 3: ConnectAndAuth — credential validation and raw MySQL handshake

**Files:**
- Modify: `mysql/handler.go` (replace `ConnectAndAuth` stub)

**Background:** Two steps:
1. `go-sql-driver/mysql` `db.Ping()` validates Vault credentials.
2. Raw `net.Dial` to MySQL + manual MySQL handshake: read Initial Handshake → send HandshakeResponse → read OK or AuthSwitchRequest → send auth switch response if needed → read OK.

Vault users are created with `IDENTIFIED WITH mysql_native_password`, so MySQL may send an AuthSwitchRequest (0xFE) to switch from `caching_sha2_password` (MySQL 8.0 default) to `mysql_native_password`. The proxy handles this by computing `nativePasswordAuth` with the new challenge from the AuthSwitchRequest.

**Step 1: Replace the `ConnectAndAuth` stub in `mysql/handler.go`**

```go
func (h *Handler) ConnectAndAuth(dbAddr string, creds *proxy.DBCredentials, dbName string) (net.Conn, error) {
	// --- Step 1: Validate credentials via go-sql-driver ---
	dsn := fmt.Sprintf("%s:%s@tcp(%s)/%s", creds.Username, creds.Password, dbAddr, dbName)
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening mysql connection: %w", err)
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("mysql ping failed: %w", err)
	}
	log.Printf("mysql credentials verified: user=%s db=%s", creds.Username, dbName)

	// --- Step 2: Open raw TCP connection for relay ---
	conn, err := net.Dial("tcp", dbAddr)
	if err != nil {
		return nil, fmt.Errorf("raw connect to mysql: %w", err)
	}

	// Read MySQL's Initial Handshake (seq=0).
	_, payload, err := readPacket(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("reading server initial handshake: %w", err)
	}
	hs, err := parseInitialHandshake(payload)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("parsing server initial handshake: %w", err)
	}

	// Send HandshakeResponse (seq=1).
	authData := nativePasswordAuth(creds.Password, hs.challenge)
	resp := buildHandshakeResponse(creds.Username, authData, dbName)
	if err := writePacket(conn, 1, resp); err != nil {
		conn.Close()
		return nil, fmt.Errorf("sending HandshakeResponse to mysql: %w", err)
	}

	// Read server response: OK (0x00), AuthSwitchRequest (0xFE), or ERR (0xFF).
	_, payload, err = readPacket(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("reading mysql auth response: %w", err)
	}
	if len(payload) == 0 {
		conn.Close()
		return nil, fmt.Errorf("empty mysql auth response")
	}

	switch payload[0] {
	case 0x00: // OK — authentication succeeded
		return conn, nil

	case 0xFF: // ERR
		conn.Close()
		return nil, fmt.Errorf("mysql auth error: %s", extractErrMessage(payload))

	case 0xFE: // AuthSwitchRequest — MySQL wants us to use a different plugin
		pluginName, challenge, err := parseAuthSwitchRequest(payload)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("parsing AuthSwitchRequest: %w", err)
		}
		if pluginName != "mysql_native_password" {
			conn.Close()
			return nil, fmt.Errorf("unexpected auth plugin switch to %q", pluginName)
		}
		switchResp := nativePasswordAuth(creds.Password, challenge)
		if err := writePacket(conn, 3, switchResp); err != nil {
			conn.Close()
			return nil, fmt.Errorf("sending auth switch response: %w", err)
		}
		_, payload, err = readPacket(conn)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("reading OK after auth switch: %w", err)
		}
		if len(payload) == 0 || payload[0] != 0x00 {
			conn.Close()
			return nil, fmt.Errorf("expected OK after auth switch, got 0x%02x", payload[0])
		}
		return conn, nil

	default:
		conn.Close()
		return nil, fmt.Errorf("unexpected mysql auth response: 0x%02x", payload[0])
	}
}
```

**Step 2: Add `parseAuthSwitchRequest` to `mysql/myproto.go`**

```go
// parseAuthSwitchRequest parses an AuthSwitchRequest payload (first byte 0xFE).
// Returns the plugin name and challenge bytes.
func parseAuthSwitchRequest(payload []byte) (pluginName string, challenge []byte, error error) {
	if len(payload) == 0 || payload[0] != 0xFE {
		return "", nil, fmt.Errorf("expected AuthSwitchRequest (0xFE), got 0x%02x", payload[0])
	}
	end := bytes.IndexByte(payload[1:], 0x00)
	if end < 0 {
		return "", nil, fmt.Errorf("no null terminator in AuthSwitchRequest plugin name")
	}
	pluginName = string(payload[1 : 1+end])
	challenge = payload[1+end+1:]
	// Strip trailing null if present
	if len(challenge) > 0 && challenge[len(challenge)-1] == 0x00 {
		challenge = challenge[:len(challenge)-1]
	}
	return pluginName, challenge, nil
}
```

**Step 3: Add missing imports to `mysql/handler.go`** — add `"database/sql"` to the import block.

**Step 4: Verify it compiles**

```bash
go build ./mysql/...
```

Expected: no errors.

**Step 5: Commit**

```bash
git add mysql/handler.go mysql/myproto.go
git commit -m "add MySQL ConnectAndAuth with native password handshake"
```

---

### Task 4: AcceptClient — send OK to client and return relay connection

**Files:**
- Modify: `mysql/handler.go` (replace `AcceptClient` stub)

**Background:** After `ConnectAndAuth` succeeds, send an OK packet to the client to signal that authentication is complete. The sequence ID must be `handshakeSeq + 1` (one more than the `HandshakeResponse41` the client sent). Return `dbConn` for the relay.

**Step 1: Replace the `AcceptClient` stub in `mysql/handler.go`**

```go
func (h *Handler) AcceptClient(clientIO io.ReadWriteCloser, dbConn net.Conn) (net.Conn, error) {
	occ, ok := clientIO.(*clientConn_)
	if !ok {
		return nil, fmt.Errorf("AcceptClient: expected *clientConn_, got %T", clientIO)
	}
	if err := writePacket(occ.Conn, occ.handshakeSeq+1, buildOKPacket()); err != nil {
		return nil, fmt.Errorf("sending OK to mysql client: %w", err)
	}
	return dbConn, nil
}
```

**Step 2: Verify it compiles**

```bash
go build ./...
```

Expected: no errors.

**Step 3: Commit**

```bash
git add mysql/handler.go
git commit -m "add MySQL AcceptClient"
```

---

### Task 5: Wire MySQL handler into main.go

**Files:**
- Modify: `main.go`

**Background:** Add `case "mysql"` to the `dbType` switch. No TLS config needed for the proxy→MySQL leg (plain TCP).

**Step 1: Add the import and case to `main.go`**

Add `"github.com/matmazurk/database-proxy/mysql"` to the import block.

Add the case to the switch at `main.go:19`:

```go
case "mysql":
    handler = &mysql.Handler{}
```

The full switch becomes:

```go
switch dbType {
case "postgres":
    handler = &postgres.Handler{}
case "mysql":
    handler = &mysql.Handler{}
case "oracle":
    oracleTLSConfig, err := buildOracleTLSConfig(os.Getenv("TLS_CA"))
    if err != nil {
        log.Fatalf("building oracle TLS config: %v", err)
    }
    handler = &oracle.Handler{OracleTLS: oracleTLSConfig}
default:
    log.Fatalf("unsupported DB_TYPE: %s", dbType)
}
```

**Step 2: Verify it compiles and tests pass**

```bash
go build ./...
go test ./...
```

Expected: compiles cleanly, all existing tests pass.

**Step 3: Commit**

```bash
git add main.go
git commit -m "wire MySQL handler into main.go"
```

---

### Task 6: Add MySQL to docker-compose.yml, vault/setup.sh, and Makefile

**Files:**
- Modify: `docker-compose.yml`
- Modify: `vault/setup.sh`
- Modify: `Makefile`

**Step 1: Add MySQL service to `docker-compose.yml`**

Add this block after the `oracle` service (before `vault`):

```yaml
  mysql:
    image: mysql:8.0
    environment:
      MYSQL_ROOT_PASSWORD: mysql
      MYSQL_DATABASE: testdb
    ports:
      - "3306:3306"
    healthcheck:
      test: ["CMD", "mysqladmin", "ping", "-h", "127.0.0.1", "-u", "root", "-pmysql"]
      interval: 2s
      timeout: 5s
      retries: 20
```

**Step 2: Add mysql to `vault-setup` `depends_on` in `docker-compose.yml`**

Add to the `vault-setup.depends_on` block:

```yaml
      mysql:
        condition: service_healthy
```

**Step 3: Add MySQL Vault config to `vault/setup.sh`**

Append before `echo "Vault setup complete"`:

```sh
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
```

**Step 4: Add `up-mysql` target to `Makefile`**

Add after `up-oracle`:

```makefile
up-mysql: certs
	DB_TYPE=mysql DB_ADDR=mysql:3306 VAULT_DB_ROLE=mysql-readonly docker compose up --build
```

Also update the `.PHONY` line to include `up-mysql`:

```makefile
.PHONY: build run certs up up-oracle up-mysql test-oracle down
```

**Step 5: Bring up the MySQL stack and verify**

```bash
make down
make up-mysql
```

Wait for all services to start, then in a separate terminal connect with any MySQL client using the proxy cert:

```bash
mysql -h 127.0.0.1 -P 5555 -u anyuser -panypass \
  --ssl-ca=certs/out/ca.crt \
  --ssl-cert=certs/out/client.crt \
  --ssl-key=certs/out/client.key \
  testdb -e "SELECT 1"
```

Expected: `mysql` connects and returns `1`.

Check proxy logs for:
```
mysql client connected: CN=test-client
mysql client requests database: "testdb"
mysql credentials verified: user=<vault-user> db=testdb
starting relay
```

**Step 6: Commit**

```bash
git add docker-compose.yml vault/setup.sh Makefile
git commit -m "add MySQL service to docker-compose, vault setup, and Makefile"
```
