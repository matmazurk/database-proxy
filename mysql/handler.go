package mysql

import (
	"crypto/rand"
	"crypto/tls"
	"database/sql"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"

	"github.com/matmazurk/database-proxy/proxy"
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
	// seq is intentionally ignored — the SSLRequest sequence (expected: 1) is not verified.
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
		tlsConn.Close()
		return nil, "", fmt.Errorf("TLS handshake: %w", err)
	}
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) > 0 {
		log.Printf("mysql client connected: CN=%s", state.PeerCertificates[0].Subject.CommonName)
	}

	// Read HandshakeResponse41 (seq=2) over TLS.
	seq, payload, err := readPacket(tlsConn)
	if err != nil {
		tlsConn.Close()
		return nil, "", fmt.Errorf("reading HandshakeResponse: %w", err)
	}
	dbName, err := parseHandshakeResponse(payload)
	if err != nil {
		tlsConn.Close()
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
	var authResponseSeq byte
	authResponseSeq, payload, err = readPacket(conn)
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
		if err := writePacket(conn, authResponseSeq+1, switchResp); err != nil {
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
