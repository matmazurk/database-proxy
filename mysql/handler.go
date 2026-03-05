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
	return nil, fmt.Errorf("not implemented")
}

func (h *Handler) AcceptClient(clientIO io.ReadWriteCloser, dbConn net.Conn) (net.Conn, error) {
	return nil, fmt.Errorf("not implemented")
}
