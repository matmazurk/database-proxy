package postgres

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"

	"github.com/matmazurk/database-proxy/proxy"
)

// Handler implements proxy.DBHandler for PostgreSQL.
type Handler struct{}

func (h *Handler) HandleClient(clientConn net.Conn, tlsConfig *tls.Config) (io.ReadWriteCloser, string, error) {
	// 1. Read SSLRequest from client
	isSSL, _, err := readStartupOrSSL(clientConn)
	if err != nil {
		return nil, "", fmt.Errorf("reading initial message: %w", err)
	}
	if !isSSL {
		return nil, "", fmt.Errorf("client did not send SSLRequest")
	}

	// 2. Accept SSL and upgrade
	if err := writeSSLAccept(clientConn); err != nil {
		return nil, "", fmt.Errorf("writing SSL accept: %w", err)
	}

	clientTLS := tls.Server(clientConn, tlsConfig)
	if err := clientTLS.Handshake(); err != nil {
		return nil, "", fmt.Errorf("TLS handshake failed: %w", err)
	}

	// 3. Extract client certificate
	state := clientTLS.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		clientTLS.Close()
		return nil, "", fmt.Errorf("no client certificate provided")
	}
	clientCert := state.PeerCertificates[0]
	log.Printf("client connected: CN=%s", clientCert.Subject.CommonName)

	// 4. Read StartupMessage from client
	_, params, err := readStartupOrSSL(clientTLS)
	if err != nil {
		clientTLS.Close()
		return nil, "", fmt.Errorf("reading startup message: %w", err)
	}

	database := params["database"]
	log.Printf("client requests database: %s", database)

	return clientTLS, database, nil
}

func (h *Handler) ConnectAndAuth(dbAddr string, creds *proxy.DBCredentials, dbName string) (net.Conn, error) {
	pgConn, err := net.Dial("tcp", dbAddr)
	if err != nil {
		return nil, fmt.Errorf("connecting to PostgreSQL: %w", err)
	}

	// Send StartupMessage
	startupMsg := buildStartupMessage(creds.Username, dbName)
	if _, err := pgConn.Write(startupMsg); err != nil {
		pgConn.Close()
		return nil, fmt.Errorf("sending startup to PG: %w", err)
	}

	// Handle SCRAM auth
	msgType, payload, err := readMessage(pgConn)
	if err != nil {
		pgConn.Close()
		return nil, fmt.Errorf("reading auth request from PG: %w", err)
	}
	if msgType != 'R' {
		pgConn.Close()
		return nil, fmt.Errorf("unexpected message type from PG: %c", msgType)
	}
	authType := binary.BigEndian.Uint32(payload[:4])
	if authType != 10 { // AuthenticationSASL
		pgConn.Close()
		return nil, fmt.Errorf("expected SASL auth (10), got: %d", authType)
	}

	if err := performSCRAMAuth(pgConn, creds.Password, payload); err != nil {
		pgConn.Close()
		return nil, fmt.Errorf("SCRAM auth failed: %w", err)
	}

	// Read until ReadyForQuery
	for {
		msgType, _, err := readMessage(pgConn)
		if err != nil {
			pgConn.Close()
			return nil, fmt.Errorf("reading from PG: %w", err)
		}
		if msgType == 'Z' { // ReadyForQuery
			break
		}
	}

	return pgConn, nil
}

func (h *Handler) AcceptClient(clientIO io.ReadWriteCloser) error {
	if err := writeAuthenticationOk(clientIO); err != nil {
		return fmt.Errorf("writing AuthOk to client: %w", err)
	}
	if err := writeReadyForQuery(clientIO); err != nil {
		return fmt.Errorf("writing ReadyForQuery to client: %w", err)
	}
	return nil
}
