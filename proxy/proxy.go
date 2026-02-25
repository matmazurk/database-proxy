package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
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
		vaultClient: NewVaultClient(cfg.VaultAddr, caPool),
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
	// Note: for TLS cert auth to Vault, we need the client's private key too.
	// Since we only have the cert from the TLS handshake (not the private key),
	// the proxy will use its own TLS keypair to auth to Vault on behalf of the client.
	// The Vault cert auth role is configured to trust certs signed by the same CA.
	creds, err := p.vaultClient.GetDBCredentials(clientCert, p.tlsConfig.Certificates[0].PrivateKey, p.cfg.VaultDBRole)
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
