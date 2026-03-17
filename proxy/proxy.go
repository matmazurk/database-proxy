package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
)

type Config struct {
	ListenAddr    string
	TLSCert       string
	TLSKey        string
	TLSCA         string
	DBAddr        string
	VaultAddr     string
	VaultCACert   string
	VaultDBRole   string
	ClientCertDir string // directory containing <cn>.crt and <cn>.key files
}

type Proxy struct {
	cfg       Config
	tlsConfig *tls.Config
	handler   DBHandler
}

func New(cfg Config, handler DBHandler) (*Proxy, error) {
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
		cfg:       cfg,
		tlsConfig: tlsConfig,
		handler:   handler,
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

	// 1. Handle client-side protocol (TLS, auth negotiation)
	clientIO, dbName, err := p.handler.HandleClient(clientRaw, p.tlsConfig)
	if err != nil {
		log.Printf("handling client: %v", err)
		return
	}
	defer clientIO.Close()

	// 2. Build a per-connection Vault client using the connecting client's cert
	// when ClientCertDir is configured, otherwise fall back to the proxy's own cert.
	certPath, keyPath := p.clientCertAndKey(clientIO)
	vaultCACert := p.cfg.VaultCACert
	if vaultCACert == "" {
		vaultCACert = p.cfg.TLSCA
	}
	vc, err := newVaultClient(p.cfg.VaultAddr, vaultCACert, certPath, keyPath)
	if err != nil {
		log.Printf("creating Vault client: %v", err)
		return
	}

	// 3. Get DB credentials from Vault
	creds, err := vc.getDBCredentials(p.cfg.VaultDBRole)
	if err != nil {
		log.Printf("Vault get creds failed: %v", err)
		return
	}
	log.Printf("got Vault credentials: user=%s", creds.Username)

	// 4. Connect to database and authenticate
	dbConn, err := p.handler.ConnectAndAuth(p.cfg.DBAddr, creds, dbName)
	if err != nil {
		log.Printf("connecting to database: %v", err)
		return
	}
	defer dbConn.Close()

	// 5. Tell client auth succeeded.
	// relayConn may differ from dbConn if the handler performed a protocol-level
	// renegotiation (e.g. Oracle TCPS RESEND with SSL re-handshake).
	relayConn, err := p.handler.AcceptClient(clientIO, dbConn)
	if err != nil {
		log.Printf("accepting client: %v", err)
		return
	}

	// 6. Bidirectional relay
	log.Printf("starting relay")
	errc := make(chan error, 2)
	go func() { _, err := io.Copy(relayConn, clientIO); errc <- err }()
	go func() { _, err := io.Copy(clientIO, relayConn); errc <- err }()
	<-errc
	log.Printf("connection closed")
}

// connStater is satisfied by *tls.Conn and any wrapper that promotes ConnectionState.
type connStater interface {
	ConnectionState() tls.ConnectionState
}

// clientCertAndKey returns the cert/key paths to use for Vault authentication.
// If ClientCertDir is set and the client presented a certificate, it uses
// <ClientCertDir>/<cn>.crt and <ClientCertDir>/<cn>.key.
// Otherwise it falls back to the proxy's own cert/key.
func (p *Proxy) clientCertAndKey(clientIO io.ReadWriteCloser) (certPath, keyPath string) {
	if p.cfg.ClientCertDir != "" {
		if cn, err := p.clientCN(clientIO); err == nil {
			return filepath.Join(p.cfg.ClientCertDir, cn+".crt"),
				filepath.Join(p.cfg.ClientCertDir, cn+".key")
		}
	}
	return p.cfg.TLSCert, p.cfg.TLSKey
}

// clientCN extracts the Common Name from the peer certificate on clientIO.
func (p *Proxy) clientCN(clientIO io.ReadWriteCloser) (string, error) {
	cs, ok := clientIO.(connStater)
	if !ok {
		return "", fmt.Errorf("connection type %T does not expose TLS state", clientIO)
	}
	state := cs.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return "", fmt.Errorf("no peer certificate on connection")
	}
	return state.PeerCertificates[0].Subject.CommonName, nil
}
