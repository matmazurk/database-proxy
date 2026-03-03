package proxy

import (
	"crypto/tls"
	"crypto/x509"
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
	DBAddr      string
	VaultAddr   string
	VaultCACert string
	VaultDBRole string
}

type Proxy struct {
	cfg         Config
	tlsConfig   *tls.Config
	vaultClient *vaultClient
	handler     DBHandler
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

	vaultCACert := cfg.VaultCACert
	if vaultCACert == "" {
		vaultCACert = cfg.TLSCA
	}

	vaultClient, err := newVaultClient(cfg.VaultAddr, vaultCACert, cfg.TLSCert, cfg.TLSKey)
	if err != nil {
		return nil, fmt.Errorf("creating Vault client: %w", err)
	}

	return &Proxy{
		cfg:         cfg,
		tlsConfig:   tlsConfig,
		vaultClient: vaultClient,
		handler:     handler,
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

	// 2. Get DB credentials from Vault
	creds, err := p.vaultClient.getDBCredentials(p.cfg.VaultDBRole)
	if err != nil {
		log.Printf("Vault get creds failed: %v", err)
		return
	}
	log.Printf("got Vault credentials: user=%s", creds.Username)

	// 3. Connect to database and authenticate
	dbConn, err := p.handler.ConnectAndAuth(p.cfg.DBAddr, creds, dbName)
	if err != nil {
		log.Printf("connecting to database: %v", err)
		return
	}
	defer dbConn.Close()

	// 4. Tell client auth succeeded
	if err := p.handler.AcceptClient(clientIO, dbConn); err != nil {
		log.Printf("accepting client: %v", err)
		return
	}

	// 5. Bidirectional relay
	log.Printf("starting relay")
	errc := make(chan error, 2)
	go func() { _, err := io.Copy(dbConn, clientIO); errc <- err }()
	go func() { _, err := io.Copy(clientIO, dbConn); errc <- err }()
	<-errc
	log.Printf("connection closed")
}
