package oracle

import (
	"crypto/tls"
	"database/sql"
	"fmt"
	"io"
	"log"
	"net"

	"github.com/matmazurk/database-proxy/proxy"
	go_ora "github.com/sijms/go-ora/v2"
)

// Handler implements proxy.DBHandler for Oracle Database using TNS protocol.
type Handler struct{}

func (h *Handler) HandleClient(clientConn net.Conn, _ *tls.Config) (io.ReadWriteCloser, string, error) {
	// Oracle clients connect with plain TNS (no TLS/SSLRequest)
	pkt, err := readTNSPacket(clientConn)
	if err != nil {
		return nil, "", fmt.Errorf("reading TNS packet: %w", err)
	}

	if pkt.packetType != tnsConnect {
		return nil, "", fmt.Errorf("expected TNS CONNECT (type %d), got type %d", tnsConnect, pkt.packetType)
	}

	serviceName := parseServiceName(pkt.payload)
	if serviceName == "" {
		return nil, "", fmt.Errorf("could not extract SERVICE_NAME from CONNECT packet")
	}

	log.Printf("oracle client requests service: %s", serviceName)

	// Store the connect payload on the connection for later use in AcceptClient
	return &clientConn_{
		Conn:           clientConn,
		connectPayload: pkt.payload,
	}, serviceName, nil
}

func (h *Handler) ConnectAndAuth(dbAddr string, creds *proxy.DBCredentials, serviceName string) (net.Conn, error) {
	// Build go-ora connection URL
	host, port, err := net.SplitHostPort(dbAddr)
	if err != nil {
		return nil, fmt.Errorf("parsing db address: %w", err)
	}
	portNum := 1521
	fmt.Sscanf(port, "%d", &portNum)

	connURL := go_ora.BuildUrl(host, portNum, serviceName, creds.Username, creds.Password, nil)

	db, err := sql.Open("oracle", connURL)
	if err != nil {
		return nil, fmt.Errorf("opening oracle connection: %w", err)
	}
	defer db.Close()

	// Verify credentials work
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("oracle ping failed: %w", err)
	}

	log.Printf("oracle credentials verified for user=%s service=%s", creds.Username, serviceName)

	// Now open a raw TCP connection to Oracle for the relay.
	// We'll forward the client's CONNECT directly and relay all subsequent traffic.
	oracleConn, err := net.Dial("tcp", dbAddr)
	if err != nil {
		return nil, fmt.Errorf("raw connect to oracle: %w", err)
	}

	return oracleConn, nil
}

func (h *Handler) AcceptClient(clientIO io.ReadWriteCloser) error {
	occ, ok := clientIO.(*clientConn_)
	if !ok {
		return fmt.Errorf("unexpected client connection type")
	}

	// Send TNS ACCEPT to the client
	acceptPayload := buildAcceptPayload(occ.connectPayload)
	pkt := &tnsPacket{
		packetType: tnsAccept,
		payload:    acceptPayload,
	}

	if err := writeTNSPacket(occ.Conn, pkt); err != nil {
		return fmt.Errorf("sending TNS ACCEPT: %w", err)
	}

	return nil
}

// clientConn_ wraps a net.Conn and stores the original CONNECT payload
// so AcceptClient can build a matching ACCEPT response.
type clientConn_ struct {
	net.Conn
	connectPayload []byte
}
