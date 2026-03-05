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
// OracleTLS configures TLS for the proxy→Oracle leg. When nil, plain TCP is used.
type Handler struct {
	OracleTLS *tls.Config
}

func (h *Handler) HandleClient(clientConn net.Conn, tlsConfig *tls.Config) (io.ReadWriteCloser, string, error) {
	// Oracle always uses TCPS: TLS handshake happens immediately after TCP connect, before any TNS.
	// This proxy does not support plain-TCP Oracle connections.
	if tlsConfig == nil {
		return nil, "", fmt.Errorf("HandleClient: tlsConfig is required for Oracle TCPS")
	}
	// Oracle clients don't present a client certificate; clone the config and clear
	// ClientAuth so the handshake doesn't require one.
	serverTLS := tlsConfig.Clone()
	serverTLS.ClientAuth = tls.NoClientCert
	tlsConn := tls.Server(clientConn, serverTLS)
	if err := tlsConn.Handshake(); err != nil {
		tlsConn.Close()
		return nil, "", fmt.Errorf("TLS handshake with oracle client: %w", err)
	}

	pkt, err := readTNSPacket(tlsConn)
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
		Conn:           tlsConn,
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

	var urlOpts map[string]string
	// SSL VERIFY=FALSE is intentional for the ping: it is a short-lived credential
	// check only; the long-lived relay socket below uses full TLS verification via h.OracleTLS.
	if h.OracleTLS != nil {
		urlOpts = map[string]string{
			"SSL":        "TRUE",
			"SSL VERIFY": "FALSE",
		}
	}
	connURL := go_ora.BuildUrl(host, portNum, serviceName, creds.Username, creds.Password, urlOpts)

	db, err := sql.Open("oracle", connURL)
	if err != nil {
		return nil, fmt.Errorf("opening oracle connection: %w", err)
	}
	defer db.Close()

	// Verify credentials work. This opens a full application-level connection via go-ora
	// (which is then discarded by defer db.Close()) and a separate raw TCP socket below.
	// Two connections are made per client intentionally: one to validate Vault creds, one
	// for the relay. This is a deliberate PoC trade-off for simplicity.
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("oracle ping failed: %w", err)
	}

	log.Printf("oracle credentials verified for user=%s service=%s", creds.Username, serviceName)

	// Open a raw connection to Oracle for the relay. AcceptClient will complete the
	// TNS CONNECT/ACCEPT handshake on this socket before traffic is relayed.
	var oracleConn net.Conn
	if h.OracleTLS != nil {
		oracleConn, err = tls.Dial("tcp", dbAddr, h.OracleTLS)
	} else {
		oracleConn, err = net.Dial("tcp", dbAddr)
	}
	if err != nil {
		return nil, fmt.Errorf("raw connect to oracle: %w", err)
	}

	return oracleConn, nil
}

func (h *Handler) AcceptClient(clientIO io.ReadWriteCloser, dbConn net.Conn) error {
	occ, ok := clientIO.(*clientConn_)
	if !ok {
		return fmt.Errorf("AcceptClient: expected *clientConn_, got %T", clientIO)
	}

	// Forward the original CONNECT to Oracle so it can complete its side of the handshake.
	connectPkt := &tnsPacket{
		packetType: tnsConnect,
		payload:    occ.connectPayload,
	}
	if err := writeTNSPacket(dbConn, connectPkt); err != nil {
		return fmt.Errorf("forwarding CONNECT to oracle: %w", err)
	}

	// Read Oracle's response to our forwarded CONNECT.
	oraclePkt, err := readTNSPacket(dbConn)
	if err != nil {
		return fmt.Errorf("reading oracle response: %w", err)
	}
	if oraclePkt.packetType != tnsAccept {
		return fmt.Errorf("expected TNS ACCEPT from oracle (type %d), got type %d", tnsAccept, oraclePkt.packetType)
	}

	// Tell the client auth succeeded. The ACCEPT payload is built from the client's CONNECT
	// rather than mirrored from Oracle's ACCEPT. This means Oracle's negotiated SDU/TDU
	// values are not propagated to the client — a known PoC trade-off.
	acceptPayload := buildAcceptPayload(occ.connectPayload)
	pkt := &tnsPacket{
		packetType: tnsAccept,
		payload:    acceptPayload,
	}
	if err := writeTNSPacket(occ.Conn, pkt); err != nil {
		return fmt.Errorf("sending TNS ACCEPT to client: %w", err)
	}

	return nil
}

// clientConn_ wraps a net.Conn and stores the original CONNECT payload
// so AcceptClient can build a matching ACCEPT response.
type clientConn_ struct {
	net.Conn
	connectPayload []byte
}
