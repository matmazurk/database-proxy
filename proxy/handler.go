package proxy

import (
	"crypto/tls"
	"io"
	"net"
)

// DBHandler abstracts the database-specific protocol handling.
// Each supported database type (PostgreSQL, Oracle, etc.) implements this interface.
type DBHandler interface {
	// HandleClient processes the client-side connection (accept, extract identity/db name).
	// Returns the client I/O stream and the database/service name the client wants.
	HandleClient(clientConn net.Conn, tlsConfig *tls.Config) (clientIO io.ReadWriteCloser, dbName string, err error)
	// ConnectAndAuth connects to the real DB and authenticates with Vault creds.
	// Returns a raw connection suitable for io.Copy relay.
	ConnectAndAuth(dbAddr string, creds *DBCredentials, dbName string) (net.Conn, error)
	// AcceptClient tells the client that auth succeeded and it's ready for queries.
	AcceptClient(clientIO io.ReadWriteCloser) error
}
