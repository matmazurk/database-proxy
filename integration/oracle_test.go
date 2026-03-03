package integration

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	_ "github.com/godror/godror"
)

const (
	proxyAddr   = "localhost:5555"
	serviceName = "FREEPDB1"
	oracleUser  = "SYSTEM"
	oraclePass  = "oracle"
)

func TestMain(m *testing.M) {
	conn, err := net.DialTimeout("tcp", proxyAddr, time.Second)
	if err != nil {
		fmt.Printf("oracle proxy not reachable at %s — skipping integration tests\n", proxyAddr)
		fmt.Printf("start the stack with: make up-oracle\n")
		os.Exit(0)
	}
	conn.Close()
	os.Exit(m.Run())
}

func oracleDB(t *testing.T) *sql.DB {
	t.Helper()
	// godror DSN: user/pass@//host:port/service  (Easy Connect format)
	dsn := oracleUser + "/" + oraclePass + "@//localhost:5555/" + serviceName
	db, err := sql.Open("godror", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestOracleProxy_HappyPath(t *testing.T) {
	db := oracleDB(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var result int
	row := db.QueryRowContext(ctx, "SELECT 1 FROM DUAL")
	if err := row.Scan(&result); err != nil {
		t.Fatalf("query failed: %v", err)
	}

	if result != 1 {
		t.Fatalf("expected 1, got %d", result)
	}
}

func TestOracleProxy_InvalidClient(t *testing.T) {
	// Send garbage bytes — not a valid TNS CONNECT packet.
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	// Write junk.
	if _, err = conn.Write([]byte("this is not a TNS packet")); err != nil {
		t.Fatalf("write: %v", err)
	}

	// The proxy should close the connection after failing to parse a TNS packet.
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 64)
	_, err = conn.Read(buf)
	if err == nil {
		t.Fatal("expected connection to be closed by proxy, but read succeeded")
	}
	// err is either io.EOF or a net error — both are acceptable.

	// Verify the proxy is still alive and accepting new connections.
	probe, err := net.DialTimeout("tcp", proxyAddr, 3*time.Second)
	if err != nil {
		t.Fatalf("proxy not accepting after bad client: %v", err)
	}
	probe.Close()
}

func TestOracleProxy_ConnectionCleanup(t *testing.T) {
	const numConns = 3

	for i := range numConns {
		func() {
			db := oracleDB(t) // t.Cleanup in oracleDB closes db when test ends

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			var result int
			row := db.QueryRowContext(ctx, "SELECT 1 FROM DUAL")
			if err := row.Scan(&result); err != nil {
				t.Fatalf("connection %d: query failed: %v", i+1, err)
			}
			if result != 1 {
				t.Fatalf("connection %d: expected 1, got %d", i+1, result)
			}
		}()
	}

	// After all connections are closed, verify the proxy still accepts new ones.
	probe, err := net.DialTimeout("tcp", proxyAddr, 3*time.Second)
	if err != nil {
		t.Fatalf("proxy not accepting after %d connections: %v", numConns, err)
	}
	probe.Close()
}
