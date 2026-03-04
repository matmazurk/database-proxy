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
	serviceName = "FREEPDB1"
	oracleUser  = "SYSTEM"
	oraclePass  = "oracle"
)

// proxyAddr is the address of the proxy under test.
// Override with PROXY_ADDR env var (e.g. "proxy:5555" when running inside docker-compose).
var proxyAddr = func() string {
	if v := os.Getenv("PROXY_ADDR"); v != "" {
		return v
	}
	return "localhost:5555"
}()

func TestMain(m *testing.M) {
	// WAIT_FOR_PROXY (seconds): when set, retry until the proxy is reachable or the
	// deadline expires. Exits 1 on timeout so the test container fails loudly in CI.
	// Without it (local dev), exit 0 immediately so `go test ./...` does not fail when
	// the stack is not running.
	waitSecs := 0
	fmt.Sscanf(os.Getenv("WAIT_FOR_PROXY"), "%d", &waitSecs)
	deadline := time.Now().Add(time.Duration(waitSecs) * time.Second)

	for {
		conn, err := net.DialTimeout("tcp", proxyAddr, time.Second)
		if err == nil {
			conn.Close()
			break
		}
		if time.Now().After(deadline) {
			if waitSecs > 0 {
				fmt.Printf("oracle proxy not reachable at %s after %ds\n", proxyAddr, waitSecs)
				os.Exit(1)
			}
			fmt.Printf("oracle proxy not reachable at %s — skipping integration tests\n", proxyAddr)
			fmt.Println("start the stack with: make up-oracle")
			os.Exit(0)
		}
		time.Sleep(time.Second)
	}
	os.Exit(m.Run())
}

func oracleDB(t *testing.T) *sql.DB {
	t.Helper()
	// godror DSN: user/pass@//host:port/service  (Easy Connect format)
	dsn := oracleUser + "/" + oraclePass + "@//" + proxyAddr + "/" + serviceName
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
