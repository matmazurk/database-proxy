package integration

import (
	"context"
	"database/sql"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	go_ora "github.com/sijms/go-ora/v2"
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
	host, port, err := net.SplitHostPort(proxyAddr)
	if err != nil {
		t.Fatalf("parse proxyAddr: %v", err)
	}
	portNum := 0
	fmt.Sscanf(port, "%d", &portNum)
	// Pass a short CID to keep the TNS connect descriptor ≤ 230 bytes.
	// go-ora omits the connect data from the CONNECT packet when it exceeds
	// 230 bytes (sending it out-of-band instead), which breaks the proxy's
	// SERVICE_NAME extraction. The default CID embeds the full program path.
	connStr := go_ora.BuildUrl(host, portNum, serviceName, oracleUser, oraclePass, map[string]string{
		"CID": "(CID=(PROGRAM=test)(HOST=test)(USER=test))",
	})
	db, err := sql.Open("oracle", connStr)
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

func TestOracleProxy_ClientDisconnectMidRelay(t *testing.T) {
	db := oracleDB(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Force a real connection through the proxy by pinging.
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("ping failed: %v", err)
	}

	// Abruptly close the connection — this tears down the TCP socket the
	// proxy's relay goroutines are copying on.
	db.Close()

	// Give the proxy's relay goroutines time to detect EOF and exit.
	time.Sleep(300 * time.Millisecond)

	// The proxy must still accept new connections and serve queries.
	db2 := oracleDB(t)
	ctx2, cancel2 := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel2()

	var result int
	if err := db2.QueryRowContext(ctx2, "SELECT 1 FROM DUAL").Scan(&result); err != nil {
		t.Fatalf("query on new connection after disconnect: %v", err)
	}
	if result != 1 {
		t.Fatalf("expected 1, got %d", result)
	}
}

func TestOracleProxy_UnknownServiceName(t *testing.T) {
	// Build a minimal TNS CONNECT packet whose connect descriptor asks for a
	// service name that does not exist in Oracle. The proxy parses it, tries
	// to ping Oracle with that service, fails, and closes the connection.
	connectData := "(DESCRIPTION=(ADDRESS=(PROTOCOL=tcp)(HOST=localhost)(PORT=5555))" +
		"(CONNECT_DATA=(SERVICE_NAME=NOTASERVICE)(CID=(PROGRAM=test)(HOST=test)(USER=test))))"

	const fixedPayloadSize = 62 // bytes before connect data (matches go-ora's dataOffset=70 minus 8-byte header)
	payload := make([]byte, fixedPayloadSize+len(connectData))
	binary.BigEndian.PutUint16(payload[0:2], 317)                        // version
	binary.BigEndian.PutUint16(payload[16:18], uint16(len(connectData))) // connect data length
	binary.BigEndian.PutUint16(payload[18:20], 70)                       // dataOffset (packet-relative, triggers regex fallback)
	copy(payload[fixedPayloadSize:], connectData)

	totalLen := 8 + len(payload)
	pkt := make([]byte, totalLen)
	binary.BigEndian.PutUint16(pkt[0:2], uint16(totalLen))
	pkt[4] = 1 // tnsConnect
	copy(pkt[8:], payload)

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	if _, err = conn.Write(pkt); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}

	// Proxy should close the connection after failing to reach NOTASERVICE.
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 64)
	_, err = conn.Read(buf)
	if err == nil {
		t.Fatal("expected connection to be closed by proxy, but read succeeded")
	}

	// Proxy must still be alive.
	probe, err := net.DialTimeout("tcp", proxyAddr, 3*time.Second)
	if err != nil {
		t.Fatalf("proxy not accepting after unknown service: %v", err)
	}
	probe.Close()
}

func TestOracleProxy_MultipleQueriesOnOneConnection(t *testing.T) {
	db := oracleDB(t)
	// Force the pool to a single connection so all queries reuse the same
	// TCP connection through the proxy.
	db.SetMaxOpenConns(1)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cases := []struct {
		query    string
		expected int
	}{
		{"SELECT 1 FROM DUAL", 1},
		{"SELECT 2 FROM DUAL", 2},
		{"SELECT 42 FROM DUAL", 42},
		{"SELECT LENGTH('hello') FROM DUAL", 5},
		{"SELECT 100 + 23 FROM DUAL", 123},
	}

	for _, tc := range cases {
		var result int
		if err := db.QueryRowContext(ctx, tc.query).Scan(&result); err != nil {
			t.Fatalf("query %q failed: %v", tc.query, err)
		}
		if result != tc.expected {
			t.Fatalf("query %q: expected %d, got %d", tc.query, tc.expected, result)
		}
	}
}
