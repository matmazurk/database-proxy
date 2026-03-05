# Oracle Integration Tests — Extended Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add three integration tests — unknown service name rejection, client disconnect mid-relay, and multiple queries on one connection — to `integration/oracle_test.go`.

**Architecture:** All three tests are appended to the existing file. No new files or dependencies are needed. `TestOracleProxy_UnknownServiceName` crafts a raw TNS CONNECT packet in-test (no separate helper file) to avoid the go-ora `BuildUrl` service name constraint. The other two tests use the existing `oracleDB` helper.

**Tech Stack:** Go `testing`, `database/sql`, `github.com/sijms/go-ora/v2`, `encoding/binary`, raw `net.Conn`.

---

### Task 1: Write and run `TestOracleProxy_UnknownServiceName`

**Files:**
- Modify: `integration/oracle_test.go`

**Background:** The proxy's `ConnectAndAuth` builds an Oracle URL with the service name from the client's CONNECT packet, then calls `db.Ping()`. If the service name does not exist in Oracle (`NOTASERVICE`), the ping fails and the proxy closes the connection. The test sends a hand-crafted TNS CONNECT packet over a raw TCP socket so we can freely specify any service name without going through go-ora's `BuildUrl`.

**TNS CONNECT packet structure needed by the proxy:**

The proxy's `readTNSPacket` reads an 8-byte header then a payload. `parseServiceName` needs:
- `payload` at least 20 bytes
- `SERVICE_NAME=NOTASERVICE` somewhere in the payload (regex fallback always runs because stored offset 70 > payload length in our minimal packet)

So the simplest packet: 8-byte TNS header + 62 zero bytes (fixed CONNECT fields) + the connect descriptor string. Set:
- `header[0:2]` = total packet length (uint16 big-endian)
- `header[4]` = 1 (tnsConnect)
- `payload[16:18]` = uint16 length of connect descriptor
- `payload[18:20]` = uint16 dataOffset = 70 (packet-relative; triggers regex fallback)

**Step 1: Append the test to `integration/oracle_test.go`**

Add this function at the end of the file:

```go
func TestOracleProxy_UnknownServiceName(t *testing.T) {
	// Build a minimal TNS CONNECT packet whose connect descriptor asks for a
	// service name that does not exist in Oracle. The proxy parses it, tries
	// to ping Oracle with that service, fails, and closes the connection.
	connectData := "(DESCRIPTION=(ADDRESS=(PROTOCOL=tcp)(HOST=localhost)(PORT=5555))" +
		"(CONNECT_DATA=(SERVICE_NAME=NOTASERVICE)(CID=(PROGRAM=test)(HOST=test)(USER=test))))"

	const fixedPayloadSize = 62 // bytes before connect data (matches go-ora's dataOffset=70 minus 8-byte header)
	payload := make([]byte, fixedPayloadSize+len(connectData))
	binary.BigEndian.PutUint16(payload[0:2], 317)                         // version
	binary.BigEndian.PutUint16(payload[16:18], uint16(len(connectData)))  // connect data length
	binary.BigEndian.PutUint16(payload[18:20], 70)                        // dataOffset (packet-relative, triggers regex fallback)
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
```

**Step 2: Add `"encoding/binary"` to the import block**

The test uses `binary.BigEndian`. Check the existing imports in `integration/oracle_test.go` — if `"encoding/binary"` is not present, add it.

Current imports:
```go
import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	go_ora "github.com/sijms/go-ora/v2"
)
```

Updated imports:
```go
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
```

**Step 3: Verify build**

```bash
go build ./integration/...
```

Expected: exits 0.

**Step 4: Run the test**

```bash
go test ./integration/ -run TestOracleProxy_UnknownServiceName -v -timeout 30s
```

Expected:
```
=== RUN   TestOracleProxy_UnknownServiceName
--- PASS: TestOracleProxy_UnknownServiceName (X.XXs)
PASS
```

If the proxy isn't running, tests skip with exit 0.

---

### Task 2: Write and run `TestOracleProxy_ClientDisconnectMidRelay`

**Files:**
- Modify: `integration/oracle_test.go`

**Background:** After `db.PingContext` completes, the proxy has finished the TNS CONNECT/ACCEPT handshake and started the bidirectional relay goroutines. Calling `db.Close()` tears down the underlying TCP connection. The proxy's two relay goroutines (`io.Copy` in each direction) both get EOF and exit. After a short sleep, the proxy should be responsive to new connections.

**Step 1: Append the test**

```go
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
```

**Step 2: Run the test**

```bash
go test ./integration/ -run TestOracleProxy_ClientDisconnectMidRelay -v -timeout 30s
```

Expected:
```
=== RUN   TestOracleProxy_ClientDisconnectMidRelay
--- PASS: TestOracleProxy_ClientDisconnectMidRelay (X.XXs)
PASS
```

---

### Task 3: Write and run `TestOracleProxy_MultipleQueriesOnOneConnection`

**Files:**
- Modify: `integration/oracle_test.go`

**Background:** `db.SetMaxOpenConns(1)` forces `database/sql` to reuse the same underlying TCP connection for all queries. This validates that the proxy's relay correctly handles multiple TNS request-response cycles (not just the first one).

**Step 1: Append the test**

```go
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
```

**Step 2: Run the test**

```bash
go test ./integration/ -run TestOracleProxy_MultipleQueriesOnOneConnection -v -timeout 30s
```

Expected:
```
=== RUN   TestOracleProxy_MultipleQueriesOnOneConnection
--- PASS: TestOracleProxy_MultipleQueriesOnOneConnection (X.XXs)
PASS
```

---

### Task 4: Run the full suite and commit

**Step 1: Run all integration tests**

```bash
go test ./integration/ -v -timeout 120s
```

Expected: all six tests PASS.

```
=== RUN   TestOracleProxy_HappyPath
--- PASS: TestOracleProxy_HappyPath (X.XXs)
=== RUN   TestOracleProxy_InvalidClient
--- PASS: TestOracleProxy_InvalidClient (5.00s)
=== RUN   TestOracleProxy_ConnectionCleanup
--- PASS: TestOracleProxy_ConnectionCleanup (X.XXs)
=== RUN   TestOracleProxy_UnknownServiceName
--- PASS: TestOracleProxy_UnknownServiceName (X.XXs)
=== RUN   TestOracleProxy_ClientDisconnectMidRelay
--- PASS: TestOracleProxy_ClientDisconnectMidRelay (X.XXs)
=== RUN   TestOracleProxy_MultipleQueriesOnOneConnection
--- PASS: TestOracleProxy_MultipleQueriesOnOneConnection (X.XXs)
PASS
ok  	github.com/matmazurk/database-proxy/integration	X.XXXs
```

**Step 2: Run the full repo test suite**

```bash
go test ./... -timeout 120s
```

Expected: exits 0 (integration tests skip gracefully if stack not running; all unit tests pass).

**Step 3: Commit**

```bash
git add integration/oracle_test.go docs/plans/2026-03-05-oracle-integration-tests-extended.md docs/plans/2026-03-05-oracle-integration-tests-extended-design.md
git commit -m "add extended Oracle integration tests: unknown service, client disconnect, multi-query"
```
