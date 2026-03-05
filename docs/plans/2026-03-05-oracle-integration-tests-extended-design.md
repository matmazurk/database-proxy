# Oracle Integration Tests — Extended Design

**Date:** 2026-03-05
**Goal:** Add three integration tests that cover protocol edge cases not addressed by the existing suite.

---

## Context

The existing tests cover:
- `TestOracleProxy_HappyPath` — single `SELECT 1 FROM DUAL`
- `TestOracleProxy_InvalidClient` — garbage TNS bytes, proxy closes cleanly
- `TestOracleProxy_ConnectionCleanup` — 3 sequential connections, proxy survives

All tests use `go-ora/v2` as the client driver via `database/sql`.

---

## New Tests

### 1. `TestOracleProxy_UnknownServiceName`

**What it verifies:** The proxy rejects a connection that requests a service name for which Vault has no configured role, and continues accepting subsequent connections.

**Mechanism:** Open a raw `net.Conn` to the proxy and send a hand-crafted TNS CONNECT packet whose connect descriptor contains `SERVICE_NAME=NOTASERVICE`. The proxy parses it, calls `ConnectAndAuth` with that service name, which will fail (Vault `oracle-readonly` role only covers `FREEPDB1`). The proxy closes the connection.

**Assertions:**
1. A `Read` on the connection returns EOF or a net error within 5 s.
2. A fresh TCP dial to the proxy immediately after succeeds.

**Why raw TCP:** `go-ora` uses the service name from `BuildUrl`; it is easier to craft the TNS packet directly than to abuse the driver. The packet can be a minimal TNS CONNECT (≤ 230 bytes) whose connect data is `(DESCRIPTION=(ADDRESS=(PROTOCOL=tcp)(HOST=localhost)(PORT=5555))(CONNECT_DATA=(SERVICE_NAME=NOTASERVICE)(CID=(PROGRAM=test)(HOST=test)(USER=test))))`.

---

### 2. `TestOracleProxy_ClientDisconnectMidRelay`

**What it verifies:** If a client drops the TCP connection after the handshake but before the query finishes, the proxy goroutine exits cleanly and does not leak — evidenced by the proxy remaining responsive.

**Mechanism:**
1. Call `oracleDB(t)` to get a `*sql.DB`.
2. Call `db.PingContext` to force a real TCP connection through the proxy and complete the TNS handshake.
3. Call `db.Close()` immediately — this tears down the underlying TCP socket abruptly.
4. Sleep 200 ms to allow the proxy's relay goroutines to detect the EOF and exit.
5. Open a new `oracleDB` and run `SELECT 1 FROM DUAL` successfully.

**Assertions:**
1. The new connection query returns `1` without error.
2. A TCP dial to the proxy succeeds (proxy is still listening).

---

### 3. `TestOracleProxy_MultipleQueriesOnOneConnection`

**What it verifies:** The relay correctly handles multiple request-response cycles over a single persistent TCP connection, not just the first one.

**Mechanism:** Open one `*sql.DB`, call `db.SetMaxOpenConns(1)` so the pool never opens a second connection, then run 5 queries in sequence and verify each result.

**Queries and expected values:**

| Query | Expected |
|---|---|
| `SELECT 1 FROM DUAL` | `1` |
| `SELECT 2 FROM DUAL` | `2` |
| `SELECT 42 FROM DUAL` | `42` |
| `SELECT LENGTH('hello') FROM DUAL` | `5` |
| `SELECT 100 + 23 FROM DUAL` | `123` |

**Assertions:** Each `row.Scan` succeeds and returns the expected integer.

---

## Implementation Notes

- All three tests are appended to `integration/oracle_test.go`.
- `TestOracleProxy_UnknownServiceName` needs a helper `buildTNSConnectPacket(connectData string) []byte` that constructs a minimal valid TNS CONNECT packet (fixed 62-byte header + connect data) for direct raw TCP use.
- No new dependencies are required.
- Tests skip automatically (via `TestMain`) when the proxy is not running.
