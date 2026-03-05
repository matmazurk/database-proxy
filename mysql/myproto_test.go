package mysql

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestReadWritePacket_RoundTrip(t *testing.T) {
	want := []byte("hello, MySQL")
	var buf bytes.Buffer
	if err := writePacket(&buf, 3, want); err != nil {
		t.Fatalf("writePacket: %v", err)
	}
	seq, got, err := readPacket(&buf)
	if err != nil {
		t.Fatalf("readPacket: %v", err)
	}
	if seq != 3 {
		t.Fatalf("seq: want 3, got %d", seq)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("payload mismatch: want %q, got %q", want, got)
	}
}

func TestNativePasswordAuth_EmptyPassword(t *testing.T) {
	result := nativePasswordAuth("", []byte("12345678901234567890"))
	if result != nil {
		t.Fatalf("expected nil for empty password, got %v", result)
	}
}

func TestNativePasswordAuth_Length(t *testing.T) {
	challenge := []byte("12345678901234567890") // 20 bytes
	result := nativePasswordAuth("password", challenge)
	if len(result) != 20 {
		t.Fatalf("expected 20-byte token, got %d bytes", len(result))
	}
}

func TestNativePasswordAuth_Deterministic(t *testing.T) {
	challenge := []byte("abcdefghijklmnopqrst") // 20 bytes
	r1 := nativePasswordAuth("secret", challenge)
	r2 := nativePasswordAuth("secret", challenge)
	if !bytes.Equal(r1, r2) {
		t.Fatalf("nativePasswordAuth not deterministic")
	}
}

func TestBuildInitialHandshake_SSLCapability(t *testing.T) {
	challenge := make([]byte, 20)
	payload := buildInitialHandshake(1, challenge)
	if len(payload) == 0 {
		t.Fatal("empty initial handshake")
	}
	// Protocol version must be 10
	if payload[0] != 10 {
		t.Fatalf("expected protocol version 10, got %d", payload[0])
	}
	// server version "8.0.0-proxy\x00" = 12 bytes, conn id = 4 bytes, part1 = 8 bytes, filler = 1 byte
	offset := 1 + 12 + 4 + 8 + 1 // = 26
	capsLow := uint32(payload[offset]) | uint32(payload[offset+1])<<8
	capsHigh := uint32(payload[offset+5]) | uint32(payload[offset+6])<<8
	caps := capsLow | capsHigh<<16
	if caps&capSSL == 0 {
		t.Fatal("CLIENT_SSL capability not set in initial handshake")
	}
}

func TestBuildParseInitialHandshake_RoundTrip(t *testing.T) {
	challenge := make([]byte, 20)
	for i := range challenge {
		challenge[i] = byte(i + 1)
	}
	payload := buildInitialHandshake(42, challenge)
	hs, err := parseInitialHandshake(payload)
	if err != nil {
		t.Fatalf("parseInitialHandshake: %v", err)
	}
	if !bytes.Equal(hs.challenge, challenge) {
		t.Fatalf("challenge mismatch: want %x, got %x", challenge, hs.challenge)
	}
	if hs.pluginName != "mysql_native_password" {
		t.Fatalf("pluginName: want mysql_native_password, got %q", hs.pluginName)
	}
}

func TestNativePasswordAuth_KnownAnswer(t *testing.T) {
	challenge := []byte("12345678901234567890")
	want, _ := hex.DecodeString("1957dce2724282e018f40d905824cb6361f88d41")
	got := nativePasswordAuth("password", challenge)
	if !bytes.Equal(got, want) {
		t.Fatalf("want %x, got %x", want, got)
	}
}

func TestParseAuthSwitchRequest(t *testing.T) {
	// Build a synthetic AuthSwitchRequest payload:
	// 0xFE + "mysql_native_password\x00" + challenge + 0x00 (trailing null)
	challenge := []byte("12345678901234567890")
	var payload []byte
	payload = append(payload, 0xFE)
	payload = append(payload, []byte("mysql_native_password\x00")...)
	payload = append(payload, challenge...)
	payload = append(payload, 0x00) // trailing null that should be stripped

	pluginName, gotChallenge, err := parseAuthSwitchRequest(payload)
	if err != nil {
		t.Fatalf("parseAuthSwitchRequest: %v", err)
	}
	if pluginName != "mysql_native_password" {
		t.Fatalf("pluginName: want mysql_native_password, got %q", pluginName)
	}
	if !bytes.Equal(gotChallenge, challenge) {
		t.Fatalf("challenge mismatch: want %x, got %x", challenge, gotChallenge)
	}
}

func TestParseHandshakeResponse_ExtractsDBName(t *testing.T) {
	caps := capProtocol41 | capSecureConn | capConnectWithDB | capPluginAuth

	var b bytes.Buffer
	writeU32LE := func(v uint32) {
		b.Write([]byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)})
	}
	writeU32LE(caps)
	writeU32LE(16777216)      // max packet size
	b.WriteByte(0x21)         // charset
	b.Write(make([]byte, 23)) // reserved

	b.WriteString("testuser\x00")  // username
	authResp := []byte{1, 2, 3, 4} // fake auth response
	b.WriteByte(byte(len(authResp)))
	b.Write(authResp)
	b.WriteString("mydb\x00")                 // database name
	b.WriteString("mysql_native_password\x00")

	dbName, err := parseHandshakeResponse(b.Bytes())
	if err != nil {
		t.Fatalf("parseHandshakeResponse: %v", err)
	}
	if dbName != "mydb" {
		t.Fatalf("expected dbName %q, got %q", "mydb", dbName)
	}
}
