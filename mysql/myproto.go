package mysql

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"io"
)

// Capability flags used in handshake packets.
const (
	capLongPassword  = uint32(0x00000001)
	capLongFlag      = uint32(0x00000004)
	capConnectWithDB = uint32(0x00000008)
	capProtocol41    = uint32(0x00000200)
	capSSL           = uint32(0x00000800)
	capSecureConn    = uint32(0x00008000)
	capPluginAuth    = uint32(0x00080000)
)

// readPacket reads one MySQL packet and returns (sequenceID, payload, error).
func readPacket(r io.Reader) (byte, []byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		return 0, nil, fmt.Errorf("reading packet header: %w", err)
	}
	length := int(uint32(header[0]) | uint32(header[1])<<8 | uint32(header[2])<<16)
	seq := header[3]
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, fmt.Errorf("reading packet payload: %w", err)
	}
	return seq, payload, nil
}

// writePacket writes a MySQL packet with the given sequence number and payload.
func writePacket(w io.Writer, seq byte, payload []byte) error {
	header := make([]byte, 4)
	length := len(payload)
	header[0] = byte(length)
	header[1] = byte(length >> 8)
	header[2] = byte(length >> 16)
	header[3] = seq
	if _, err := w.Write(header); err != nil {
		return fmt.Errorf("writing packet header: %w", err)
	}
	if _, err := w.Write(payload); err != nil {
		return fmt.Errorf("writing packet payload: %w", err)
	}
	return nil
}

// nativePasswordAuth computes the mysql_native_password auth response:
//
//	token = SHA1(password) XOR SHA1(challenge + SHA1(SHA1(password)))
//
// Returns nil for an empty password.
func nativePasswordAuth(password string, challenge []byte) []byte {
	if password == "" {
		return nil
	}
	h1 := sha1.Sum([]byte(password))
	h2 := sha1.Sum(h1[:])
	h := sha1.New()
	h.Write(challenge)
	h.Write(h2[:])
	h3 := h.Sum(nil)
	token := make([]byte, sha1.Size)
	for i := range token {
		token[i] = h1[i] ^ h3[i]
	}
	return token
}

// buildInitialHandshake builds a Protocol::HandshakeV10 payload.
// challenge must be exactly 20 bytes.
// Advertises CLIENT_SSL so the client will send an SSLRequest before HandshakeResponse.
func buildInitialHandshake(connID uint32, challenge []byte) []byte {
	caps := capLongPassword | capLongFlag | capConnectWithDB |
		capProtocol41 | capSSL | capSecureConn | capPluginAuth

	var b bytes.Buffer
	b.WriteByte(10)                                                          // protocol version
	b.WriteString("8.0.0-proxy\x00")                                        // server version
	_ = binary.Write(&b, binary.LittleEndian, connID)                       // connection id
	b.Write(challenge[:8])                                                   // auth-plugin-data-part-1
	b.WriteByte(0x00)                                                        // filler
	_ = binary.Write(&b, binary.LittleEndian, uint16(caps))                 // capability flags (lower 2 bytes)
	b.WriteByte(0x21)                                                        // character set: utf8
	_ = binary.Write(&b, binary.LittleEndian, uint16(0x0002))               // status flags: SERVER_STATUS_AUTOCOMMIT
	_ = binary.Write(&b, binary.LittleEndian, uint16(caps>>16))             // capability flags (upper 2 bytes)
	b.WriteByte(21)                                        // auth plugin data length (20 bytes + null)
	b.Write(make([]byte, 10))                              // reserved
	b.Write(challenge[8:])                                 // auth-plugin-data-part-2 (12 bytes)
	b.WriteByte(0x00)                                      // null terminator for part-2
	b.WriteString("mysql_native_password\x00")             // auth plugin name
	return b.Bytes()
}

// parseHandshakeResponse extracts the database name from a HandshakeResponse41 payload.
// It ignores the username and auth data (the client's credentials are not verified).
func parseHandshakeResponse(payload []byte) (string, error) {
	if len(payload) < 32 {
		return "", fmt.Errorf("HandshakeResponse payload too short: %d bytes", len(payload))
	}
	caps := binary.LittleEndian.Uint32(payload[0:4])
	offset := 32 // skip: caps(4) + maxPkt(4) + charset(1) + reserved(23)

	// Skip username (null-terminated string)
	end := bytes.IndexByte(payload[offset:], 0x00)
	if end < 0 {
		return "", fmt.Errorf("no null terminator after username")
	}
	offset += end + 1

	// Skip auth response
	if caps&capSecureConn != 0 {
		if offset >= len(payload) {
			return "", fmt.Errorf("truncated at auth length")
		}
		authLen := int(payload[offset])
		offset += 1 + authLen
	} else {
		end = bytes.IndexByte(payload[offset:], 0x00)
		if end < 0 {
			return "", fmt.Errorf("no null terminator after auth response")
		}
		offset += end + 1
	}

	// Read database name (null-terminated, if CLIENT_CONNECT_WITH_DB)
	if caps&capConnectWithDB == 0 || offset >= len(payload) {
		return "", nil
	}
	end = bytes.IndexByte(payload[offset:], 0x00)
	if end < 0 {
		return string(payload[offset:]), nil
	}
	return string(payload[offset : offset+end]), nil
}

// serverHandshake holds the data extracted from MySQL's Initial Handshake packet.
type serverHandshake struct {
	challenge  []byte // 20 bytes
	pluginName string
}

// parseInitialHandshake parses a Protocol::HandshakeV10 payload from the MySQL server.
func parseInitialHandshake(payload []byte) (*serverHandshake, error) {
	if len(payload) < 1 || payload[0] != 10 {
		return nil, fmt.Errorf("expected protocol v10, got %d", payload[0])
	}
	// Skip server version (null-terminated)
	versionEnd := bytes.IndexByte(payload[1:], 0x00)
	if versionEnd < 0 {
		return nil, fmt.Errorf("no null terminator after server version")
	}
	offset := 1 + versionEnd + 1

	// Skip connection id (4 bytes)
	if offset+4 > len(payload) {
		return nil, fmt.Errorf("packet too short for connection id")
	}
	offset += 4

	// Auth plugin data part-1 (8 bytes)
	if offset+8 > len(payload) {
		return nil, fmt.Errorf("packet too short for auth-plugin-data-part-1")
	}
	challenge := make([]byte, 20)
	copy(challenge[:8], payload[offset:offset+8])
	offset += 8

	// Filler (1 byte)
	offset++

	// Capability flags lower (2 bytes)
	if offset+2 > len(payload) {
		return nil, fmt.Errorf("packet too short for capability flags lower")
	}
	capsLower := uint32(binary.LittleEndian.Uint16(payload[offset : offset+2]))
	offset += 2

	// Charset (1 byte), status flags (2 bytes)
	offset += 3

	// Capability flags upper (2 bytes)
	if offset+2 > len(payload) {
		return nil, fmt.Errorf("packet too short for capability flags upper")
	}
	capsUpper := uint32(binary.LittleEndian.Uint16(payload[offset:offset+2])) << 16
	caps := capsLower | capsUpper
	offset += 2

	// Auth plugin data length (1 byte)
	if offset >= len(payload) {
		return nil, fmt.Errorf("packet too short for auth plugin data length")
	}
	authDataLen := int(payload[offset])
	offset++

	// Reserved (10 bytes)
	offset += 10

	// Auth plugin data part-2: max(13, authDataLen-8) bytes
	part2Len := authDataLen - 8
	if part2Len < 13 {
		part2Len = 13
	}
	if offset+part2Len > len(payload) {
		return nil, fmt.Errorf("packet too short for auth-plugin-data-part-2")
	}
	copy(challenge[8:], payload[offset:offset+12]) // only first 12 bytes are the actual nonce
	offset += part2Len

	// Auth plugin name (null-terminated, if CLIENT_PLUGIN_AUTH)
	var pluginName string
	if caps&capPluginAuth != 0 && offset < len(payload) {
		end := bytes.IndexByte(payload[offset:], 0x00)
		if end >= 0 {
			pluginName = string(payload[offset : offset+end])
		}
	}
	return &serverHandshake{challenge: challenge, pluginName: pluginName}, nil
}

// buildHandshakeResponse builds the client HandshakeResponse41 payload for the
// proxy->MySQL leg (no CLIENT_SSL -- the proxy connects to MySQL over plain TCP).
func buildHandshakeResponse(username string, authData []byte, dbName string) []byte {
	caps := capLongPassword | capLongFlag | capConnectWithDB |
		capProtocol41 | capSecureConn | capPluginAuth

	var b bytes.Buffer
	_ = binary.Write(&b, binary.LittleEndian, caps)
	_ = binary.Write(&b, binary.LittleEndian, uint32(16777216)) // max packet size
	b.WriteByte(0x21)                                       // charset utf8
	b.Write(make([]byte, 23))                               // reserved
	b.WriteString(username)
	b.WriteByte(0x00)
	b.WriteByte(byte(len(authData)))
	b.Write(authData)
	b.WriteString(dbName)
	b.WriteByte(0x00)
	b.WriteString("mysql_native_password\x00")
	return b.Bytes()
}

// buildOKPacket builds a minimal OK_Packet payload.
func buildOKPacket() []byte {
	return []byte{
		0x00,       // OK header
		0x00,       // affected rows (length-encoded int = 0)
		0x00,       // last insert id (length-encoded int = 0)
		0x02, 0x00, // status flags: SERVER_STATUS_AUTOCOMMIT
		0x00, 0x00, // warnings
	}
}

// parseAuthSwitchRequest parses an AuthSwitchRequest payload (first byte 0xFE).
// Returns the plugin name and challenge bytes.
func parseAuthSwitchRequest(payload []byte) (pluginName string, challenge []byte, err error) {
	if len(payload) == 0 || payload[0] != 0xFE {
		return "", nil, fmt.Errorf("expected AuthSwitchRequest (0xFE), got 0x%02x", payload[0])
	}
	end := bytes.IndexByte(payload[1:], 0x00)
	if end < 0 {
		return "", nil, fmt.Errorf("no null terminator in AuthSwitchRequest plugin name")
	}
	pluginName = string(payload[1 : 1+end])
	challenge = payload[1+end+1:]
	// Strip trailing null if present
	if len(challenge) > 0 && challenge[len(challenge)-1] == 0x00 {
		challenge = challenge[:len(challenge)-1]
	}
	return pluginName, challenge, nil
}

// extractErrMessage extracts the human-readable message from an ERR_Packet payload.
func extractErrMessage(payload []byte) string {
	// ERR: 0xFF(1) + error_code(2) + '#'(1) + sql_state(5) + message
	if len(payload) < 9 {
		return fmt.Sprintf("(short error packet, %d bytes)", len(payload))
	}
	return string(payload[9:])
}
