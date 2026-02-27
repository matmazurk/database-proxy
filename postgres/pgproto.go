package postgres

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

// SSLRequest is the magic number clients send to request TLS.
const sslRequestCode = 80877103

// readStartupOrSSL reads the first message from a client.
// Returns (isSSL, params map, error).
// If isSSL is true, params is nil - caller should upgrade to TLS and read again.
func readStartupOrSSL(r io.Reader) (bool, map[string]string, error) {
	// First 4 bytes: message length (including self)
	var length int32
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return false, nil, fmt.Errorf("reading length: %w", err)
	}

	// Next 4 bytes: protocol version or SSL request code
	var code int32
	if err := binary.Read(r, binary.BigEndian, &code); err != nil {
		return false, nil, fmt.Errorf("reading code: %w", err)
	}

	if code == sslRequestCode {
		return true, nil, nil
	}

	// It's a StartupMessage. Read the rest as null-terminated key-value pairs.
	remaining := make([]byte, length-8) // subtract length(4) + code(4)
	if _, err := io.ReadFull(r, remaining); err != nil {
		return false, nil, fmt.Errorf("reading params: %w", err)
	}

	params := make(map[string]string)
	parts := bytes.Split(remaining, []byte{0})
	for i := 0; i+1 < len(parts); i += 2 {
		key := string(parts[i])
		val := string(parts[i+1])
		if key == "" {
			break
		}
		params[key] = val
	}

	return false, params, nil
}

// writeSSLAccept writes the 'S' byte indicating SSL is supported.
func writeSSLAccept(w io.Writer) error {
	_, err := w.Write([]byte{'S'})
	return err
}

// writeAuthenticationOk sends AuthenticationOk (type 'R', status 0).
func writeAuthenticationOk(w io.Writer) error {
	// Type 'R' + length 8 + status 0
	msg := []byte{'R', 0, 0, 0, 8, 0, 0, 0, 0}
	_, err := w.Write(msg)
	return err
}

// writeReadyForQuery sends ReadyForQuery with 'I' (idle) status.
func writeReadyForQuery(w io.Writer) error {
	// Type 'Z' + length 5 + status 'I'
	msg := []byte{'Z', 0, 0, 0, 5, 'I'}
	_, err := w.Write(msg)
	return err
}

// buildStartupMessage creates a StartupMessage for the server connection.
func buildStartupMessage(user, database string) []byte {
	var buf bytes.Buffer

	// Placeholder for length
	buf.Write([]byte{0, 0, 0, 0})

	// Protocol version 3.0
	binary.Write(&buf, binary.BigEndian, int32(196608))

	// Parameters
	buf.WriteString("user")
	buf.WriteByte(0)
	buf.WriteString(user)
	buf.WriteByte(0)
	buf.WriteString("database")
	buf.WriteByte(0)
	buf.WriteString(database)
	buf.WriteByte(0)

	// Terminating null
	buf.WriteByte(0)

	// Write length
	msg := buf.Bytes()
	binary.BigEndian.PutUint32(msg[0:4], uint32(len(msg)))
	return msg
}

// readMessage reads a single protocol message (type byte + length + payload).
// Returns (msgType, payload, error). Payload does not include the type or length bytes.
func readMessage(r io.Reader) (byte, []byte, error) {
	var msgType [1]byte
	if _, err := io.ReadFull(r, msgType[:]); err != nil {
		return 0, nil, err
	}

	var length int32
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return 0, nil, err
	}

	payload := make([]byte, length-4) // length includes itself
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}

	return msgType[0], payload, nil
}

// writeMessage writes a protocol message (type byte + length + payload).
func writeMessage(w io.Writer, msgType byte, payload []byte) error {
	length := int32(len(payload) + 4)
	if _, err := w.Write([]byte{msgType}); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, length); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}
