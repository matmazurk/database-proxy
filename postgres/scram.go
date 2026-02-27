package postgres

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/xdg-go/scram"
)

// PerformSCRAMAuth performs SCRAM-SHA-256 authentication on a server connection.
// The caller has already sent StartupMessage and read back an AuthenticationSASL
// message (msgType 'R', status 10) whose payload lists supported mechanisms.
func performSCRAMAuth(conn io.ReadWriter, password string, saslPayload []byte) error {
	// Verify SCRAM-SHA-256 is offered
	if !containsMechanism(saslPayload, "SCRAM-SHA-256") {
		return fmt.Errorf("server does not support SCRAM-SHA-256")
	}

	client, err := scram.SHA256.NewClient("", password, "")
	if err != nil {
		return fmt.Errorf("creating SCRAM client: %w", err)
	}
	conv := client.NewConversation()

	// Step 1: client-first-message
	clientFirst, err := conv.Step("")
	if err != nil {
		return fmt.Errorf("SCRAM step 1: %w", err)
	}

	// Send SASLInitialResponse (password message type 'p')
	if err := writeSASLInitialResponse(conn, "SCRAM-SHA-256", []byte(clientFirst)); err != nil {
		return fmt.Errorf("sending SASLInitialResponse: %w", err)
	}

	// Read AuthenticationSASLContinue (type 'R', status 11)
	msgType, payload, err := readMessage(conn)
	if err != nil {
		return fmt.Errorf("reading SASLContinue: %w", err)
	}
	if msgType != 'R' || binary.BigEndian.Uint32(payload[:4]) != 11 {
		return fmt.Errorf("expected AuthenticationSASLContinue, got type=%c status=%d", msgType, binary.BigEndian.Uint32(payload[:4]))
	}
	serverFirst := string(payload[4:])

	// Step 2: client-final-message
	clientFinal, err := conv.Step(serverFirst)
	if err != nil {
		return fmt.Errorf("SCRAM step 2: %w", err)
	}

	// Send SASLResponse (password message type 'p')
	if err := writeMessage(conn, 'p', []byte(clientFinal)); err != nil {
		return fmt.Errorf("sending SASLResponse: %w", err)
	}

	// Read AuthenticationSASLFinal (type 'R', status 12)
	msgType, payload, err = readMessage(conn)
	if err != nil {
		return fmt.Errorf("reading SASLFinal: %w", err)
	}
	if msgType != 'R' || binary.BigEndian.Uint32(payload[:4]) != 12 {
		return fmt.Errorf("expected AuthenticationSASLFinal, got type=%c status=%d", msgType, binary.BigEndian.Uint32(payload[:4]))
	}
	serverFinal := string(payload[4:])

	// Step 3: validate server signature
	_, err = conv.Step(serverFinal)
	if err != nil {
		return fmt.Errorf("SCRAM step 3 (server validation): %w", err)
	}

	// Read AuthenticationOk (type 'R', status 0)
	msgType, payload, err = readMessage(conn)
	if err != nil {
		return fmt.Errorf("reading AuthenticationOk: %w", err)
	}
	if msgType != 'R' || binary.BigEndian.Uint32(payload[:4]) != 0 {
		return fmt.Errorf("expected AuthenticationOk, got type=%c status=%d", msgType, binary.BigEndian.Uint32(payload[:4]))
	}

	return nil
}

func containsMechanism(payload []byte, mech string) bool {
	// After the 4-byte status code, mechanisms are null-terminated strings
	data := payload[4:]
	for len(data) > 0 {
		idx := 0
		for idx < len(data) && data[idx] != 0 {
			idx++
		}
		if string(data[:idx]) == mech {
			return true
		}
		if idx < len(data) {
			data = data[idx+1:]
		} else {
			break
		}
	}
	return false
}

func writeSASLInitialResponse(w io.Writer, mechanism string, data []byte) error {
	var buf []byte
	buf = append(buf, mechanism...)
	buf = append(buf, 0) // null terminator for mechanism name
	// 4-byte length of client-first-message
	lenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBytes, uint32(len(data)))
	buf = append(buf, lenBytes...)
	buf = append(buf, data...)
	return writeMessage(w, 'p', buf)
}
