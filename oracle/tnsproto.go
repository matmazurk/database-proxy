package oracle

import (
	"encoding/binary"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// TNS packet types
const (
	tnsConnect = 1
	tnsAccept  = 2
)

// TNS header is 8 bytes:
//
//	[0:2] packet length (big-endian)
//	[2:4] packet checksum (usually 0)
//	[4]   packet type
//	[5]   reserved
//	[6:8] header checksum (usually 0)
const tnsHeaderSize = 8

// tnsPacket represents a raw TNS packet.
type tnsPacket struct {
	packetType byte
	payload    []byte // everything after the 8-byte header
}

// readTNSPacket reads one TNS packet from the reader.
func readTNSPacket(r io.Reader) (*tnsPacket, error) {
	header := make([]byte, tnsHeaderSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, fmt.Errorf("reading TNS header: %w", err)
	}

	packetLen := int(binary.BigEndian.Uint16(header[0:2]))
	if packetLen < tnsHeaderSize {
		return nil, fmt.Errorf("invalid TNS packet length: %d", packetLen)
	}

	payload := make([]byte, packetLen-tnsHeaderSize)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, fmt.Errorf("reading TNS payload: %w", err)
	}

	return &tnsPacket{
		packetType: header[4],
		payload:    payload,
	}, nil
}

// writeTNSPacket writes a TNS packet to the writer.
func writeTNSPacket(w io.Writer, pkt *tnsPacket) error {
	totalLen := tnsHeaderSize + len(pkt.payload)
	header := make([]byte, tnsHeaderSize)
	binary.BigEndian.PutUint16(header[0:2], uint16(totalLen))
	// header[2:4] = checksum (0)
	header[4] = pkt.packetType
	// header[5] = reserved (0)
	// header[6:8] = header checksum (0)

	if _, err := w.Write(header); err != nil {
		return fmt.Errorf("writing TNS header: %w", err)
	}
	if _, err := w.Write(pkt.payload); err != nil {
		return fmt.Errorf("writing TNS payload: %w", err)
	}
	return nil
}

var serviceNameRe = regexp.MustCompile(`(?i)SERVICE_NAME\s*=\s*([^\s\)]+)`)

// parseServiceName extracts SERVICE_NAME from a TNS CONNECT packet's connection descriptor.
// The connect descriptor is an ASCII string embedded in the CONNECT payload.
func parseServiceName(connectPayload []byte) string {
	// The connect data starts after the fixed-length CONNECT header fields.
	// The CONNECT packet payload layout:
	//   [0:2]  version
	//   [2:4]  version compatible
	//   [4:6]  service options
	//   [6:8]  SDU size
	//   [8:10] TDU size
	//   [10:12] NT protocol characteristics
	//   [12:14] line turnaround value
	//   [14:16] value of 1 in hardware
	//   [16:18] connect data length
	//   [18:20] connect data offset
	//   [20:24] max receivable connect data
	//   [24]   connect flags 0
	//   [25]   connect flags 1
	//   Remaining bytes may include trace info, then connect data string

	if len(connectPayload) < 20 {
		return ""
	}

	connectDataLen := int(binary.BigEndian.Uint16(connectPayload[16:18]))
	connectDataOffset := int(binary.BigEndian.Uint16(connectPayload[18:20]))

	// Offset is relative to the start of the packet payload (after TNS header)
	if connectDataOffset+connectDataLen > len(connectPayload) || connectDataOffset < 0 {
		// Fall back to searching the entire payload
		matches := serviceNameRe.FindSubmatch(connectPayload)
		if matches != nil {
			return strings.TrimSpace(string(matches[1]))
		}
		return ""
	}

	connectData := string(connectPayload[connectDataOffset : connectDataOffset+connectDataLen])
	matches := serviceNameRe.FindStringSubmatch(connectData)
	if matches != nil {
		return strings.TrimSpace(matches[1])
	}
	return ""
}

// buildAcceptPayload builds a TNS ACCEPT packet payload.
// It mirrors key parameters from the client's CONNECT packet.
func buildAcceptPayload(connectPayload []byte) []byte {
	// ACCEPT payload layout:
	//   [0:2]  version
	//   [2:4]  service options
	//   [4:6]  SDU size
	//   [6:8]  TDU size
	//   [8:10] value of 1 in hardware
	//   [10:12] accept data length (0 — no data)
	//   [12:14] accept data offset
	//   [14]   connect flags 0
	//   [15]   connect flags 1

	accept := make([]byte, 16)

	if len(connectPayload) >= 26 {
		// Copy version from connect
		copy(accept[0:2], connectPayload[0:2])
		// Copy service options
		copy(accept[2:4], connectPayload[4:6])
		// Copy SDU size
		copy(accept[4:6], connectPayload[6:8])
		// Copy TDU size
		copy(accept[6:8], connectPayload[8:10])
		// Copy value of 1 in hardware
		copy(accept[8:10], connectPayload[14:16])
		// Accept data length = 0
		binary.BigEndian.PutUint16(accept[10:12], 0)
		// Accept data offset
		binary.BigEndian.PutUint16(accept[12:14], 16)
		// Connect flags
		accept[14] = connectPayload[24]
		accept[15] = connectPayload[25]
	} else {
		// Defaults for minimal ACCEPT
		binary.BigEndian.PutUint16(accept[0:2], 314)   // version
		binary.BigEndian.PutUint16(accept[4:6], 8192)  // SDU
		binary.BigEndian.PutUint16(accept[6:8], 65535)  // TDU
		binary.BigEndian.PutUint16(accept[12:14], 16)
	}

	return accept
}
