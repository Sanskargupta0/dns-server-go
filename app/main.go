package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

// Ensures gofmt doesn't remove the "net" import in stage 1 (feel free to remove this!)
var _ = net.ListenUDP

// ResourceRecord represents a DNS "A" record (IPv4) answer.
type ResourceRecord struct {
	Name     string // e.g. "www.example.com"
	Type     uint16 // 1 = A record
	Class    uint16 // 1 = IN (Internet)
	TTL      uint32 // Cache duration in seconds
	RDLength uint16 // Always 4 for IPv4
	RData    string // e.g. "93.184.216.34"
}

// Serialize encodes the resource record into DNS wire format (assuming valid input).
func (rr *ResourceRecord) Serialize() []byte {
	var buf []byte

	// Encode Name as label sequence
	labels := strings.Split(rr.Name, ".")
	for _, label := range labels {
		buf = append(buf, byte(len(label)))
		buf = append(buf, []byte(label)...)
	}
	buf = append(buf, 0x00) // End of domain name

	// Type
	tmp := make([]byte, 2)
	binary.BigEndian.PutUint16(tmp, rr.Type)
	buf = append(buf, tmp...)

	// Class
	binary.BigEndian.PutUint16(tmp, rr.Class)
	buf = append(buf, tmp...)

	// TTL
	tmp = make([]byte, 4)
	binary.BigEndian.PutUint32(tmp, rr.TTL)
	buf = append(buf, tmp...)

	// RDLength (4 for IPv4)
	tmp = make([]byte, 2)
	binary.BigEndian.PutUint16(tmp, 4)
	buf = append(buf, tmp...)

	// RData (convert dotted string to 4 bytes)
	for _, octet := range strings.Split(rr.RData, ".") {
		n, _ := strconv.Atoi(octet) // assume it's valid
		buf = append(buf, byte(n))
	}

	return buf
}

type Header struct {
	ID uint16 // 16 bits

	// Flags (packed into 16 bits)
	QR     uint8 // 1 bit
	OPCode uint8 // 4 bits
	AA     uint8 // 1 bit
	TC     uint8 // 1 bit
	RD     uint8 // 1 bit
	RA     uint8 // 1 bit
	Z      uint8 // 3 bits (reserved, must be 0 in queries)
	RCode  uint8 // 4 bits

	QDCount uint16 // 16 bits
	ANCount uint16 // 16 bits
	NSCount uint16 // 16 bits
	ARCount uint16 // 16 bits
}

// Encode serializes the DNS header into a fixed 12-byte array (big-endian).
func (h Header) Encode() [12]byte {
	var b [12]byte

	// Write ID
	binary.BigEndian.PutUint16(b[0:2], h.ID)

	// Construct flags from fields
	flags := uint16(h.QR&1)<<15 |
		uint16(h.OPCode&0xF)<<11 |
		uint16(h.AA&1)<<10 |
		uint16(h.TC&1)<<9 |
		uint16(h.RD&1)<<8 |
		uint16(h.RA&1)<<7 |
		uint16(h.Z&0x7)<<4 |
		uint16(h.RCode&0xF)

	binary.BigEndian.PutUint16(b[2:4], flags)

	// Write counts
	binary.BigEndian.PutUint16(b[4:6], h.QDCount)
	binary.BigEndian.PutUint16(b[6:8], h.ANCount)
	binary.BigEndian.PutUint16(b[8:10], h.NSCount)
	binary.BigEndian.PutUint16(b[10:12], h.ARCount)

	return b
}

// DecodeHeader parses a 12-byte DNS header into a Header struct.
func DecodeHeader(b [12]byte) Header {
	id := binary.BigEndian.Uint16(b[0:2])
	flags := binary.BigEndian.Uint16(b[2:4])

	return Header{
		ID:      id,
		QR:      uint8((flags >> 15) & 1),
		OPCode:  uint8((flags >> 11) & 0xF),
		AA:      uint8((flags >> 10) & 1),
		TC:      uint8((flags >> 9) & 1),
		RD:      uint8((flags >> 8) & 1),
		RA:      uint8((flags >> 7) & 1),
		Z:       uint8((flags >> 4) & 0x7),
		RCode:   uint8(flags & 0xF),
		QDCount: binary.BigEndian.Uint16(b[4:6]),
		ANCount: binary.BigEndian.Uint16(b[6:8]),
		NSCount: binary.BigEndian.Uint16(b[8:10]),
		ARCount: binary.BigEndian.Uint16(b[10:12]),
	}
}

type Question struct {
	Name  string // e.g., "codecrafters.io"
	Type  uint16 // e.g., 1 (A)
	Class uint16 // e.g., 1 (IN)
}

// Encode serializes a DNS Question into bytes.
func (q Question) Encode() []byte {
	var buf []byte

	// Encode domain name: "codecrafters.io" -> \x0ccodecrafters\x02io\x00
	labels := strings.Split(q.Name, ".")
	for _, label := range labels {
		if len(label) > 63 {
			continue // Skip invalid labels
		}
		buf = append(buf, byte(len(label)))
		buf = append(buf, label...)
	}
	buf = append(buf, 0x00) // End of name

	// Append Type and Class (2 bytes each, big-endian)
	typeBuf := make([]byte, 2)
	classBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(typeBuf, q.Type)
	binary.BigEndian.PutUint16(classBuf, q.Class)

	buf = append(buf, typeBuf...)
	buf = append(buf, classBuf...)

	return buf
}
func DecodeQuestion(data []byte, offset int) (Question, int) {
	var q Question
	var labels []string

	// Decode domain name
	start := offset
	for {
		length := int(data[offset])
		if length == 0 {
			offset++
			break
		}
		offset++
		labels = append(labels, string(data[offset:offset+length]))
		offset += length
	}
	q.Name = strings.Join(labels, ".")

	// Type (2 bytes)
	q.Type = binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	// Class (2 bytes)
	q.Class = binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	return q, offset - start // return question and number of bytes consumed
}

type Questions []Question

// DecodeHeaderFromBytes reads a DNS header from a 12-byte slice.
func DecodeHeaderFromBytes(data []byte) (Header, error) {
	if len(data) < 12 {
		return Header{}, fmt.Errorf("insufficient data: want 12 bytes, got %d", len(data))
	}
	var b [12]byte
	copy(b[:], data[:12])
	return DecodeHeader(b), nil
}

func DecodeHeaderFromStrings(data string) (Header, error) {
	return DecodeHeaderFromBytes([]byte(data))
}

// DecodeHeaderFromReader reads a DNS header from an io.Reader (e.g., net.Conn).
func DecodeHeaderFromReader(r io.Reader) (Header, error) {
	var b [12]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return Header{}, fmt.Errorf("read header: %w", err)
	}
	return DecodeHeader(b), nil
}

// String formats the Header in a readable form for debugging/logging.
func (h Header) String() string {
	return fmt.Sprintf(
		"ID: 0x%04X, QR: %d, OPCode: %d, AA: %d, TC: %d, RD: %d, RA: %d, Z: %d, RCode: %d, QD: %d, AN: %d, NS: %d, AR: %d",
		h.ID, h.QR, h.OPCode, h.AA, h.TC, h.RD, h.RA, h.Z, h.RCode, h.QDCount, h.ANCount, h.NSCount, h.ARCount,
	)
}

func main() {
	// You can use print statements as follows for debugging, they'll be visible when running tests.
	fmt.Println("Logs from your program will appear here!")

	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:2053")
	if err != nil {
		fmt.Println("Failed to resolve UDP address:", err)
		return
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		fmt.Println("Failed to bind to address:", err)
		return
	}
	defer udpConn.Close()

	buf := make([]byte, 512)

	for {
		size, source, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Error receiving data:", err)
			break
		}

		receivedData := string(buf[:size])

		heada, err := DecodeHeaderFromBytes(buf[:size])

		fmt.Printf("Received %d bytes from %s: %s\n", size, source, receivedData, err)

		qa, msd := DecodeQuestion(buf[:size], 12)

		fmt.Println("Question: ", qa, msd)

		//qa2, msd2 := DecodeQuestion(buf[:size], 12+msd)

		//fmt.Println("Question 2: ", qa2, msd2)

		header := Header{
			ID:      heada.ID,
			QR:      1,
			OPCode:  heada.OPCode,
			AA:      0,
			TC:      0,
			RD:      heada.RD,
			RA:      0,
			Z:       0,
			RCode:   4,
			QDCount: 1,
			ANCount: 2,
			NSCount: 0,
			ARCount: 0,
		}
		question := Question{
			Name:  qa.Name,
			Type:  1, // A record
			Class: 1, // IN
		}

		rr1 := ResourceRecord{
			Name:     qa.Name,
			Type:     1,
			Class:    1,
			TTL:      60,
			RDLength: 4,
			RData:    "8.8.8.8",
		}

		rr2 := ResourceRecord{
			Name:     qa.Name,
			Type:     1,
			Class:    1,
			TTL:      60,
			RDLength: 4,
			RData:    "8.8.8.8",
		}

		var packet []byte

		head := header.Encode()

		packet = append(packet, head[:]...)
		packet = append(packet, question.Encode()...)
		packet = append(packet, rr1.Serialize()...)
		packet = append(packet, rr2.Serialize()...)

		_, err = udpConn.WriteToUDP(packet, source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}
