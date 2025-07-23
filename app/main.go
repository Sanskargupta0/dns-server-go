package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
)

// Ensures gofmt doesn't remove the "net" import in stage 1 (feel free to remove this!)
//var _ = net.ListenUDP

type Header struct {
	PacketIdentifier       uint16
	QueryResponseIndicator bool
	OperationCode          uint8
	AuthoritativeAnswer    bool
	Truncation             bool
	RecursionDesired       bool
	RecursionAvailable     bool
	Reserved               uint8
	ResponseCode           uint8
	QuestionCount          uint16
	AnswerRecordCount      uint16
	AuthorityRecordCount   uint16
	AdditionalRecordCount  uint16
}

func (hdr *Header) Serialize() []byte {
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], hdr.PacketIdentifier)
	return header
}

// Header is always 12 bytes long
type EndodedHeader = [12]byte

// BigEndian
func (h *Header) EncodeHeader() (EndodedHeader, error) {
	var buf EndodedHeader
	//ID
	binary.BigEndian.PutUint16(buf[0:2], h.PacketIdentifier)
	// 2nd Section (16 bit flags)
	flags, err := h.buildFlags()
	if err != nil {
		return [12]byte{}, fmt.Errorf("failed to set header flags, cause: %e", err)
	}
	fmt.Println("flags: ", flags)
	binary.BigEndian.PutUint16(buf[2:4], flags)
	binary.BigEndian.PutUint16(buf[4:6], h.QuestionCount)
	binary.BigEndian.PutUint16(buf[6:8], h.AnswerRecordCount)
	binary.BigEndian.PutUint16(buf[8:10], h.AuthorityRecordCount)
	binary.BigEndian.PutUint16(buf[10:12], h.AdditionalRecordCount)

	fmt.Println("header: ", buf[:])
	fmt.Println("header encoded: ", hex.EncodeToString(buf[:]))
	return buf, nil
}

// BigEndian
func (h *Header) DecodeHeader(buf EndodedHeader) Header {
	//header := Header{}
	h.PacketIdentifier = binary.BigEndian.Uint16(buf[0:2])
	flagsByte := binary.BigEndian.Uint16(buf[2:4])
	h.QueryResponseIndicator = true //(flagsByte>>15)&1 != 0
	h.OperationCode = uint8((flagsByte >> 11) & 0xF)
	h.AuthoritativeAnswer = false
	h.Truncation = false
	h.RecursionDesired = flagsByte>>8&1 != 0
	h.RecursionAvailable = false
	h.Reserved = 0
	if h.OperationCode == 0 {
		h.ResponseCode = 0
	} else {
		h.ResponseCode = 4
	}
	h.QuestionCount = 1
	h.AnswerRecordCount = 1
	h.AuthorityRecordCount = 0
	h.AdditionalRecordCount = 0

	return *h

}

// Build the second section of the header (16 bits)
//    0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15
//   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//   |QR|   Opcode  |AA|TC|RD|RA| Z|AD|CD|   RCODE   |
//   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//    ↑
//    Bit 15 (QR – Query/Response): 0 = Query, 1 = Response

func (h *Header) buildFlags() (uint16, error) {
	var flags uint16

	// Set QR
	if h.QueryResponseIndicator {
		flags |= 1 << 15
	}

	// Set OPCODE
	// Only from 0-15 (4 bits)
	flags |= uint16(h.OperationCode&0xF) << 11

	// Set AA TC RD RA
	if h.AuthoritativeAnswer {
		flags |= 1 << 10
	}
	if h.Truncation {
		flags |= 1 << 9
	}
	if h.RecursionDesired {
		flags |= 1 << 8
	}
	if h.RecursionAvailable {
		flags |= 1 << 7
	}

	// Set Reserved (Z)
	// Only from 0-8 (3 bits)
	flags |= uint16(h.Reserved&0x8) << 4

	// Set Response code (RCODE)
	// Only from 0-15 (4 bits)
	flags |= uint16(h.ResponseCode & 0xF)

	return flags, nil
}

func main() {
	fmt.Println("STarting")

	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:2053")
	if err != nil {
		fmt.Println("Failed to resolve UDP address:", err)
		return
	}
	//
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		fmt.Println("Failed to bind to address:", err)
		return
	}
	defer udpConn.Close()
	fmt.Println("Listening")
	//
	buf := make([]byte, 512)

	for {
		fmt.Println("For")
		size, source, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Error receiving data:", err)
			break
		}
		fmt.Println("Data")
		receivedData := string(buf[:size])
		fmt.Printf("Received %d bytes from %s: %s\n", size, source, receivedData)

		fmt.Printf("Received header from\n", receivedData[0:12])
		rHeader := Header{}
		header := rHeader.DecodeHeader(EndodedHeader(buf[0:12]))

		fmt.Printf("Received header from\n", header)
		// Create an empty response
		//response := []byte{0x04, 0xD2, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0}
		//header := rHeader.De
		// Create an empty response
		response, err := header.EncodeHeader()
		if err != nil {
			fmt.Println("failed to encode header")
		}

		//Write question after header
		hexString := "0c636f6465637261667465727302696f00"
		byteArray, err := hex.DecodeString(hexString)
		if err != nil {
			fmt.Println("Error decoding hex:", err)
			return
		}
		byteArray = append(byteArray, 0x00, 0x01, 0x00, 0x01)

		//Write question after header
		ansString := "0c636f6465637261667465727302696f00"
		ansArray, err := hex.DecodeString(ansString)
		if err != nil {
			fmt.Println("Error decoding hex:", err)
			return
		}
		ansArray = append(ansArray, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x60, 0x00, 0x04, 0x08, 0x08, 0x08, 0x08)

		_, err = udpConn.WriteToUDP(append(append(response[:], byteArray...), ansArray...), source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}
