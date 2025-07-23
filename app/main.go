package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"net"
)

var resAddr *net.UDPAddr

type DNSHeader [12]byte

func (h *DNSHeader) SetID(id []byte) {
	copy(h[:2], id[:2])
}

func (h *DNSHeader) SetReply() {
	h[2] |= 0b10000000
}

func (h *DNSHeader) SetQDCount(n uint16) {
	binary.BigEndian.PutUint16(h[4:6], n)
}

func (h *DNSHeader) GetQDCount() uint16 {
	return binary.BigEndian.Uint16((*h)[4:6])
}

func (h *DNSHeader) SetAnCount(n uint16) {
	binary.BigEndian.PutUint16(h[6:8], n)
}

type DNSMessage struct {
	Header    DNSHeader
	Questions []byte
	Answers   []byte
}

func (m *DNSMessage) Reply(msg []byte) {
	// set ID
	copy(m.Header[:2], msg[:2])
	// set QR, OPCODE, AA, TC, RD
	m.Header[2] = msg[2]&0xf9 | 0x80
	// set QDCOUNT, ANCOUNT
	copy(m.Header[4:6], msg[4:6])
	copy(m.Header[6:8], msg[4:6])
	// set RA, Z, RCODE
	if m.Header[2]&0b01111000 != 0 {
		m.Header[3] = 4
	}
	// copy questions
	var b bytes.Buffer
	count := binary.BigEndian.Uint16(msg[4:6])
	i := 12
	for range count {
		i += extractQuestion(msg, i, &b)
	}
	m.Questions = b.Bytes()
}

func (m *DNSMessage) MakeAnswer() {
	buf := make([]byte, 512)
	conn, err := net.DialUDP("udp", nil, resAddr)
	if err != nil {
		fmt.Println("Failed to dial:", err)
		return
	}
	defer conn.Close()
	var out bytes.Buffer
	i, k := 0, 0
	for range m.Header.GetQDCount() {
		for m.Questions[i] != 0 {
			i += int(m.Questions[i]) + 1
		}
		i += 5
		if _, err = conn.Write(m.BuildForward(m.Questions[k:i])); err != nil {
			fmt.Println("Failed to forward request:", err)
			return
		}
		l, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Error receiving data:", err)
			break
		}
		out.Write(buf[12+i-k : l])
		k = i
	}
	m.Answers = out.Bytes()
}

func (m *DNSMessage) BuildResponse() []byte {
	var b bytes.Buffer
	b.Write(m.Header[:])
	b.Write(m.Questions)
	b.Write(m.Answers)
	return b.Bytes()
}

func (m *DNSMessage) BuildForward(question []byte) []byte {
	res := make([]byte, 12+len(question))
	binary.BigEndian.PutUint16(res[4:6], 1)
	copy(res[12:], question)
	return res
}

func main() {
	addr := flag.String("resolver", "", "resolver server")
	flag.Parse()
	var err error
	if resAddr, err = net.ResolveUDPAddr("udp", *addr); err != nil {
		fmt.Println("Failed to resolve resolver UDP address:", err)
		return
	}

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

		// receivedData := string(buf[:size])
		// fmt.Printf("Received %d bytes from %s: %s\n", size, source, receivedData)

		msg := DNSMessage{}
		msg.Reply(buf[:size])
		msg.MakeAnswer()

		_, err = udpConn.WriteToUDP(msg.BuildResponse(), source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}

func extractQuestion(m []byte, i int, b *bytes.Buffer) int {
	if m[i] == 0 {
		b.Write(m[i : i+5])
		return 5
	} else if m[i]&0xc0 == 0 {
		k := int(m[i])
		b.Write(m[i : i+k+1])
		return k + 1 + extractQuestion(m, i+k+1, b)
	}
	offset := int(binary.BigEndian.Uint16(m[i:i+2]) & 0x3fff)
	extractQuestion(m, offset, b)
	return 2
}
