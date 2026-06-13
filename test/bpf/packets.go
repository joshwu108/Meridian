//go:build bpf

package bpftest

import "encoding/binary"

// synthTCPPacket builds a minimal well-formed Ethernet + IPv4 + TCP frame.
// The parser must accept it (IPv4 ethertype, ihl=5, TCP).
func synthTCPPacket() []byte {
	const (
		ethHdrLen = 14
		ipHdrLen  = 20
		tcpHdrLen = 20
	)
	pkt := make([]byte, ethHdrLen+ipHdrLen+tcpHdrLen)

	// Ethernet.
	copy(pkt[0:6], []byte{0x02, 0, 0, 0, 0, 0x02})  // dst MAC (locally administered)
	copy(pkt[6:12], []byte{0x02, 0, 0, 0, 0, 0x01}) // src MAC
	binary.BigEndian.PutUint16(pkt[12:14], 0x0800)  // ethertype = IPv4

	// IPv4.
	ip := pkt[ethHdrLen:]
	ip[0] = 0x45 // version 4, IHL 5
	binary.BigEndian.PutUint16(ip[2:4], ipHdrLen+tcpHdrLen)
	binary.BigEndian.PutUint16(ip[4:6], 0x0001) // identification
	binary.BigEndian.PutUint16(ip[6:8], 0x4000) // DF
	ip[8] = 64                                  // TTL
	ip[9] = 6                                   // TCP
	copy(ip[12:16], []byte{169, 254, 10, 2})   // src
	copy(ip[16:20], []byte{169, 254, 10, 1})   // dst

	// TCP.
	tcp := pkt[ethHdrLen+ipHdrLen:]
	binary.BigEndian.PutUint16(tcp[0:2], 49152) // src port
	binary.BigEndian.PutUint16(tcp[2:4], 8080)  // dst port
	tcp[12] = 0x50                               // data offset 5
	tcp[13] = 0x02                               // SYN
	binary.BigEndian.PutUint16(tcp[14:16], 0xffff)

	return pkt
}

func synthIPv4Packet(proto uint8, srcIP, dstIP []byte) []byte {
	const (
		ethHdrLen = 14
		ipHdrLen  = 20
		l4HdrLen  = 8 // enough for both UDP and common TCP/UDP port prefix
	)

	pkt := make([]byte, ethHdrLen+ipHdrLen+l4HdrLen)
	copy(pkt[0:6], []byte{0x02, 0, 0, 0, 0, 0x02})  // dst MAC
	copy(pkt[6:12], []byte{0x02, 0, 0, 0, 0, 0x01}) // src MAC
	binary.BigEndian.PutUint16(pkt[12:14], 0x0800)  // IPv4 ethertype

	ip := pkt[ethHdrLen:]
	ip[0] = 0x45 // v4 + IHL 5
	binary.BigEndian.PutUint16(ip[2:4], ipHdrLen+l4HdrLen)
	ip[8] = 64
	ip[9] = proto
	copy(ip[12:16], srcIP)
	copy(ip[16:20], dstIP)

	l4 := pkt[ethHdrLen+ipHdrLen:]
	binary.BigEndian.PutUint16(l4[0:2], 40000)
	binary.BigEndian.PutUint16(l4[2:4], 8080)
	return pkt
}

func synthNonIPv4Packet(ethertype uint16) []byte {
	pkt := make([]byte, 14+32)
	copy(pkt[0:6], []byte{0x02, 0, 0, 0, 0, 0x02})
	copy(pkt[6:12], []byte{0x02, 0, 0, 0, 0, 0x01})
	binary.BigEndian.PutUint16(pkt[12:14], ethertype)
	return pkt
}

func synthMalformedIPv4IHLPacket(ihl uint8) []byte {
	const (
		ethHdrLen = 14
		ipHdrLen  = 20
	)
	pkt := make([]byte, ethHdrLen+ipHdrLen+8)
	copy(pkt[0:6], []byte{0x02, 0, 0, 0, 0, 0x02})
	copy(pkt[6:12], []byte{0x02, 0, 0, 0, 0, 0x01})
	binary.BigEndian.PutUint16(pkt[12:14], 0x0800)

	ip := pkt[ethHdrLen:]
	ip[0] = (4 << 4) | (ihl & 0x0f) // version 4 + chosen IHL nibble
	binary.BigEndian.PutUint16(ip[2:4], 28)
	ip[8] = 64
	ip[9] = 6 // TCP
	copy(ip[12:16], []byte{10, 9, 0, 1})
	copy(ip[16:20], []byte{10, 9, 0, 2})
	return pkt
}
