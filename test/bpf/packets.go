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
	copy(ip[12:16], []byte{169, 254, 10, 2})    // src
	copy(ip[16:20], []byte{169, 254, 10, 1})    // dst

	// TCP.
	tcp := pkt[ethHdrLen+ipHdrLen:]
	binary.BigEndian.PutUint16(tcp[0:2], 49152) // src port
	binary.BigEndian.PutUint16(tcp[2:4], 8080)  // dst port
	tcp[12] = 0x50                              // data offset 5
	tcp[13] = 0x02                              // SYN
	binary.BigEndian.PutUint16(tcp[14:16], 0xffff)

	return pkt
}

// synthVLANTaggedIPv4Packet wraps synthIPv4Packet with a single 802.1Q tag.
func synthVLANTaggedIPv4Packet(proto uint8, srcIP, dstIP []byte) []byte {
	inner := synthIPv4PacketFrom(proto, srcIP, dstIP)
	pkt := make([]byte, 4+len(inner))

	copy(pkt[0:6], []byte{0x02, 0, 0, 0, 0, 0x02})
	copy(pkt[6:12], []byte{0x02, 0, 0, 0, 0, 0x01})
	binary.BigEndian.PutUint16(pkt[12:14], 0x8100) // VLAN-tagged
	binary.BigEndian.PutUint16(pkt[14:16], 0x0064) // VLAN ID 100
	binary.BigEndian.PutUint16(pkt[16:18], 0x0800) // inner IPv4
	copy(pkt[18:], inner[14:])                     // skip inner Ethernet header
	return pkt
}

// synthTruncatedVLANTaggedPacket has 802.1Q ethertype but no complete VLAN tag.
func synthTruncatedVLANTaggedPacket() []byte {
	pkt := make([]byte, 16)
	copy(pkt[0:6], []byte{0x02, 0, 0, 0, 0, 0x02})
	copy(pkt[6:12], []byte{0x02, 0, 0, 0, 0, 0x01})
	binary.BigEndian.PutUint16(pkt[12:14], 0x8100)
	binary.BigEndian.PutUint16(pkt[14:16], 0x0064)
	return pkt
}

// synthVLANTaggedNonIPv4Packet carries VLAN with a non-IPv4 inner ethertype.
func synthVLANTaggedNonIPv4Packet(innerEthertype uint16) []byte {
	pkt := make([]byte, 18+32)
	copy(pkt[0:6], []byte{0x02, 0, 0, 0, 0, 0x02})
	copy(pkt[6:12], []byte{0x02, 0, 0, 0, 0, 0x01})
	binary.BigEndian.PutUint16(pkt[12:14], 0x8100)
	binary.BigEndian.PutUint16(pkt[14:16], 0x0064)
	binary.BigEndian.PutUint16(pkt[16:18], innerEthertype)
	return pkt
}

// synthVLANTaggedGeneveIPv4Packet wraps synthGeneveIPv4Packet with 802.1Q.
func synthVLANTaggedGeneveIPv4Packet(innerProto uint8, innerSrcIP, innerDstIP []byte, reserveTLVHeadroom bool) []byte {
	inner := synthGeneveIPv4Packet(innerProto, innerSrcIP, innerDstIP, reserveTLVHeadroom)
	pkt := make([]byte, 4+len(inner))

	copy(pkt[0:6], inner[0:6])
	copy(pkt[6:12], inner[6:12])
	binary.BigEndian.PutUint16(pkt[12:14], 0x8100)
	binary.BigEndian.PutUint16(pkt[14:16], 0x0064)
	binary.BigEndian.PutUint16(pkt[16:18], 0x0800)
	copy(pkt[18:], inner[14:])
	return pkt
}

func synthIPv4Packet(proto uint8, srcIP, dstIP []byte) []byte {
	return synthIPv4PacketFrom(proto, srcIP, dstIP)
}

func synthIPv4PacketFrom(proto uint8, srcIP, dstIP []byte) []byte {
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

// synthTruncatedEthPacket is a minimum-size Ethernet header (14 bytes). Pair with
// runTcIngressWithDataEnd(..., dataEnd < 14) to exercise the truncated-L2 path
// under bpf_prog_test_run's 14-byte minimum Data length.
func synthTruncatedEthPacket() []byte {
	pkt := make([]byte, 14)
	copy(pkt[0:6], []byte{0x02, 0, 0, 0, 0, 0x02})
	copy(pkt[6:12], []byte{0x02, 0, 0, 0, 0, 0x01})
	binary.BigEndian.PutUint16(pkt[12:14], 0x0800)
	return pkt
}

// synthTruncatedIPv4Packet has a valid Ethernet header but fewer than 20 IPv4 bytes.
func synthTruncatedIPv4Packet() []byte {
	const ethHdrLen = 14
	pkt := make([]byte, ethHdrLen+10)
	copy(pkt[0:6], []byte{0x02, 0, 0, 0, 0, 0x02})
	copy(pkt[6:12], []byte{0x02, 0, 0, 0, 0, 0x01})
	binary.BigEndian.PutUint16(pkt[12:14], 0x0800)
	ip := pkt[ethHdrLen:]
	ip[0] = 0x45
	return pkt
}

// synthMalformedIPv4IHLOptionsTruncated claims IHL=15 (60-byte header) in a short frame.
func synthMalformedIPv4IHLOptionsTruncated() []byte {
	const (
		ethHdrLen = 14
		ipHdrLen  = 20
	)
	pkt := make([]byte, ethHdrLen+ipHdrLen)
	copy(pkt[0:6], []byte{0x02, 0, 0, 0, 0, 0x02})
	copy(pkt[6:12], []byte{0x02, 0, 0, 0, 0, 0x01})
	binary.BigEndian.PutUint16(pkt[12:14], 0x0800)

	ip := pkt[ethHdrLen:]
	ip[0] = 0x4f // version 4, IHL 15
	binary.BigEndian.PutUint16(ip[2:4], ipHdrLen)
	ip[8] = 64
	ip[9] = 6
	copy(ip[12:16], []byte{10, 9, 1, 1})
	copy(ip[16:20], []byte{10, 9, 1, 2})
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

func synthGeneveIPv4Packet(innerProto uint8, innerSrcIP, innerDstIP []byte, reserveTLVHeadroom bool) []byte {
	const (
		ethHdrLen    = 14
		ipHdrLen     = 20
		udpHdrLen    = 8
		geneveHdrLen = 8
	)

	inner := synthInnerIPv4L4Payload(innerProto, innerSrcIP, innerDstIP)
	headroom := 0
	if reserveTLVHeadroom {
		headroom = 8
	}

	payloadLen := udpHdrLen + geneveHdrLen + headroom + len(inner)
	pkt := make([]byte, ethHdrLen+ipHdrLen+payloadLen)

	// Outer Ethernet.
	copy(pkt[0:6], []byte{0x02, 0, 0, 0, 0, 0x02})
	copy(pkt[6:12], []byte{0x02, 0, 0, 0, 0, 0x01})
	binary.BigEndian.PutUint16(pkt[12:14], 0x0800)

	// Outer IPv4.
	ip := pkt[ethHdrLen:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(ipHdrLen+payloadLen))
	ip[8] = 64
	ip[9] = 17 // UDP
	copy(ip[12:16], []byte{172, 31, 1, 2})
	copy(ip[16:20], []byte{172, 31, 1, 3})

	// Outer UDP.
	udp := pkt[ethHdrLen+ipHdrLen:]
	binary.BigEndian.PutUint16(udp[0:2], 40000)
	binary.BigEndian.PutUint16(udp[2:4], 6081)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpHdrLen+geneveHdrLen+headroom+len(inner)))

	// Geneve base header.
	geneve := udp[udpHdrLen:]
	geneve[0] = 0x00 // version=0, opt_len=0
	geneve[1] = 0x00
	binary.BigEndian.PutUint16(geneve[2:4], 0x0800) // inner protocol = IPv4 payload
	// VNI = 100 (24-bit field in bytes 4..6).
	geneve[4] = 0x00
	geneve[5] = 0x00
	geneve[6] = 0x64
	geneve[7] = 0x00

	copy(geneve[geneveHdrLen+headroom:], inner)
	return pkt
}

// synthGeneveIPv4PacketWithIdentity builds a Geneve-encapsulated frame whose
// option region already carries the Meridian identity TLV (post-egress shape).
func synthGeneveIPv4PacketWithIdentity(innerProto uint8, innerSrcIP, innerDstIP []byte, srcIdentity uint32) []byte {
	const (
		ethHdrLen    = 14
		ipHdrLen     = 20
		udpHdrLen    = 8
		geneveHdrLen = 8
		optBytes     = 8
	)

	inner := synthInnerIPv4L4Payload(innerProto, innerSrcIP, innerDstIP)
	payloadLen := udpHdrLen + geneveHdrLen + optBytes + len(inner)
	pkt := make([]byte, ethHdrLen+ipHdrLen+payloadLen)

	copy(pkt[0:6], []byte{0x02, 0, 0, 0, 0, 0x02})
	copy(pkt[6:12], []byte{0x02, 0, 0, 0, 0, 0x01})
	binary.BigEndian.PutUint16(pkt[12:14], 0x0800)

	ip := pkt[ethHdrLen:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(ipHdrLen+payloadLen))
	ip[8] = 64
	ip[9] = 17
	copy(ip[12:16], []byte{172, 31, 1, 2})
	copy(ip[16:20], []byte{172, 31, 1, 3})

	udp := pkt[ethHdrLen+ipHdrLen:]
	binary.BigEndian.PutUint16(udp[0:2], 40000)
	binary.BigEndian.PutUint16(udp[2:4], 6081)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpHdrLen+geneveHdrLen+optBytes+len(inner)))

	geneve := udp[udpHdrLen:]
	geneve[0] = 0x02 // version=0, opt_len=2 words
	geneve[1] = 0x00
	binary.BigEndian.PutUint16(geneve[2:4], 0x0800)
	geneve[4] = 0x00
	geneve[5] = 0x00
	geneve[6] = 0x64
	geneve[7] = 0x00

	opts := geneve[geneveHdrLen:]
	binary.BigEndian.PutUint16(opts[0:2], 0x4d52) // MERIDIAN_GENEVE_CLASS
	opts[2] = 0x01                                // MERIDIAN_OPT_IDENTITY
	opts[3] = 0x01                                // body length in 4-byte units
	binary.BigEndian.PutUint32(opts[4:8], srcIdentity)

	copy(opts[optBytes:], inner)
	return pkt
}

func synthMalformedGenevePacket() []byte {
	const (
		ethHdrLen = 14
		ipHdrLen  = 20
		udpHdrLen = 8
	)

	// Outer UDP points to Geneve, but payload is too short for the base header.
	payloadLen := udpHdrLen + 4
	pkt := make([]byte, ethHdrLen+ipHdrLen+payloadLen)
	copy(pkt[0:6], []byte{0x02, 0, 0, 0, 0, 0x02})
	copy(pkt[6:12], []byte{0x02, 0, 0, 0, 0, 0x01})
	binary.BigEndian.PutUint16(pkt[12:14], 0x0800)

	ip := pkt[ethHdrLen:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(ipHdrLen+payloadLen))
	ip[8] = 64
	ip[9] = 17
	copy(ip[12:16], []byte{172, 31, 9, 2})
	copy(ip[16:20], []byte{172, 31, 9, 3})

	udp := pkt[ethHdrLen+ipHdrLen:]
	binary.BigEndian.PutUint16(udp[0:2], 40000)
	binary.BigEndian.PutUint16(udp[2:4], 6081)
	binary.BigEndian.PutUint16(udp[4:6], uint16(payloadLen))
	return pkt
}

func synthInnerIPv4L4Payload(proto uint8, srcIP, dstIP []byte) []byte {
	const (
		ipHdrLen = 20
		l4HdrLen = 8
	)
	out := make([]byte, ipHdrLen+l4HdrLen)
	out[0] = 0x45
	binary.BigEndian.PutUint16(out[2:4], ipHdrLen+l4HdrLen)
	out[8] = 64
	out[9] = proto
	copy(out[12:16], srcIP)
	copy(out[16:20], dstIP)
	binary.BigEndian.PutUint16(out[ipHdrLen+0:ipHdrLen+2], 41000)
	binary.BigEndian.PutUint16(out[ipHdrLen+2:ipHdrLen+4], 8080)
	return out
}
