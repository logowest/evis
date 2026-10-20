// Package ipstack builds and decodes the IPv4 + UDP headers that carry the DNS
// message. The built datagram is a valid packet (correct header + UDP checksums)
// so it decodes cleanly in Wireshark as well as in this tool.
package ipstack

import (
	"fmt"
	"net"

	"evis/internal/ber"
)

// UDPDatagram builds a complete IPv4 datagram: 20-byte IPv4 header + 8-byte UDP
// header + payload, with both checksums computed.
func UDPDatagram(src, dst net.IP, srcPort, dstPort uint16, ident uint16, ttl uint8, payload []byte) []byte {
	src4, dst4 := src.To4(), dst.To4()

	udpLen := 8 + len(payload)
	udp := make([]byte, 8)
	udp[0], udp[1] = byte(srcPort>>8), byte(srcPort)
	udp[2], udp[3] = byte(dstPort>>8), byte(dstPort)
	udp[4], udp[5] = byte(udpLen>>8), byte(udpLen)
	// checksum (udp[6:8]) left zero for now
	udpAll := append(udp, payload...)
	csum := udpChecksum(src4, dst4, udpAll)
	udpAll[6], udpAll[7] = byte(csum>>8), byte(csum)

	totalLen := 20 + udpLen
	ip := make([]byte, 20)
	ip[0] = 0x45 // version 4, IHL 5
	ip[1] = 0x00 // DSCP/ECN
	ip[2], ip[3] = byte(totalLen>>8), byte(totalLen)
	ip[4], ip[5] = byte(ident>>8), byte(ident)
	ip[6], ip[7] = 0x40, 0x00 // flags: DF set, fragment offset 0
	ip[8] = ttl
	ip[9] = 17 // protocol UDP
	// header checksum ip[10:12] zero for computation
	copy(ip[12:16], src4)
	copy(ip[16:20], dst4)
	hc := checksum(ip)
	ip[10], ip[11] = byte(hc>>8), byte(hc)

	return append(ip, udpAll...)
}

// checksum is the 16-bit one's-complement sum used by IPv4/UDP.
func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// udpChecksum adds the IPv4 pseudo-header before summing.
func udpChecksum(src, dst net.IP, udp []byte) uint16 {
	pseudo := make([]byte, 12+len(udp))
	copy(pseudo[0:4], src)
	copy(pseudo[4:8], dst)
	pseudo[8] = 0
	pseudo[9] = 17 // UDP
	pseudo[10], pseudo[11] = byte(len(udp)>>8), byte(len(udp))
	copy(pseudo[12:], udp)
	cs := checksum(pseudo)
	if cs == 0 {
		cs = 0xffff // 0 means "no checksum"; use the equivalent all-ones form
	}
	return cs
}

// DecodeNodes decodes an IPv4/UDP datagram into labelled byte-range nodes and
// returns the absolute offset and bytes of the UDP payload (the DNS message).
// base is the absolute offset of b within the whole file.
func DecodeNodes(b []byte, base int) (nodes []*ber.Node, payloadOff int, payload []byte) {
	raw := func(off, length int, name, typ, val string) *ber.Node {
		return &ber.Node{Raw: true, Offset: base + off, Length: length,
			Name: name, TypeName: typ, Value: val, Content: b[off : off+length]}
	}
	if len(b) < 20 || b[0]>>4 != 4 {
		return []*ber.Node{raw(0, len(b), "non-IPv4 payload", "", "")}, base + len(b), nil
	}
	ihl := int(b[0]&0x0f) * 4
	totalLen := int(b[2])<<8 | int(b[3])
	ident := int(b[4])<<8 | int(b[5])
	ttl := b[8]
	proto := b[9]
	srcIP := net.IP(b[12:16]).String()
	dstIP := net.IP(b[16:20]).String()

	ipNode := &ber.Node{Raw: true, Offset: base, Length: ihl, Name: "IPv4 header", TypeName: "RFC 791",
		Value: fmt.Sprintf("%s → %s, proto %s, TTL %d", srcIP, dstIP, protoName(proto), ttl)}
	ipNode.Children = []*ber.Node{
		raw(0, 1, "version/IHL", "nibble", fmt.Sprintf("v4, IHL %d bytes", ihl)),
		raw(2, 2, "totalLength", "uint16", fmt.Sprintf("%d", totalLen)),
		raw(4, 2, "identification", "uint16", fmt.Sprintf("0x%04x", ident)),
		raw(6, 2, "flags/fragment", "bits", flagsText(b[6], b[7])),
		raw(8, 1, "ttl", "uint8", fmt.Sprintf("%d", ttl)),
		raw(9, 1, "protocol", "uint8", fmt.Sprintf("%s (%d)", protoName(proto), proto)),
		raw(10, 2, "headerChecksum", "uint16", fmt.Sprintf("0x%02x%02x", b[10], b[11])),
		raw(12, 4, "source", "IPv4", srcIP),
		raw(16, 4, "destination", "IPv4", dstIP),
	}
	nodes = append(nodes, ipNode)

	if proto != 17 || len(b) < ihl+8 {
		return nodes, base + ihl, b[min(ihl, len(b)):]
	}
	u := b[ihl : ihl+8]
	sp := int(u[0])<<8 | int(u[1])
	dp := int(u[2])<<8 | int(u[3])
	ul := int(u[4])<<8 | int(u[5])
	udpNode := &ber.Node{Raw: true, Offset: base + ihl, Length: 8, Name: "UDP header", TypeName: "RFC 768",
		Value: fmt.Sprintf("%d → %d, len %d", sp, dp, ul)}
	udpNode.Children = []*ber.Node{
		raw(ihl, 2, "sourcePort", "uint16", fmt.Sprintf("%d", sp)),
		raw(ihl+2, 2, "destinationPort", "uint16", fmt.Sprintf("%d%s", dp, portHint(dp))),
		raw(ihl+4, 2, "length", "uint16", fmt.Sprintf("%d", ul)),
		raw(ihl+6, 2, "checksum", "uint16", fmt.Sprintf("0x%02x%02x", u[6], u[7])),
	}
	nodes = append(nodes, udpNode)

	payloadOff = base + ihl + 8
	payload = b[ihl+8:]
	return nodes, payloadOff, payload
}

func protoName(p byte) string {
	switch p {
	case 1:
		return "ICMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	default:
		return fmt.Sprintf("%d", p)
	}
}

func portHint(p int) string {
	if p == 53 {
		return " (domain)"
	}
	return ""
}

func flagsText(hi, lo byte) string {
	df := hi&0x40 != 0
	mf := hi&0x20 != 0
	off := (int(hi&0x1f) << 8) | int(lo)
	s := fmt.Sprintf("offset %d", off)
	if df {
		s = "DF, " + s
	}
	if mf {
		s = "MF, " + s
	}
	return s
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
