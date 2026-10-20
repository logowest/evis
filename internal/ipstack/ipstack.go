// Package ipstack builds and decodes the IPv4 + UDP/TCP headers that carry the
// DNS or HTTP message. The built datagram is a valid packet (correct header + UDP checksums)
// so it decodes cleanly in Wireshark as well as in this tool.
package ipstack

import (
	"fmt"
	"net"
	"strings"

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

	return append(ipv4Header(src4, dst4, ident, ttl, 17, len(udpAll)), udpAll...)
}

// TCP flag bits (low 6 bits of the TCP flags octet).
const (
	TCPFin = 0x01
	TCPSyn = 0x02
	TCPRst = 0x04
	TCPPsh = 0x08
	TCPAck = 0x10
	TCPUrg = 0x20
)

// TCP describes one TCP segment's header fields.
type TCP struct {
	SrcPort, DstPort uint16
	Seq, Ack         uint32
	Flags            byte // TCPFin | TCPSyn | ...
	Window           uint16
}

// TCPHeaderLen is the length of the option-less TCP header built here.
const TCPHeaderLen = 20

// TCPSegment builds a complete IPv4 datagram: 20-byte IPv4 header + 20-byte TCP
// header (no options) + payload, with both checksums computed.
func TCPSegment(src, dst net.IP, ident uint16, ttl uint8, t TCP, payload []byte) []byte {
	src4, dst4 := src.To4(), dst.To4()

	tcp := make([]byte, TCPHeaderLen)
	tcp[0], tcp[1] = byte(t.SrcPort>>8), byte(t.SrcPort)
	tcp[2], tcp[3] = byte(t.DstPort>>8), byte(t.DstPort)
	copy(tcp[4:8], []byte{byte(t.Seq >> 24), byte(t.Seq >> 16), byte(t.Seq >> 8), byte(t.Seq)})
	copy(tcp[8:12], []byte{byte(t.Ack >> 24), byte(t.Ack >> 16), byte(t.Ack >> 8), byte(t.Ack)})
	tcp[12] = byte(TCPHeaderLen/4) << 4 // data offset in 32-bit words
	tcp[13] = t.Flags
	tcp[14], tcp[15] = byte(t.Window>>8), byte(t.Window)
	// checksum tcp[16:18] and urgent pointer tcp[18:20] zero for now
	tcpAll := append(tcp, payload...)
	csum := checksum(pseudoHeader(src4, dst4, 6, tcpAll))
	tcpAll[16], tcpAll[17] = byte(csum>>8), byte(csum)

	return append(ipv4Header(src4, dst4, ident, ttl, 6, len(tcpAll)), tcpAll...)
}

// ipv4Header builds a 20-byte IPv4 header (no options, DF set) with its checksum.
func ipv4Header(src4, dst4 net.IP, ident uint16, ttl, proto uint8, dataLen int) []byte {
	totalLen := 20 + dataLen
	ip := make([]byte, 20)
	ip[0] = 0x45 // version 4, IHL 5
	ip[1] = 0x00 // DSCP/ECN
	ip[2], ip[3] = byte(totalLen>>8), byte(totalLen)
	ip[4], ip[5] = byte(ident>>8), byte(ident)
	ip[6], ip[7] = 0x40, 0x00 // flags: DF set, fragment offset 0
	ip[8] = ttl
	ip[9] = proto
	// header checksum ip[10:12] zero for computation
	copy(ip[12:16], src4)
	copy(ip[16:20], dst4)
	hc := checksum(ip)
	ip[10], ip[11] = byte(hc>>8), byte(hc)
	return ip
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
	cs := checksum(pseudoHeader(src, dst, 17, udp))
	if cs == 0 {
		cs = 0xffff // 0 means "no checksum"; use the equivalent all-ones form
	}
	return cs
}

// pseudoHeader prefixes a transport segment with the IPv4 pseudo-header used
// by the UDP and TCP checksums.
func pseudoHeader(src, dst net.IP, proto byte, seg []byte) []byte {
	pseudo := make([]byte, 12+len(seg))
	copy(pseudo[0:4], src)
	copy(pseudo[4:8], dst)
	pseudo[9] = proto
	pseudo[10], pseudo[11] = byte(len(seg)>>8), byte(len(seg))
	copy(pseudo[12:], seg)
	return pseudo
}

// Transport identifies the flow of a decoded datagram, so callers can choose a
// decoder for its payload and reassemble TCP streams. Ports are 0 when the
// transport header was not decoded; Seq and Flags are set for TCP only.
type Transport struct {
	Proto            byte // IP protocol number (6 = TCP, 17 = UDP)
	SrcIP, DstIP     net.IP
	SrcPort, DstPort int
	Seq              uint32 // TCP sequence number of the first payload byte
	Flags            byte   // TCP flags (TCPSyn, TCPFin, ...)
}

// HasPort reports whether either port is p.
func (t Transport) HasPort(p int) bool { return t.SrcPort == p || t.DstPort == p }

// DecodeNodes decodes an IPv4/UDP or IPv4/TCP datagram into labelled byte-range
// nodes and returns the transport protocol and ports plus the absolute offset
// and bytes of the transport payload (e.g. the DNS or HTTP message). base is
// the absolute offset of b within the whole file.
func DecodeNodes(b []byte, base int) (nodes []*ber.Node, tr Transport, payloadOff int, payload []byte) {
	raw := func(off, length int, name, typ, val string) *ber.Node {
		return &ber.Node{Raw: true, Offset: base + off, Length: length,
			Name: name, TypeName: typ, Value: val, Content: b[off : off+length]}
	}
	if len(b) < 20 || b[0]>>4 != 4 {
		return []*ber.Node{raw(0, len(b), "non-IPv4 payload", "", "")}, tr, base + len(b), nil
	}
	ihl := int(b[0]&0x0f) * 4
	totalLen := int(b[2])<<8 | int(b[3])
	ident := int(b[4])<<8 | int(b[5])
	ttl := b[8]
	proto := b[9]
	tr.Proto = proto
	tr.SrcIP, tr.DstIP = net.IP(b[12:16]), net.IP(b[16:20])
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

	if proto == 6 {
		return decodeTCP(b, base, ihl, raw, nodes, tr)
	}
	if proto != 17 || len(b) < ihl+8 {
		return nodes, tr, base + ihl, b[min(ihl, len(b)):]
	}
	u := b[ihl : ihl+8]
	sp := int(u[0])<<8 | int(u[1])
	dp := int(u[2])<<8 | int(u[3])
	ul := int(u[4])<<8 | int(u[5])
	udpNode := &ber.Node{Raw: true, Offset: base + ihl, Length: 8, Name: "UDP header", TypeName: "RFC 768",
		Value: fmt.Sprintf("%d → %d, len %d", sp, dp, ul)}
	udpNode.Children = []*ber.Node{
		raw(ihl, 2, "sourcePort", "uint16", fmt.Sprintf("%d", sp)),
		raw(ihl+2, 2, "destinationPort", "uint16", fmt.Sprintf("%d%s", dp, PortHint(dp))),
		raw(ihl+4, 2, "length", "uint16", fmt.Sprintf("%d", ul)),
		raw(ihl+6, 2, "checksum", "uint16", fmt.Sprintf("0x%02x%02x", u[6], u[7])),
	}
	nodes = append(nodes, udpNode)

	tr.SrcPort, tr.DstPort = sp, dp
	payloadOff = base + ihl + 8
	payload = b[ihl+8:]
	return nodes, tr, payloadOff, payload
}

// decodeTCP appends the TCP header node (RFC 9293) after the IPv4 header.
func decodeTCP(b []byte, base, ihl int, raw func(off, length int, name, typ, val string) *ber.Node,
	nodes []*ber.Node, tr Transport) ([]*ber.Node, Transport, int, []byte) {
	if len(b) < ihl+TCPHeaderLen {
		return nodes, tr, base + ihl, b[ihl:]
	}
	t := b[ihl:]
	hl := int(t[12]>>4) * 4
	if hl < TCPHeaderLen || len(t) < hl {
		hl = TCPHeaderLen
	}
	sp := int(t[0])<<8 | int(t[1])
	dp := int(t[2])<<8 | int(t[3])
	seq := uint32(t[4])<<24 | uint32(t[5])<<16 | uint32(t[6])<<8 | uint32(t[7])
	ack := uint32(t[8])<<24 | uint32(t[9])<<16 | uint32(t[10])<<8 | uint32(t[11])
	tcpNode := &ber.Node{Raw: true, Offset: base + ihl, Length: hl, Name: "TCP header", TypeName: "RFC 9293",
		Value: fmt.Sprintf("%d → %d, [%s] seq %d", sp, dp, TCPFlagsText(t[13]), seq)}
	tcpNode.Children = []*ber.Node{
		raw(ihl, 2, "sourcePort", "uint16", fmt.Sprintf("%d", sp)),
		raw(ihl+2, 2, "destinationPort", "uint16", fmt.Sprintf("%d%s", dp, PortHint(dp))),
		raw(ihl+4, 4, "sequenceNumber", "uint32", fmt.Sprintf("%d", seq)),
		raw(ihl+8, 4, "ackNumber", "uint32", fmt.Sprintf("%d", ack)),
		raw(ihl+12, 1, "dataOffset", "nibble", fmt.Sprintf("%d bytes", hl)),
		raw(ihl+13, 1, "controlBits", "bits", TCPFlagsText(t[13])),
		raw(ihl+14, 2, "windowSize", "uint16", fmt.Sprintf("%d", int(t[14])<<8|int(t[15]))),
		raw(ihl+16, 2, "checksum", "uint16", fmt.Sprintf("0x%02x%02x", t[16], t[17])),
		raw(ihl+18, 2, "urgentPointer", "uint16", fmt.Sprintf("%d", int(t[18])<<8|int(t[19]))),
	}
	if hl > TCPHeaderLen {
		tcpNode.Children = append(tcpNode.Children, raw(ihl+TCPHeaderLen, hl-TCPHeaderLen, "options", "bytes", ""))
	}
	nodes = append(nodes, tcpNode)
	tr.SrcPort, tr.DstPort, tr.Seq, tr.Flags = sp, dp, seq, t[13]
	return nodes, tr, base + ihl + hl, b[ihl+hl:]
}

// TCPFlagsText renders the low 6 TCP flag bits, e.g. "PSH, ACK".
func TCPFlagsText(f byte) string {
	var parts []string
	for _, x := range []struct {
		bit  byte
		name string
	}{{TCPUrg, "URG"}, {TCPSyn, "SYN"}, {TCPFin, "FIN"}, {TCPRst, "RST"}, {TCPPsh, "PSH"}, {TCPAck, "ACK"}} {
		if f&x.bit != 0 {
			parts = append(parts, x.name)
		}
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ", ")
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

// PortHint names well-known ports used by the samples, e.g. " (http)".
func PortHint(p int) string {
	switch p {
	case 53:
		return " (domain)"
	case 80:
		return " (http)"
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
