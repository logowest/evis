// Package dns builds and decodes a minimal DNS message on the wire (RFC 1035),
// enough for a single standard query such as an A lookup. It is used both to
// synthesise the intercepted packet and to decode it for the visualiser.
package dns

import (
	"fmt"
	"strings"

	"evis/internal/ber"
)

// Query options for a single question.
type Query struct {
	ID     uint16
	RD     bool   // recursion desired
	Name   string // e.g. "example.com."
	QType  uint16 // e.g. TypeA
	QClass uint16
}

const (
	TypeA     = 1
	TypeNS    = 2
	TypeCNAME = 5
	TypeAAAA  = 28
	ClassIN   = 1
)

// Build encodes q as a DNS query message (header + one question section).
func Build(q Query) []byte {
	var flags uint16
	if q.RD {
		flags |= 0x0100 // RD bit
	}
	msg := make([]byte, 0, 32)
	msg = append(msg, byte(q.ID>>8), byte(q.ID))
	msg = append(msg, byte(flags>>8), byte(flags))
	msg = append(msg, 0x00, 0x01) // QDCOUNT = 1
	msg = append(msg, 0x00, 0x00) // ANCOUNT
	msg = append(msg, 0x00, 0x00) // NSCOUNT
	msg = append(msg, 0x00, 0x00) // ARCOUNT
	msg = append(msg, encodeName(q.Name)...)
	msg = append(msg, byte(q.QType>>8), byte(q.QType))
	msg = append(msg, byte(q.QClass>>8), byte(q.QClass))
	return msg
}

func encodeName(name string) []byte {
	name = strings.TrimSuffix(name, ".")
	var out []byte
	if name != "" {
		for _, label := range strings.Split(name, ".") {
			out = append(out, byte(len(label)))
			out = append(out, []byte(label)...)
		}
	}
	out = append(out, 0x00) // root
	return out
}

// TypeName maps a QTYPE to its mnemonic.
func TypeName(t uint16) string {
	switch t {
	case TypeA:
		return "A"
	case TypeNS:
		return "NS"
	case TypeCNAME:
		return "CNAME"
	case TypeAAAA:
		return "AAAA"
	default:
		return fmt.Sprintf("TYPE%d", t)
	}
}

func classText(c uint16) string {
	if c == ClassIN {
		return "IN"
	}
	return fmt.Sprintf("CLASS%d", c)
}

func opcodeText(op uint16) string {
	switch op {
	case 0:
		return "QUERY"
	case 1:
		return "IQUERY"
	case 2:
		return "STATUS"
	default:
		return fmt.Sprintf("OP%d", op)
	}
}

// DecodeNodes parses a DNS message and returns a tree of labelled byte-range
// (Raw) nodes, with offsets biased by base (the absolute offset of the message
// within the whole file). It decodes the header and question section, which is
// all a standard query contains.
func DecodeNodes(b []byte, base int) []*ber.Node {
	raw := func(off, length int, name, typ, val string) *ber.Node {
		return &ber.Node{Raw: true, Offset: base + off, Length: length,
			Name: name, TypeName: typ, Value: val, Content: b[off : off+length]}
	}
	if len(b) < 12 {
		return []*ber.Node{raw(0, len(b), "truncated DNS message", "", "")}
	}
	id := uint16(b[0])<<8 | uint16(b[1])
	flags := uint16(b[2])<<8 | uint16(b[3])
	qd := uint16(b[4])<<8 | uint16(b[5])
	an := uint16(b[6])<<8 | uint16(b[7])
	ns := uint16(b[8])<<8 | uint16(b[9])
	ar := uint16(b[10])<<8 | uint16(b[11])

	qr := (flags >> 15) & 1
	opcode := (flags >> 11) & 0xf
	rd := (flags >> 8) & 1

	qrText := "query"
	if qr == 1 {
		qrText = "response"
	}

	hdr := &ber.Node{Raw: true, Offset: base, Length: 12, Name: "DNS header", TypeName: "RFC 1035",
		Value: fmt.Sprintf("id 0x%04x, %s, %s, RD=%d", id, qrText, opcodeText(opcode), rd)}
	hdr.Children = []*ber.Node{
		raw(0, 2, "id", "uint16", fmt.Sprintf("0x%04x", id)),
		raw(2, 2, "flags", "bits", fmt.Sprintf("QR=%d OPCODE=%s RD=%d (0x%04x)", qr, opcodeText(opcode), rd, flags)),
		raw(4, 2, "qdcount", "uint16", fmt.Sprintf("%d", qd)),
		raw(6, 2, "ancount", "uint16", fmt.Sprintf("%d", an)),
		raw(8, 2, "nscount", "uint16", fmt.Sprintf("%d", ns)),
		raw(10, 2, "arcount", "uint16", fmt.Sprintf("%d", ar)),
	}
	nodes := []*ber.Node{hdr}

	// Question section.
	pos := 12
	for i := 0; i < int(qd) && pos < len(b); i++ {
		name, nameLen, ok := readName(b, pos)
		if !ok || pos+nameLen+4 > len(b) {
			nodes = append(nodes, raw(pos, len(b)-pos, "question (unparsed)", "", ""))
			break
		}
		qtype := uint16(b[pos+nameLen])<<8 | uint16(b[pos+nameLen+1])
		qclass := uint16(b[pos+nameLen+2])<<8 | uint16(b[pos+nameLen+3])
		q := &ber.Node{Raw: true, Offset: base + pos, Length: nameLen + 4,
			Name: fmt.Sprintf("question[%d]", i), TypeName: "QNAME/QTYPE/QCLASS",
			Value: fmt.Sprintf("%s %s %s", name, TypeName(qtype), classText(qclass))}
		q.Children = []*ber.Node{
			raw(pos, nameLen, "qname", "labels", name),
			raw(pos+nameLen, 2, "qtype", "uint16", fmt.Sprintf("%s (%d)", TypeName(qtype), qtype)),
			raw(pos+nameLen+2, 2, "qclass", "uint16", fmt.Sprintf("%s (%d)", classText(qclass), qclass)),
		}
		nodes = append(nodes, q)
		pos += nameLen + 4
	}
	return nodes
}

// readName reads a (non-compressed) DNS name starting at pos, returning the
// dotted string and the number of bytes consumed.
func readName(b []byte, pos int) (string, int, bool) {
	var labels []string
	start := pos
	for {
		if pos >= len(b) {
			return "", 0, false
		}
		l := int(b[pos])
		if l == 0 {
			pos++
			break
		}
		if l&0xc0 != 0 { // compression pointer — not used in a fresh query
			return "", 0, false
		}
		pos++
		if pos+l > len(b) {
			return "", 0, false
		}
		labels = append(labels, string(b[pos:pos+l]))
		pos += l
	}
	name := strings.Join(labels, ".") + "."
	if len(labels) == 0 {
		name = "." // root
	}
	return name, pos - start, true
}
