package ber

import (
	"errors"
	"fmt"
)

// Node is one element of a decoded BER tree. Offsets are absolute within the
// original buffer so a UI can map any node back onto its raw bytes.
//
// A Node is usually a real TLV. When Raw is true it is instead a labelled byte
// range produced by a higher-level decoder (e.g. the IPv4/UDP/DNS fields found
// inside an iPPackets OCTET STRING): HeaderLen is 0 and Offset/Length delimit
// the field directly.
type Node struct {
	Offset      int    // absolute offset of the identifier octet (or field start, if Raw)
	HeaderLen   int    // length of tag+length octets (0 for Raw nodes)
	Length      int    // content length in bytes
	Class       Class  // tag class (Raw: Universal, unused)
	Constructed bool   // constructed bit
	TagNum      int    // tag number
	Content     []byte // raw content bytes (primitive / Raw nodes)
	Children    []*Node
	Raw         bool // true => labelled byte range, not an ASN.1 TLV

	// Annotations, filled in by the etsi package.
	Name     string // field name, e.g. "sequenceNumber"
	TypeName string // ASN.1 type, e.g. "INTEGER", "OCTET STRING"
	Value    string // human-readable decoded value
	Note     string // extra context
}

// ContentOffset is the absolute offset of the first content byte.
func (n *Node) ContentOffset() int {
	if n.Raw {
		return n.Offset
	}
	return n.Offset + n.HeaderLen
}

// End is the absolute offset one past the node's last byte.
func (n *Node) End() int {
	if n.Raw {
		return n.Offset + n.Length
	}
	return n.Offset + n.HeaderLen + n.Length
}

// TotalLen is the full on-wire size including header.
func (n *Node) TotalLen() int { return n.End() - n.Offset }

// TagString renders the identifier for display, e.g. "[3]" or "SEQUENCE".
func (n *Node) TagString() string {
	if n.Raw {
		return ""
	}
	if n.Class == Universal {
		if name, ok := universalNames[n.TagNum]; ok {
			return name
		}
		return fmt.Sprintf("UNIVERSAL %d", n.TagNum)
	}
	cls := map[Class]string{Application: "APPLICATION ", Context: "", Private: "PRIVATE "}[n.Class]
	return fmt.Sprintf("[%s%d]", cls, n.TagNum)
}

var universalNames = map[int]string{
	TagBoolean: "BOOLEAN", TagInteger: "INTEGER", TagBitString: "BIT STRING",
	TagOctetString: "OCTET STRING", TagNull: "NULL", TagOID: "OBJECT IDENTIFIER",
	TagEnumerated: "ENUMERATED", TagUTF8String: "UTF8String", TagRelativeOID: "RELATIVE-OID",
	TagSequence: "SEQUENCE", TagSet: "SET", TagPrintableString: "PrintableString",
	TagIA5String: "IA5String", TagUTCTime: "UTCTime", TagGeneralizedTime: "GeneralizedTime",
}

// Parse decodes every top-level TLV in b (an ETSI stream may concatenate several
// PS-PDUs). Offsets are relative to the start of b.
func Parse(b []byte) ([]*Node, error) {
	var out []*Node
	pos := 0
	for pos < len(b) {
		n, next, err := parseOne(b, pos)
		if err != nil {
			return out, err
		}
		out = append(out, n)
		pos = next
	}
	return out, nil
}

func parseOne(b []byte, start int) (*Node, int, error) {
	pos := start
	if pos >= len(b) {
		return nil, pos, errors.New("unexpected end of data reading tag")
	}
	first := b[pos]
	class := Class(first >> 6)
	constructed := first&0x20 != 0
	tagNum := int(first & 0x1f)
	pos++
	if tagNum == 0x1f { // high tag number form
		tagNum = 0
		for {
			if pos >= len(b) {
				return nil, pos, errors.New("truncated high-tag-number")
			}
			c := b[pos]
			pos++
			tagNum = tagNum<<7 | int(c&0x7f)
			if c&0x80 == 0 {
				break
			}
		}
	}

	if pos >= len(b) {
		return nil, pos, errors.New("unexpected end of data reading length")
	}
	lenByte := b[pos]
	pos++
	var length int
	if lenByte&0x80 == 0 {
		length = int(lenByte)
	} else {
		nBytes := int(lenByte & 0x7f)
		if nBytes == 0 {
			return nil, pos, errors.New("indefinite length not supported (ETSI uses definite length)")
		}
		if pos+nBytes > len(b) {
			return nil, pos, errors.New("truncated long-form length")
		}
		for i := 0; i < nBytes; i++ {
			length = length<<8 | int(b[pos])
			pos++
		}
	}

	headerLen := pos - start
	contentStart := pos
	contentEnd := contentStart + length
	if contentEnd > len(b) {
		return nil, pos, fmt.Errorf("content length %d at offset %d overruns buffer (have %d)", length, start, len(b)-contentStart)
	}
	content := b[contentStart:contentEnd]

	n := &Node{
		Offset: start, HeaderLen: headerLen, Length: length,
		Class: class, Constructed: constructed, TagNum: tagNum, Content: content,
	}
	if constructed {
		cpos := contentStart
		for cpos < contentEnd {
			child, next, err := parseOne(b, cpos)
			if err != nil {
				return n, contentEnd, err // return what we have, surface the error
			}
			n.Children = append(n.Children, child)
			cpos = next
		}
	}
	return n, contentEnd, nil
}

// DecodeInt reads a (possibly multi-byte) unsigned integer from content.
func DecodeInt(b []byte) uint64 {
	var v uint64
	for _, c := range b {
		v = v<<8 | uint64(c)
	}
	return v
}

// DecodeOID renders OID content as a dotted string.
func DecodeOID(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	first := uint64(b[0])
	arcs := []uint64{first / 40, first % 40}
	var cur uint64
	for _, c := range b[1:] {
		cur = cur<<7 | uint64(c&0x7f)
		if c&0x80 == 0 {
			arcs = append(arcs, cur)
			cur = 0
		}
	}
	return joinArcs(arcs)
}

// DecodeRelOID renders RELATIVE-OID content as a dotted string.
func DecodeRelOID(b []byte) string {
	var arcs []uint64
	var cur uint64
	for _, c := range b {
		cur = cur<<7 | uint64(c&0x7f)
		if c&0x80 == 0 {
			arcs = append(arcs, cur)
			cur = 0
		}
	}
	return joinArcs(arcs)
}

func joinArcs(arcs []uint64) string {
	s := ""
	for i, a := range arcs {
		if i > 0 {
			s += "."
		}
		s += fmt.Sprintf("%d", a)
	}
	return s
}
