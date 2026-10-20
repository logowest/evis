// Package rtp builds and decodes RTP packets on the wire (RFC 3550): the fixed
// header, CSRC list, header extension, media payload and padding. It is used
// both to synthesise intercepted media and to decode it for the visualiser.
package rtp

import (
	"fmt"

	"evis/internal/ber"
)

// HeaderLen is the length of the fixed RTP header.
const HeaderLen = 12

// Packet describes one RTP packet. Build emits no header extension or padding;
// DecodeNodes handles both.
type Packet struct {
	Marker      bool
	PayloadType uint8 // 0..127, e.g. 0 = PCMU
	Seq         uint16
	Timestamp   uint32
	SSRC        uint32
	CSRC        []uint32 // contributing sources, at most 15
	Payload     []byte
}

// Build encodes p as an RTP version 2 packet.
func Build(p Packet) []byte {
	b := make([]byte, HeaderLen, HeaderLen+4*len(p.CSRC)+len(p.Payload))
	b[0] = 2<<6 | byte(len(p.CSRC)&0x0f) // V=2, P=0, X=0, CC
	b[1] = p.PayloadType & 0x7f
	if p.Marker {
		b[1] |= 0x80
	}
	b[2], b[3] = byte(p.Seq>>8), byte(p.Seq)
	put32(b[4:8], p.Timestamp)
	put32(b[8:12], p.SSRC)
	for _, c := range p.CSRC {
		b = append(b, 0, 0, 0, 0)
		put32(b[len(b)-4:], c)
	}
	return append(b, p.Payload...)
}

// LooksLikeRTP reports whether b plausibly is an RTP packet: version 2, room
// for the CSRC list, and a second octet outside the RTCP packet-type range
// (192..223, RFC 5761 §4). RTP has no fixed port, so this is a heuristic.
func LooksLikeRTP(b []byte) bool {
	if len(b) < HeaderLen || b[0]>>6 != 2 {
		return false
	}
	if b[1] >= 192 && b[1] <= 223 {
		return false
	}
	return len(b) >= HeaderLen+4*int(b[0]&0x0f)
}

// PayloadTypeName maps the static payload types of RFC 3551 to encoding names;
// 96..127 are dynamic and bound by signalling (e.g. SDP a=rtpmap).
func PayloadTypeName(pt uint8) string {
	switch pt {
	case 0:
		return "PCMU"
	case 3:
		return "GSM"
	case 4:
		return "G723"
	case 8:
		return "PCMA"
	case 9:
		return "G722"
	case 13:
		return "CN"
	case 18:
		return "G729"
	case 26:
		return "JPEG"
	case 31:
		return "H261"
	case 34:
		return "H263"
	}
	if pt >= 96 && pt <= 127 {
		return "dynamic"
	}
	return "unassigned"
}

// Summary returns a one-line description, e.g. "PT 0 (PCMU), seq 1, SSRC 0x…".
func Summary(b []byte) string {
	if len(b) < HeaderLen {
		return fmt.Sprintf("%d bytes", len(b))
	}
	pt := b[1] & 0x7f
	return fmt.Sprintf("PT %d (%s), seq %d, SSRC 0x%08x", pt, PayloadTypeName(pt),
		int(b[2])<<8|int(b[3]), get32(b[8:12]))
}

// DecodeNodes parses an RTP packet and returns a tree of labelled byte-range
// (Raw) nodes, with offsets biased by base (the absolute offset of the packet
// within the whole file).
func DecodeNodes(b []byte, base int) []*ber.Node {
	raw := func(off, length int, name, typ, val string) *ber.Node {
		return &ber.Node{Raw: true, Offset: base + off, Length: length,
			Name: name, TypeName: typ, Value: val, Content: b[off : off+length]}
	}
	if len(b) < HeaderLen {
		return []*ber.Node{raw(0, len(b), "truncated RTP packet", "", "")}
	}
	padding := b[0]&0x20 != 0
	ext := b[0]&0x10 != 0
	cc := int(b[0] & 0x0f)
	marker := b[1]&0x80 != 0
	pt := b[1] & 0x7f
	seq := int(b[2])<<8 | int(b[3])
	ts := get32(b[4:8])
	ssrc := get32(b[8:12])

	hdrLen := HeaderLen + 4*cc
	if hdrLen > len(b) {
		hdrLen = HeaderLen
		cc = 0
	}
	hdr := &ber.Node{Raw: true, Offset: base, Length: hdrLen, Name: "RTP header", TypeName: "RFC 3550 §5.1",
		Value: fmt.Sprintf("PT %d (%s), seq %d, ts %d%s", pt, PayloadTypeName(pt), seq, ts, markText(marker))}
	hdr.Children = []*ber.Node{
		raw(0, 1, "version/P/X/CC", "bits", fmt.Sprintf("V=%d P=%d X=%d CC=%d", b[0]>>6, bit(padding), bit(ext), cc)),
		raw(1, 1, "marker/payloadType", "bits", fmt.Sprintf("M=%d PT=%d (%s)", bit(marker), pt, PayloadTypeName(pt))),
		raw(2, 2, "sequenceNumber", "uint16", fmt.Sprintf("%d", seq)),
		raw(4, 4, "timestamp", "uint32", fmt.Sprintf("%d", ts)),
		raw(8, 4, "ssrc", "uint32", fmt.Sprintf("0x%08x", ssrc)),
	}
	for i := 0; i < cc; i++ {
		off := HeaderLen + 4*i
		hdr.Children = append(hdr.Children,
			raw(off, 4, fmt.Sprintf("csrc[%d]", i), "uint32", fmt.Sprintf("0x%08x", get32(b[off:off+4]))))
	}
	nodes := []*ber.Node{hdr}

	pos, end := hdrLen, len(b)
	if padding && end > pos {
		if n := int(b[end-1]); n > 0 && n <= end-pos {
			end -= n
		}
	}
	if ext && pos+4 <= end {
		words := int(b[pos+2])<<8 | int(b[pos+3])
		extLen := 4 + 4*words
		if pos+extLen <= end {
			profile := int(b[pos])<<8 | int(b[pos+1])
			x := &ber.Node{Raw: true, Offset: base + pos, Length: extLen, Name: "header extension",
				TypeName: "RFC 3550 §5.3.1", Value: fmt.Sprintf("profile 0x%04x, %d words", profile, words)}
			x.Children = []*ber.Node{
				raw(pos, 2, "profile", "uint16", fmt.Sprintf("0x%04x%s", profile, extProfileHint(profile))),
				raw(pos+2, 2, "extensionLength", "uint16", fmt.Sprintf("%d words", words)),
			}
			if words > 0 {
				x.Children = append(x.Children, raw(pos+4, 4*words, "extension data", "bytes", ""))
			}
			nodes = append(nodes, x)
			pos += extLen
		}
	}
	if end > pos {
		nodes = append(nodes, raw(pos, end-pos, "media payload", PayloadTypeName(pt), fmt.Sprintf("%d bytes", end-pos)))
	}
	if end < len(b) {
		nodes = append(nodes, raw(end, len(b)-end, "padding", "bytes", fmt.Sprintf("%d bytes", len(b)-end)))
	}
	return nodes
}

func extProfileHint(p int) string {
	switch {
	case p == 0xbede:
		return " (one-byte header, RFC 8285)"
	case p&0xfff0 == 0x1000:
		return " (two-byte header, RFC 8285)"
	}
	return ""
}

func markText(m bool) string {
	if m {
		return ", marker"
	}
	return ""
}

func bit(v bool) int {
	if v {
		return 1
	}
	return 0
}

func get32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func put32(b []byte, v uint32) {
	b[0], b[1], b[2], b[3] = byte(v>>24), byte(v>>16), byte(v>>8), byte(v)
}
