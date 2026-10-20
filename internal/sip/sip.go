// Package sip builds and decodes SIP messages (RFC 3261) with an optional SDP
// body (RFC 8866). SIP shares HTTP's message grammar, so decoding reuses the
// httpmsg decoder with SIP names; SDP bodies are split into their lines.
package sip

import (
	"bytes"
	"fmt"
	"strings"

	"evis/internal/ber"
	"evis/internal/httpmsg"
)

// Request describes a SIP request. Build appends Content-Length itself.
type Request struct {
	Method      string      // e.g. "INVITE"
	URI         string      // Request-URI, e.g. "sip:bob@example.com"
	Headers     [][2]string // header fields in wire order, without Content-Length
	ContentType string      // e.g. "application/sdp"; empty for no body
	Body        []byte
}

// Build encodes r as a SIP/2.0 request.
func Build(r Request) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "%s %s SIP/2.0\r\n", r.Method, r.URI)
	for _, h := range r.Headers {
		fmt.Fprintf(&b, "%s: %s\r\n", h[0], h[1])
	}
	if r.ContentType != "" {
		fmt.Fprintf(&b, "Content-Type: %s\r\n", r.ContentType)
	}
	fmt.Fprintf(&b, "Content-Length: %d\r\n\r\n", len(r.Body))
	b.Write(r.Body)
	return b.Bytes()
}

// SDP joins session description lines with CRLF, as RFC 8866 §5 requires.
func SDP(lines ...string) []byte {
	return []byte(strings.Join(lines, "\r\n") + "\r\n")
}

// Dialect is SIP's message grammar, for callers that frame or decode SIP
// themselves (e.g. after TCP reassembly).
var Dialect = httpmsg.Dialect{
	VersionPrefix: "SIP/",
	TargetName:    "Request-URI",
	VersionName:   "SIP-Version",
	StartLineRef:  "RFC 3261 §7.1",
	HeaderRef:     "RFC 3261 §7.3",
	Body:          decodeBody,
}

// LooksLikeMessage reports whether b starts with a SIP request or status line.
func LooksLikeMessage(b []byte) bool {
	return Dialect.LooksLikeStart(b)
}

// Summary returns the start line, e.g. "INVITE sip:bob@example.com SIP/2.0".
func Summary(b []byte) string { return httpmsg.Summary(b) }

// DecodeNodes decodes a SIP message into labelled byte-range (Raw) nodes, with
// offsets biased by base (the absolute offset of the message in the file).
func DecodeNodes(b []byte, base int) []*ber.Node { return Dialect.DecodeNodes(b, base) }

// decodeBody decodes an application/sdp body line by line; any other body is
// left as one opaque node.
func decodeBody(b []byte, base int, headers []string) *ber.Node {
	n := &ber.Node{Raw: true, Offset: base, Length: len(b), Content: b,
		Name: "message body", TypeName: "bytes", Value: fmt.Sprintf("%d bytes", len(b))}
	if !isSDP(headers) {
		return n
	}
	n.Name, n.TypeName, n.Value = "SDP body", "RFC 8866", sdpSummary(b)
	for pos := 0; pos < len(b); {
		end := bytes.Index(b[pos:], []byte("\r\n"))
		length := end + 2
		if end < 0 {
			end, length = len(b)-pos, len(b)-pos
		}
		line := string(b[pos : pos+end])
		n.Children = append(n.Children, &ber.Node{Raw: true, Offset: base + pos, Length: length,
			Content: b[pos : pos+length], Name: "SDP line", TypeName: sdpLineType(line), Value: line})
		pos += length
	}
	return n
}

func isSDP(headers []string) bool {
	for _, h := range headers {
		name, val, _ := strings.Cut(h, ":")
		name = strings.ToLower(strings.TrimSpace(name))
		if (name == "content-type" || name == "c") && strings.HasPrefix(strings.TrimSpace(strings.ToLower(val)), "application/sdp") {
			return true
		}
	}
	return false
}

// sdpSummary picks out the media lines, e.g. "m=audio 40000 RTP/AVP 0".
func sdpSummary(b []byte) string {
	var media []string
	for _, line := range strings.Split(string(b), "\r\n") {
		if strings.HasPrefix(line, "m=") {
			media = append(media, line)
		}
	}
	if len(media) == 0 {
		return fmt.Sprintf("%d bytes", len(b))
	}
	return strings.Join(media, "; ")
}

// sdpLineType names an SDP line by its type letter (RFC 8866 §5).
func sdpLineType(line string) string {
	if len(line) < 2 || line[1] != '=' {
		return "SDP"
	}
	switch line[0] {
	case 'v':
		return "protocol version"
	case 'o':
		return "origin"
	case 's':
		return "session name"
	case 'i':
		return "information"
	case 'c':
		return "connection data"
	case 'b':
		return "bandwidth"
	case 't':
		return "timing"
	case 'm':
		return "media description"
	case 'a':
		return "attribute"
	}
	return "SDP " + line[:1] + "="
}
