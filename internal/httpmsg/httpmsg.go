// Package httpmsg builds HTTP/1.1 messages on the wire (RFC 9112) and decodes
// requests and responses for the visualiser: start line, header fields, and
// the body, including chunked framing and gzip/deflate content coding. It also
// finds where each message ends, for splitting a reassembled TCP stream.
//
// SIP (RFC 3261 §7) shares HTTP's message grammar, so the decoder is
// parameterised by a Dialect and package sip reuses it.
package httpmsg

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"

	"evis/internal/ber"
)

// Request describes a single body-less HTTP/1.1 request.
type Request struct {
	Method  string      // e.g. "GET"
	Target  string      // request-target, e.g. "/index.html"
	Headers [][2]string // header fields in wire order, e.g. {"Host", "example.com"}
}

// Build encodes r as an HTTP/1.1 request message.
func Build(r Request) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", r.Method, r.Target)
	for _, h := range r.Headers {
		fmt.Fprintf(&b, "%s: %s\r\n", h[0], h[1])
	}
	b.WriteString("\r\n")
	return b.Bytes()
}

// Response describes an HTTP/1.1 response. Headers are written as given, so
// include Content-Length (or Transfer-Encoding) yourself.
type Response struct {
	Status  int    // e.g. 200
	Reason  string // e.g. "OK"
	Headers [][2]string
	Body    []byte
}

// BuildResponse encodes r as an HTTP/1.1 response message.
func BuildResponse(r Response) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\n", r.Status, r.Reason)
	for _, h := range r.Headers {
		fmt.Fprintf(&b, "%s: %s\r\n", h[0], h[1])
	}
	b.WriteString("\r\n")
	b.Write(r.Body)
	return b.Bytes()
}

// Dialect names the parts of a start-line + header + body text message.
type Dialect struct {
	VersionPrefix string // "HTTP/" or "SIP/"
	TargetName    string // name of the request-line's middle token
	VersionName   string // name of the protocol-version token
	StartLineRef  string // TypeName for request-line / status-line
	HeaderRef     string // TypeName for header fields
	// Body, if set, decodes the message body; it gets the header fields so it
	// can look at Content-Type. Otherwise the body is one opaque node.
	Body func(body []byte, base int, headers []string) *ber.Node
}

// HTTP is the HTTP/1.1 dialect.
var HTTP = Dialect{
	VersionPrefix: "HTTP/",
	TargetName:    "request-target",
	VersionName:   "HTTP-version",
	StartLineRef:  "RFC 9112 §3",
	HeaderRef:     "RFC 9110 §5",
	Body:          decodeBody,
}

// LooksLikeRequest reports whether b starts with an HTTP request line.
func LooksLikeRequest(b []byte) bool { return HTTP.LooksLikeRequest(b) }

// LooksLikeResponse reports whether b starts with an HTTP status line.
func LooksLikeResponse(b []byte) bool { return HTTP.LooksLikeResponse(b) }

// LooksLikeRequest reports whether b starts with a request line in dialect d.
func (d Dialect) LooksLikeRequest(b []byte) bool {
	parts := startLine(b)
	return len(parts) == 3 && strings.HasPrefix(parts[2], d.VersionPrefix)
}

// LooksLikeResponse reports whether b starts with a status line in dialect d.
func (d Dialect) LooksLikeResponse(b []byte) bool {
	parts := startLine(b)
	return len(parts) == 3 && strings.HasPrefix(parts[0], d.VersionPrefix)
}

func startLine(b []byte) []string {
	line, _, ok := bytes.Cut(b, []byte("\r\n"))
	if !ok {
		return nil
	}
	return strings.SplitN(string(line), " ", 3)
}

// Summary returns the start line, e.g. "GET / HTTP/1.1" or "HTTP/1.1 200 OK".
func Summary(b []byte) string {
	line, _, _ := bytes.Cut(b, []byte("\r\n"))
	return string(line)
}

// DecodeNodes decodes an HTTP message into labelled byte-range (Raw) nodes,
// with offsets biased by base (the absolute offset of the message in the file).
func DecodeNodes(b []byte, base int) []*ber.Node { return HTTP.DecodeNodes(b, base) }

// DecodeNodes decodes a message in dialect d. Each line's node covers its
// trailing CRLF.
func (d Dialect) DecodeNodes(b []byte, base int) []*ber.Node {
	raw := func(off, length int, name, typ, val string) *ber.Node {
		return &ber.Node{Raw: true, Offset: base + off, Length: length,
			Name: name, TypeName: typ, Value: val, Content: b[off : off+length]}
	}
	body := func(pos int, headers []string) *ber.Node {
		if d.Body != nil {
			return d.Body(b[pos:], base+pos, headers)
		}
		return raw(pos, len(b)-pos, "message body", "bytes", fmt.Sprintf("%d bytes", len(b)-pos))
	}
	var nodes []*ber.Node
	var headers []string
	pos := 0
	for i := 0; pos < len(b); i++ {
		end := bytes.Index(b[pos:], []byte("\r\n"))
		if end < 0 {
			nodes = append(nodes, body(pos, headers))
			break
		}
		line := string(b[pos : pos+end])
		n := raw(pos, end+2, "", "", line)
		switch {
		case i == 0:
			n.Children = d.startLineNodes(line, raw, pos)
			n.Name, n.TypeName = "request-line", d.StartLineRef
			if d.LooksLikeResponse(b) {
				n.Name = "status-line"
			}
		case line == "":
			n.Name, n.TypeName, n.Value = "end of headers", "CRLF", "empty line"
		default:
			n.Name, n.TypeName = "header field", d.HeaderRef
			headers = append(headers, line)
		}
		nodes = append(nodes, n)
		pos += end + 2
		if line == "" && i > 0 {
			if pos < len(b) {
				nodes = append(nodes, body(pos, headers))
			}
			break
		}
	}
	return nodes
}

// startLineNodes splits a request-line (method SP target SP version) or a
// status-line (version SP status-code SP reason-phrase) into its parts.
func (d Dialect) startLineNodes(line string, raw func(off, length int, name, typ, val string) *ber.Node, pos int) []*ber.Node {
	parts := strings.SplitN(line, " ", 3)
	if len(parts) != 3 {
		return nil
	}
	names := [3]string{"method", d.TargetName, d.VersionName}
	types := [3]string{"token", "string", "string"}
	if strings.HasPrefix(parts[0], d.VersionPrefix) {
		names = [3]string{d.VersionName, "status-code", "reason-phrase"}
		types = [3]string{"string", "3DIGIT", "string"}
	}
	var nodes []*ber.Node
	off := pos
	for i, p := range parts {
		nodes = append(nodes, raw(off, len(p), names[i], types[i], p))
		off += len(p) + 1
	}
	return nodes
}

// LooksLikeStart reports whether b starts with a request or status line.
func (d Dialect) LooksLikeStart(b []byte) bool {
	return d.LooksLikeRequest(b) || d.LooksLikeResponse(b)
}

// MessageLen returns the length of the message at the start of b, using the
// framing rules of RFC 9112 §6.3: Transfer-Encoding chunked, else
// Content-Length (or SIP's compact "l"), else no body for requests, SIP and
// 1xx/204/304 responses. complete is false when b ends before the message
// does, or for a response delimited only by closing the connection; n is then
// len(b).
func (d Dialect) MessageLen(b []byte) (n int, complete bool) {
	hdrEnd := bytes.Index(b, []byte("\r\n\r\n"))
	if hdrEnd < 0 {
		return len(b), false
	}
	head := hdrEnd + 4
	_, rest, _ := bytes.Cut(b[:hdrEnd+2], []byte("\r\n"))
	headers := strings.Split(strings.TrimSuffix(string(rest), "\r\n"), "\r\n")
	if isChunked(headers) {
		n, ok := chunkedLen(b[head:])
		return head + n, ok
	}
	if cl, ok := contentLength(headers); ok {
		if head+cl > len(b) {
			return len(b), false
		}
		return head + cl, true
	}
	if d.LooksLikeRequest(b) || d.VersionPrefix != HTTP.VersionPrefix {
		return head, true
	}
	if code := statusCode(b); code/100 == 1 || code == 204 || code == 304 {
		return head, true
	}
	return len(b), false
}

// header returns the value of the first header field called name (case
// insensitive), trimmed.
func header(headers []string, names ...string) (string, bool) {
	for _, h := range headers {
		k, v, ok := strings.Cut(h, ":")
		if !ok {
			continue
		}
		for _, name := range names {
			if strings.EqualFold(strings.TrimSpace(k), name) {
				return strings.TrimSpace(v), true
			}
		}
	}
	return "", false
}

func isChunked(headers []string) bool {
	te, _ := header(headers, "Transfer-Encoding")
	return strings.Contains(strings.ToLower(te), "chunked")
}

func contentLength(headers []string) (int, bool) {
	v, ok := header(headers, "Content-Length", "l")
	if !ok {
		return 0, false
	}
	var n int
	if _, err := fmt.Sscanf(v, "%d", &n); err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

func statusCode(b []byte) int {
	parts := startLine(b)
	if len(parts) < 2 {
		return 0
	}
	var code int
	fmt.Sscanf(parts[1], "%d", &code)
	return code
}

// chunk is one chunk of a chunked body: offsets relative to the body start.
type chunk struct {
	start, sizeLen, dataLen, end int // sizeLen includes its CRLF; end is past the data's CRLF
}

// parseChunks walks a chunked body. It returns the chunks (the last one has
// dataLen 0), the length of the whole body including trailers, and whether the
// body is complete.
func parseChunks(b []byte) (chunks []chunk, n int, complete bool) {
	pos := 0
	for {
		eol := bytes.Index(b[pos:], []byte("\r\n"))
		if eol < 0 {
			return chunks, len(b), false
		}
		sizeText, _, _ := strings.Cut(string(b[pos:pos+eol]), ";") // drop chunk extensions
		var size int
		if _, err := fmt.Sscanf(strings.TrimSpace(sizeText), "%x", &size); err != nil || size < 0 {
			return chunks, len(b), false
		}
		c := chunk{start: pos, sizeLen: eol + 2, dataLen: size}
		dataEnd := pos + eol + 2 + size
		if size == 0 {
			// Trailer fields, then an empty line.
			end := bytes.Index(b[pos+eol:], []byte("\r\n\r\n"))
			if end < 0 {
				return chunks, len(b), false
			}
			c.end = pos + eol + end + 4
			return append(chunks, c), c.end, true
		}
		if dataEnd+2 > len(b) {
			c.end = len(b)
			return append(chunks, c), len(b), false
		}
		c.end = dataEnd + 2
		chunks = append(chunks, c)
		pos = c.end
	}
}

func chunkedLen(b []byte) (int, bool) {
	_, n, ok := parseChunks(b)
	return n, ok
}

// decodeBody decodes an HTTP body: chunked framing (one node per chunk) and
// gzip/deflate content coding (a "decoded content" node with a preview of the
// decompressed data). Uncompressed text bodies get a preview in the value.
func decodeBody(b []byte, base int, headers []string) *ber.Node {
	raw := func(off, length int, name, typ, val string) *ber.Node {
		return &ber.Node{Raw: true, Offset: base + off, Length: length,
			Name: name, TypeName: typ, Value: val, Content: b[off : off+length]}
	}
	ctype, _ := header(headers, "Content-Type")
	ctype, _, _ = strings.Cut(ctype, ";")
	n := raw(0, len(b), "message body", "bytes", fmt.Sprintf("%d bytes", len(b)))
	if ctype != "" {
		n.TypeName = ctype
	}

	payload := b
	if isChunked(headers) {
		n.TypeName = "chunked " + n.TypeName
		chunks, _, complete := parseChunks(b)
		payload = nil
		for _, c := range chunks {
			data := c.start + c.sizeLen
			have := min(c.dataLen, len(b)-data)
			if c.dataLen == 0 {
				n.Children = append(n.Children, raw(c.start, c.end-c.start, "last-chunk", "chunk", "size 0, end of body"))
				continue
			}
			cn := raw(c.start, c.end-c.start, "chunk", "chunk", fmt.Sprintf("%d bytes", c.dataLen))
			cn.Children = []*ber.Node{
				raw(c.start, c.sizeLen, "chunk-size", "hex", strings.TrimSpace(string(b[c.start:c.start+c.sizeLen]))),
				raw(data, have, "chunk-data", "bytes", fmt.Sprintf("%d bytes", have)),
			}
			n.Children = append(n.Children, cn)
			payload = append(payload, b[data:data+have]...)
		}
		n.Value = fmt.Sprintf("%d bytes in %d chunks, %d bytes of data", len(b), len(chunks), len(payload))
		if !complete {
			n.Value += " (incomplete)"
		}
	}

	enc, _ := header(headers, "Content-Encoding")
	enc = strings.ToLower(enc)
	switch {
	case enc == "" || enc == "identity":
		if isText(ctype) && len(payload) > 0 {
			n.Value += ": " + preview(payload)
		}
	case enc == "gzip" || enc == "x-gzip" || enc == "deflate":
		out, err := decompress(enc, payload)
		d := raw(0, len(b), "decoded content", enc+" → "+orBytes(ctype), "")
		d.Value = fmt.Sprintf("%d bytes", len(out))
		if err != nil {
			d.Value = fmt.Sprintf("%d bytes decoded before the data ended (%v)", len(out), err)
		}
		if len(out) > 0 {
			d.Value += ": " + preview(out)
		}
		n.Children = append(n.Children, d)
	default:
		n.Children = append(n.Children, raw(0, len(b), "decoded content", enc, "content coding not supported"))
	}
	return n
}

// decompress undoes gzip or deflate content coding. HTTP "deflate" is the
// zlib format (RFC 9110 §8.4.1.2), but some servers send raw DEFLATE, so that
// is tried too. On a truncated body it returns what it decoded and the error.
func decompress(enc string, b []byte) ([]byte, error) {
	var r io.Reader
	var err error
	switch enc {
	case "gzip", "x-gzip":
		r, err = gzip.NewReader(bytes.NewReader(b))
	default:
		r, err = zlib.NewReader(bytes.NewReader(b))
		if err != nil {
			r, err = flate.NewReader(bytes.NewReader(b)), nil
		}
	}
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

func isText(ctype string) bool {
	ctype = strings.ToLower(strings.TrimSpace(ctype))
	return strings.HasPrefix(ctype, "text/") || strings.HasSuffix(ctype, "json") ||
		strings.HasSuffix(ctype, "xml") || strings.HasSuffix(ctype, "javascript") ||
		ctype == "application/x-www-form-urlencoded"
}

func orBytes(ctype string) string {
	if ctype == "" {
		return "bytes"
	}
	return ctype
}

// preview renders the start of b on one line: text with whitespace collapsed,
// or hex if b does not look like text.
func preview(b []byte) string {
	const limit = 160
	head := b[:min(len(b), limit*4)]
	for !utf8.Valid(head) && len(head) > 0 && len(b) > len(head) { // cut mid-rune
		head = head[:len(head)-1]
	}
	if !utf8.Valid(head) || bytes.ContainsFunc(head, func(r rune) bool {
		return unicode.IsControl(r) && r != '\r' && r != '\n' && r != '\t'
	}) {
		var parts []string
		for i, c := range b {
			if i == 24 {
				parts = append(parts, "…")
				break
			}
			parts = append(parts, fmt.Sprintf("%02x", c))
		}
		return strings.Join(parts, " ")
	}
	text := []rune(strings.Join(strings.Fields(string(head)), " "))
	if len(text) > limit || len(head) < len(b) {
		return string(text[:min(len(text), limit)]) + "…"
	}
	return string(text)
}
