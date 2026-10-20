package httpmsg

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"io"
	"strconv"
	"strings"
	"testing"

	"evis/internal/ber"
)

func TestMessageLen(t *testing.T) {
	const next = "GET /next HTTP/1.1\r\n\r\n" // a pipelined message after the first
	for _, tc := range []struct {
		name     string
		msg      string
		n        int
		complete bool
	}{
		{"request, no body", "GET / HTTP/1.1\r\nHost: a\r\n\r\n", 27, true},
		{"content-length", "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc", 41, true},
		{"content-length, truncated", "HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nabc", 41, false},
		{"chunked", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n", 60, true},
		{"chunked with trailer", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX-T: 1\r\n\r\n", 60, true},
		{"chunked, truncated", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n9\r\nabc", 53, false},
		{"204 has no body", "HTTP/1.1 204 No Content\r\n\r\n", 27, true},
		{"close-delimited", "HTTP/1.1 200 OK\r\n\r\nabc", 22, false},
		{"headers incomplete", "HTTP/1.1 200 OK\r\nContent-Le", 27, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := []byte(tc.msg)
			if tc.complete {
				b = append(b, next...)
			}
			n, complete := HTTP.MessageLen(b)
			if n != tc.n || complete != tc.complete {
				t.Errorf("MessageLen = %d, %v; want %d, %v", n, complete, tc.n, tc.complete)
			}
		})
	}
}

// bodyNode decodes msg and returns its body node.
func bodyNode(t *testing.T, msg []byte) *ber.Node {
	t.Helper()
	nodes := DecodeNodes(msg, 0)
	last := nodes[len(nodes)-1]
	if last.Name != "message body" {
		t.Fatalf("last node is %q, not the body", last.Name)
	}
	return last
}

func child(n *ber.Node, name string) *ber.Node {
	for _, c := range n.Children {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func gz(s string) []byte {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Write([]byte(s))
	w.Close()
	return b.Bytes()
}

func TestGzipBody(t *testing.T) {
	text := strings.Repeat("<p>hello world</p>\n", 50)
	body := gz(text)
	msg := BuildResponse(Response{Status: 200, Reason: "OK", Headers: [][2]string{
		{"Content-Type", "text/html; charset=utf-8"}, {"Content-Encoding", "gzip"},
		{"Content-Length", strconv.Itoa(len(body))}}, Body: body})
	d := child(bodyNode(t, msg), "decoded content")
	if d == nil {
		t.Fatal("no decoded content node")
	}
	if d.TypeName != "gzip → text/html" || !strings.Contains(d.Value, strconv.Itoa(len(text))+" bytes: <p>hello world</p>") {
		t.Errorf("decoded content = %q %q", d.TypeName, d.Value)
	}

	// A body cut short (as in the first segment of a long response) still
	// decodes as far as it goes and says why it stopped.
	cut := msg[:len(msg)-len(body)/2]
	d = child(bodyNode(t, cut), "decoded content")
	if d == nil || !strings.Contains(d.Value, "decoded before the data ended") {
		t.Errorf("truncated gzip: %+v", d)
	}
}

func TestDeflateBody(t *testing.T) {
	for name, compress := range map[string]func(w io.Writer) io.WriteCloser{
		"zlib": func(w io.Writer) io.WriteCloser { return zlib.NewWriter(w) },
		"raw": func(w io.Writer) io.WriteCloser {
			fw, _ := flate.NewWriter(w, flate.DefaultCompression)
			return fw
		},
	} {
		var b bytes.Buffer
		w := compress(&b)
		w.Write([]byte(`{"ok":true}`))
		w.Close()
		msg := BuildResponse(Response{Status: 200, Reason: "OK", Headers: [][2]string{
			{"Content-Type", "application/json"}, {"Content-Encoding", "deflate"},
			{"Content-Length", strconv.Itoa(b.Len())}}, Body: b.Bytes()})
		if d := child(bodyNode(t, msg), "decoded content"); d == nil || d.Value != `11 bytes: {"ok":true}` {
			t.Errorf("%s deflate: %+v", name, d)
		}
	}
}

func TestChunkedBody(t *testing.T) {
	msg := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n" +
		"5\r\nhello\r\n7;ext=1\r\n, world\r\n0\r\n\r\n")
	body := bodyNode(t, msg)
	if !strings.HasSuffix(body.Value, ": hello, world") || body.TypeName != "chunked text/plain" {
		t.Errorf("body = %q %q", body.TypeName, body.Value)
	}
	var names []string
	for _, c := range body.Children {
		names = append(names, c.Name)
	}
	if strings.Join(names, ",") != "chunk,chunk,last-chunk" {
		t.Errorf("children = %v", names)
	}
	data := body.Children[1].Children[1]
	if string(msg[data.Offset:data.Offset+data.Length]) != ", world" {
		t.Errorf("chunk-data covers %q", msg[data.Offset:data.Offset+data.Length])
	}
}
