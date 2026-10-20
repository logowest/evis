package etsi

import (
	"bytes"
	"strconv"
	"strings"
	"testing"

	"evis/internal/ber"
	"evis/internal/ipstack"
)

// annotate parses and annotates b, failing on parse errors.
func annotate(t *testing.T, b []byte) []*ber.Node {
	t.Helper()
	nodes, err := ber.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	Annotate(nodes)
	return nodes
}

// find returns every node called name, in tree order.
func find(nodes []*ber.Node, name string) []*ber.Node {
	var out []*ber.Node
	var walk func(n *ber.Node)
	walk = func(n *ber.Node) {
		if n.Name == name {
			out = append(out, n)
		}
		for _, c := range n.Children {
			walk(c)
		}
	}
	for _, n := range nodes {
		walk(n)
	}
	return out
}

// checkHighlights verifies that every reassembled field highlights file bytes
// equal to the start of its own content, i.e. the stream→file mapping is right.
func checkHighlights(t *testing.T, file []byte, n *ber.Node) {
	t.Helper()
	if n.Raw && n.Content != nil && n.Length > 0 {
		got := file[n.Offset : n.Offset+n.Length]
		if !bytes.Equal(got, n.Content[:n.Length]) {
			t.Errorf("%q @%d+%d highlights %q, want %q", n.Name, n.Offset, n.Length, got, n.Content[:n.Length])
		}
	}
	for _, c := range n.Children {
		checkHighlights(t, file, c)
	}
}

func exchange(t *testing.T, x HTTPExchange) ([]byte, []*ber.Node) {
	b := BuildHTTPExchange(DefaultHTTPMeta(), DefaultHTTPScenario(), x)
	return b, annotate(t, b)
}

func TestHTTPExchangeReassembled(t *testing.T) {
	m := DefaultHTTPMeta()
	page := string(demoPage())
	var decoded []string
	for name, x := range map[string]HTTPExchange{"in order": DefaultHTTPExchange(m), "reordered": ReorderedHTTPExchange(m)} {
		t.Run(name, func(t *testing.T) {
			file, nodes := exchange(t, x)
			roots := find(nodes, "reassembled HTTP response")
			if len(roots) != 1 {
				t.Fatalf("%d reassembled responses, want 1", len(roots))
			}
			root := roots[0]
			if !strings.HasPrefix(root.Value, "HTTP/1.1 200 OK — ") || strings.Contains(root.Value, "missing") {
				t.Errorf("root = %q", root.Value)
			}
			checkHighlights(t, file, root)

			var content *ber.Node
			for _, d := range find([]*ber.Node{root}, "decoded content") {
				content = d
			}
			if content == nil {
				t.Fatal("no decoded content")
			}
			if want := strconv.Itoa(len(page)) + " bytes: <!doctype html>"; !strings.HasPrefix(content.Value, want) {
				t.Errorf("decoded content = %.80q, want prefix %q", content.Value, want)
			}
			decoded = append(decoded, content.Value)
		})
	}
	if len(decoded) == 2 && decoded[0] != decoded[1] {
		t.Error("reordered exchange decodes differently from the in-order one")
	}

	_, nodes := exchange(t, ReorderedHTTPExchange(m))
	var retrans int
	for _, p := range find(nodes, "transport payload") {
		if strings.Contains(p.Value, "retransmission") {
			retrans++
		}
	}
	if retrans != 1 {
		t.Errorf("%d segments marked as retransmissions, want 1", retrans)
	}
}

// A lost segment: the response is reported as cut off, nothing after the gap
// is decoded as HTTP, and the segment after the gap says what is missing.
func TestHTTPExchangeGap(t *testing.T) {
	x := DefaultHTTPExchange(DefaultHTTPMeta())
	x.Order = []int{0, 1, 3, 4}
	_, nodes := exchange(t, x)
	roots := find(nodes, "reassembled HTTP response")
	if len(roots) != 1 || !strings.Contains(roots[0].Value, "cut off by 1460 missing bytes") {
		t.Fatalf("reassembled responses = %v", roots)
	}
	if len(find(roots, "missing data")) != 1 {
		t.Error("no missing data node")
	}
	var after int
	for _, p := range find(nodes, "transport payload") {
		if strings.Contains(p.Value, "follows 1460 missing bytes") {
			after++
		}
	}
	if after != 1 {
		t.Errorf("%d segments marked as following the gap, want 1", after)
	}
}

// Two pipelined requests in one segment are split and each decoded.
func TestPipelinedRequests(t *testing.T) {
	s := DefaultHTTPScenario()
	two := "GET /a HTTP/1.1\r\nHost: example.com\r\n\r\nGET /b HTTP/1.1\r\nHost: example.com\r\n\r\n"
	pkt := ipstack.TCPSegment(s.SrcIP, s.DstIP, 1, 64, s.TCP, []byte(two))
	file := ccPDU(DefaultHTTPMeta(), pkt)
	nodes := annotate(t, file)
	roots := find(nodes, "reassembled HTTP request")
	if len(roots) != 2 || !strings.HasPrefix(roots[0].Value, "GET /a") || !strings.HasPrefix(roots[1].Value, "GET /b") {
		t.Fatalf("got %d reassembled requests: %v", len(roots), roots)
	}
	for _, r := range roots {
		checkHighlights(t, file, r)
	}
}
