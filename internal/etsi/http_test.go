package etsi

import (
	"testing"

	"evis/internal/ipstack"
)

// A response used to show only as "transport payload": detection matched
// request lines alone.
func TestHTTPResponseDecoded(t *testing.T) {
	s := DefaultHTTPScenario()
	resp := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 15\r\n\r\n<p>Example</p>\n"
	tcp := ipstack.TCP{SrcPort: s.TCP.DstPort, DstPort: s.TCP.SrcPort, Seq: s.TCP.Ack, Ack: s.TCP.Seq + 60,
		Flags: ipstack.TCPPsh | ipstack.TCPAck, Window: 65535}
	pkt := ipstack.TCPSegment(s.DstIP, s.SrcIP, 1, 64, tcp, []byte(resp))
	seen := names(t, ccPDU(DefaultHTTPMeta(), pkt))
	for _, want := range []string{"HTTP response", "status-line", "HTTP-version", "status-code", "reason-phrase",
		"header field", "message body"} {
		if !seen[want] {
			t.Errorf("no %q node", want)
		}
	}
	if seen["transport payload"] {
		t.Error("response left as transport payload")
	}
}
