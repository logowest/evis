package etsi

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"net"
	"strings"
	"time"

	"evis/internal/ber"
	"evis/internal/httpmsg"
	"evis/internal/ipstack"
)

// HTTPScenario describes a single plain-HTTP request being handed over: one
// TCP segment (PSH, ACK) carrying the whole request, sent on an already
// established connection.
type HTTPScenario struct {
	SrcIP   net.IP
	DstIP   net.IP // the web server
	IPIdent uint16
	TTL     uint8
	TCP     ipstack.TCP
	HTTP    httpmsg.Request
}

// DefaultHTTPScenario is a self-contained example: a GET for
// http://example.com/ from a subscriber, using RFC 5737 documentation
// addresses so nothing resembles a real target.
func DefaultHTTPScenario() HTTPScenario {
	return HTTPScenario{
		SrcIP:   net.ParseIP("198.51.100.23"),
		DstIP:   net.ParseIP("203.0.113.80"),
		IPIdent: 0x2d57,
		TTL:     64,
		TCP: ipstack.TCP{
			SrcPort: 49200, DstPort: 80,
			Seq: 1000001, Ack: 2000001, // first data bytes after the handshake
			Flags:  ipstack.TCPPsh | ipstack.TCPAck,
			Window: 64240,
		},
		HTTP: httpmsg.Request{
			Method: "GET", Target: "/",
			Headers: [][2]string{
				{"Host", "example.com"},
				{"User-Agent", "evis-demo/1.0"},
				{"Accept", "*/*"},
				{"Accept-Encoding", "gzip"},
			},
		},
	}
}

// DefaultHTTPMeta returns demo handover metadata for the HTTP request: a
// different network element and session (CIN) from the DNS sample.
func DefaultHTTPMeta() Meta {
	m := DefaultMeta()
	m.NEID = "ne-http-01"
	m.CIN = 1002
	return m
}

func (s HTTPScenario) packet() []byte {
	return ipstack.TCPSegment(s.SrcIP, s.DstIP, s.IPIdent, s.TTL, s.TCP, httpmsg.Build(s.HTTP))
}

// BuildHTTPCC produces a PS-PDU whose CC payload carries the intercepted HTTP
// request (full IPv4/TCP/HTTP datagram) as IPCC / iPPackets.
func BuildHTTPCC(m Meta, s HTTPScenario) []byte {
	return ccPDU(m, s.packet())
}

// BuildHTTPIRIOnly produces a PS-PDU whose IRI payload carries an IPIRIOnly
// record: the IPv4 + TCP header fields of the HTTP request, without content.
func BuildHTTPIRIOnly(m Meta, s HTTPScenario) []byte {
	totalLen := len(s.packet())
	t := s.TCP

	// TCPInformation ::= SEQUENCE { sourcePort [0], destinationPort [1], sequenceNumber [2],
	//   ackNumber [3], dataOffset [4] BIT STRING (SIZE(4)), controlBits [5] BIT STRING (SIZE(6)),
	//   windowSize [6], checkSum [7], urgentPointer [8], options [9] }
	tcpInfo := ber.CCons(1, // ProtocolInformation alternative tCPInformation [1] (SEQUENCE)
		ber.COctet(0, ber.Fixed(2, uint64(t.SrcPort))), // sourcePort      [0]
		ber.COctet(1, ber.Fixed(2, uint64(t.DstPort))), // destinationPort [1]
		ber.COctet(2, ber.Fixed(4, uint64(t.Seq))),     // sequenceNumber  [2]
		ber.COctet(3, ber.Fixed(4, uint64(t.Ack))),     // ackNumber       [3]
		ber.CBitString(4, 4, ipstack.TCPHeaderLen/4),   // dataOffset      [4] (32-bit words)
		ber.CBitString(5, 6, uint64(t.Flags&0x3f)),     // controlBits     [5] URG..FIN
		ber.COctet(6, ber.Fixed(2, uint64(t.Window))),  // windowSize      [6]
	)
	return iriPDU(m, ipv4Info(s.SrcIP, s.DstIP, totalLen, s.IPIdent, s.TTL, 6), tcpInfo)
}

// BuildHTTPIRIAndCC produces one handover file holding the IRI-only PS-PDU
// followed by the CC PS-PDU for the HTTP request, as BuildIRIAndCC does for DNS.
func BuildHTTPIRIAndCC(m Meta, s HTTPScenario) []byte {
	return append(BuildHTTPIRIOnly(m, s), BuildHTTPCC(m, s)...)
}

// HTTPExchange is the server's answer to an HTTPScenario's request: a
// response big enough to need several TCP segments, so the CC is spread over
// several PS-PDUs and has to be reassembled.
type HTTPExchange struct {
	Response httpmsg.Response
	MSS      int           // maximum TCP payload per segment
	RTT      time.Duration // request to first response segment
	TTL      uint8         // of the server's packets
	// Order lists the response segments (0-based) in the order they are
	// intercepted; nil means in order. A repeated index is a retransmission.
	Order []int
}

// DefaultHTTPExchange answers GET / with a gzip-compressed HTML page that
// needs several 1460-byte segments.
func DefaultHTTPExchange(m Meta) HTTPExchange {
	body := gzipBytes(demoPage())
	return HTTPExchange{
		Response: httpmsg.Response{Status: 200, Reason: "OK", Headers: [][2]string{
			{"Date", m.When.UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT")},
			{"Server", "evis-demo/1.0"},
			{"Content-Type", "text/html; charset=utf-8"},
			{"Content-Encoding", "gzip"},
			{"Content-Length", fmt.Sprint(len(body))},
		}, Body: body},
		MSS: 1460,
		RTT: 30 * time.Millisecond,
		TTL: 56,
	}
}

// ReorderedHTTPExchange is DefaultHTTPExchange intercepted out of order: the
// third segment arrives before the second, and the third is retransmitted at
// the end. Reassembly must give the same response. Needs at least 3 segments.
func ReorderedHTTPExchange(m Meta) HTTPExchange {
	x := DefaultHTTPExchange(m)
	n := x.segmentCount()
	x.Order = []int{0, 2, 1}
	for i := 3; i < n; i++ {
		x.Order = append(x.Order, i)
	}
	x.Order = append(x.Order, 2)
	return x
}

func (x HTTPExchange) segmentCount() int {
	n := len(httpmsg.BuildResponse(x.Response))
	return (n + x.MSS - 1) / x.MSS
}

// BuildHTTPExchange produces the CC for a whole exchange: the request PS-PDU
// (fromTarget) followed by one PS-PDU per response segment (toTarget), in
// x.Order. Request and response share one CC sequence number context, so the
// sequence number counts up from m.SeqNum across all of them.
func BuildHTTPExchange(m Meta, s HTTPScenario, x HTTPExchange) []byte {
	out := ccPDU(m, s.packet())

	reqLen := uint32(len(httpmsg.Build(s.HTTP)))
	resp := httpmsg.BuildResponse(x.Response)
	var segs [][]byte
	for off := 0; off < len(resp); off += x.MSS {
		segs = append(segs, resp[off:min(off+x.MSS, len(resp))])
	}
	order := x.Order
	if order == nil {
		for i := range segs {
			order = append(order, i)
		}
	}
	for k, i := range order {
		pm := m
		pm.SeqNum += uint64(k + 1)
		pm.When = m.When.Add(x.RTT + time.Duration(k)*time.Millisecond)
		t := ipstack.TCP{
			SrcPort: s.TCP.DstPort, DstPort: s.TCP.SrcPort,
			Seq:    s.TCP.Ack + uint32(i*x.MSS), // the server's data starts at the client's ack
			Ack:    s.TCP.Seq + reqLen,
			Flags:  ipstack.TCPAck,
			Window: 65535,
		}
		if i == len(segs)-1 {
			t.Flags |= ipstack.TCPPsh
		}
		pkt := ipstack.TCPSegment(s.DstIP, s.SrcIP, 0x5a00+uint16(k), x.TTL, t, segs[i])
		out = append(out, ipccPDU(pm, dirToTarget, pkt)...)
	}
	return out
}

// demoPage is an HTML page whose rows (SHA-256 hex strings) compress poorly,
// so the gzipped body still spans several segments.
func demoPage() []byte {
	var b strings.Builder
	b.WriteString("<!doctype html>\n<html><head><title>Example Domain</title></head>\n<body>\n" +
		"<h1>Example Domain</h1>\n<table>\n")
	for i := 0; i < 200; i++ {
		fmt.Fprintf(&b, "<tr><td>%d</td><td>%x</td></tr>\n", i, sha256.Sum256([]byte(fmt.Sprint("row ", i))))
	}
	b.WriteString("</table>\n</body></html>\n")
	return []byte(b.String())
}

func gzipBytes(b []byte) []byte {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	w.Write(b)
	w.Close()
	return buf.Bytes()
}
