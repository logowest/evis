package etsi

import (
	"net"
	"testing"

	"evis/internal/ber"
	"evis/internal/ipstack"
	"evis/internal/rtp"
)

// rtpCC builds an iPCC PDU carrying one RTP packet over UDP (not port 53).
func rtpCC() []byte {
	media := rtp.Build(rtp.Packet{PayloadType: 0, Seq: 1, Timestamp: 160, SSRC: 0x5eed1e55,
		Payload: make([]byte, 160)})
	pkt := ipstack.UDPDatagram(net.ParseIP("198.51.100.23"), net.ParseIP("203.0.113.40"),
		40000, 40002, 0x3e68, 64, media)
	return ccPDU(DefaultMeta(), pkt)
}

// UDP payloads used to be decoded as DNS whatever the port. RTP must come out
// as RTP, and nothing in the tree may be labelled DNS.
func TestRTPNotDecodedAsDNS(t *testing.T) {
	nodes, err := ber.Parse(rtpCC())
	if err != nil {
		t.Fatal(err)
	}
	Annotate(nodes)
	var sawRTP bool
	var walk func(n *ber.Node)
	walk = func(n *ber.Node) {
		switch n.Name {
		case "RTP packet":
			sawRTP = true
		case "DNS message", "DNS header":
			t.Errorf("RTP payload decoded as %q", n.Name)
		}
		for _, c := range n.Children {
			walk(c)
		}
	}
	for _, n := range nodes {
		walk(n)
	}
	if !sawRTP {
		t.Error("no RTP packet node in tree")
	}
}
