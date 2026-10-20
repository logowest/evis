package etsi

import (
	"testing"

	"evis/internal/ber"
	"evis/internal/ipstack"
	"evis/internal/rtp"
	"evis/internal/sip"
)

// names returns every node name in the annotated tree of b.
func names(t *testing.T, b []byte) map[string]bool {
	t.Helper()
	nodes, err := ber.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	Annotate(nodes)
	seen := map[string]bool{}
	var walk func(n *ber.Node)
	walk = func(n *ber.Node) {
		seen[n.Name] = true
		if n.Note == "" {
			t.Errorf("%q (%s at @%d) has no description", n.Name, n.TypeName, n.Offset)
		}
		for _, c := range n.Children {
			walk(c)
		}
	}
	for _, n := range nodes {
		walk(n)
	}
	return seen
}

// SIP delivered as originalIPMMMessage: the whole IPv4/UDP/SIP packet.
func TestIPMMIRIOriginalMessage(t *testing.T) {
	s := DefaultVoIPScenario()
	pkt := ipstack.UDPDatagram(s.TargetIP, s.ProxyIP, s.SIPPort, s.SIPPort, 1, 64, sip.Build(s.SIP))
	b := iriPayloadPDU(DefaultVoIPMeta(), iriBegin, ber.CCons(11,
		ber.CRelOID(0, ipMMIRIObjID...),
		ber.CExplicit(1, ber.COctet(0, pkt)), // originalIPMMMessage [0]
	))
	seen := names(t, b)
	for _, want := range []string{"originalIPMMMessage", "UDP header", "SIP message", "SDP body"} {
		if !seen[want] {
			t.Errorf("no %q node", want)
		}
	}
}

// Media delivered as rtpFrame: RTP without IP and UDP headers.
func TestIPMMCCRTPFrame(t *testing.T) {
	media := rtp.Build(rtp.Packet{PayloadType: 8, Seq: 9, SSRC: 1, Payload: make([]byte, 160)})
	b := ccPayloadPDU(DefaultVoIPMeta(), dirToTarget, ber.CCons(12,
		ber.CRelOID(0, ipMMCCObjID...),
		ber.COctet(1, media),
		ber.CEnum(2, 2), // frameType rtpFrame(2)
	))
	seen := names(t, b)
	if !seen["RTP packet"] || seen["IPv4 header"] {
		t.Errorf("rtpFrame not decoded as bare RTP: %v", seen)
	}
}
