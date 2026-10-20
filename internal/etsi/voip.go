package etsi

import (
	"fmt"
	"net"
	"time"

	"evis/internal/ber"
	"evis/internal/ipstack"
	"evis/internal/rtp"
	"evis/internal/sip"
)

// RELATIVE-OIDs from TS 102 232-5 IPMultimediaPDU, relative to
// {...lawfulIntercept(2)}. Version 17 is the one LI-PS-PDU v43 imports.
var (
	ipMMIRIObjID = []uint64{5, 5, 17, 1} // li-ps iPMultimedia v17 iRI
	ipMMCCObjID  = []uint64{5, 5, 17, 2} // li-ps iPMultimedia v17 cC
)

// FrameType and MMCCprotocol values (TS 102 232-5).
const (
	frameIP     = 0 // ipFrame: all headers present
	mmccRTP     = 0 // rTP: mMCCContents holds RTP/RTCP packets
	ipTypeV4    = 0 // IPAddress iP-type iPV4(0)
	ipAssignDyn = 2 // IPAddress iP-assignment dynamic(2)
)

// VoIPScenario describes the start of a SIP call made by the target: the
// INVITE sent to a SIP proxy (handed over as IRI) and the first few outgoing
// RTP packets of the media stream it set up (handed over as CC).
type VoIPScenario struct {
	TargetIP net.IP // the target's phone; source of SIP and RTP
	ProxyIP  net.IP // SIP proxy the INVITE is sent to
	MediaIP  net.IP // far end of the media stream
	SIPPort  uint16
	SIP      sip.Request

	RTPSrcPort, RTPDstPort uint16
	PayloadType            uint8 // 0 = PCMU
	SSRC                   uint32
	FirstSeq               uint16
	FirstTimestamp         uint32
	Packets                int           // number of RTP packets
	Interval               time.Duration // packetisation time, e.g. 20 ms
	MediaStart             time.Duration // first RTP packet, after the INVITE
	IPIdent                uint16
	TTL                    uint8
}

// DefaultVoIPScenario is a self-contained example: alice@example.com calls
// bob@example.com with G.711 µ-law audio, using RFC 5737 documentation
// addresses so nothing resembles a real target.
func DefaultVoIPScenario() VoIPScenario {
	target := "198.51.100.23"
	return VoIPScenario{
		TargetIP: net.ParseIP(target),
		ProxyIP:  net.ParseIP("203.0.113.5"),
		MediaIP:  net.ParseIP("203.0.113.40"),
		SIPPort:  5060,
		SIP: sip.Request{
			Method: "INVITE", URI: "sip:bob@example.com",
			Headers: [][2]string{
				{"Via", "SIP/2.0/UDP " + target + ":5060;branch=z9hG4bK776asdhds"},
				{"Max-Forwards", "70"},
				{"From", "\"Alice\" <sip:alice@example.com>;tag=1928301774"},
				{"To", "<sip:bob@example.com>"},
				{"Call-ID", "a84b4c76e66710@" + target},
				{"CSeq", "1 INVITE"},
				{"Contact", "<sip:alice@" + target + ":5060>"},
			},
			ContentType: "application/sdp",
			Body: sip.SDP(
				"v=0",
				"o=alice 2890844526 2890844526 IN IP4 "+target,
				"s=-",
				"c=IN IP4 "+target,
				"t=0 0",
				"m=audio 40000 RTP/AVP 0",
				"a=rtpmap:0 PCMU/8000",
			),
		},
		RTPSrcPort: 40000, RTPDstPort: 40002,
		PayloadType:    0,
		SSRC:           0x5eed1e55,
		FirstSeq:       1,
		FirstTimestamp: 160,
		Packets:        3,
		Interval:       20 * time.Millisecond,
		MediaStart:     2 * time.Second,
		IPIdent:        0x3e68,
		TTL:            64,
	}
}

// DefaultVoIPMeta returns demo handover metadata for the call: its own network
// element and session (CIN).
func DefaultVoIPMeta() Meta {
	m := DefaultMeta()
	m.NEID = "ne-voip-01"
	m.CIN = 1003
	return m
}

// BuildSIPIRI produces an IRI-BEGIN PS-PDU whose IPMMIRI carries the INVITE as
// a sIPMessage: the SIP content plus the network-layer source and destination
// addresses (TS 102 232-5 clause 5.2.7).
func BuildSIPIRI(m Meta, s VoIPScenario) []byte {
	sipMessage := ber.CCons(1, // IPIRIContents alternative sIPMessage [1] SIPMessage (SEQUENCE)
		ipAddress(0, s.TargetIP),        // iPSourceAddress      [0] IPAddress
		ipAddress(1, s.ProxyIP),         // iPDestinationAddress [1] IPAddress
		ber.COctet(2, sip.Build(s.SIP)), // sIPContent           [2] OCTET STRING
	)
	ipMMIRI := ber.CCons(11, // IRIContents alternative iPMMIRI [11] IPMMIRI (SEQUENCE)
		ber.CRelOID(0, ipMMIRIObjID...), // iPMMIRIObjId    [0] RELATIVE-OID
		ber.CExplicit(1, sipMessage),    // iPMMIRIContents [1] IPIRIContents CHOICE -> explicit
	)
	return iriPayloadPDU(m, iriBegin, ipMMIRI)
}

// ipAddress builds an LI-PS-PDU IPAddress for an IPv4 address under context
// tag num.
func ipAddress(num int, ip net.IP) []byte {
	return ber.CCons(num, // IPAddress ::= SEQUENCE
		ber.CEnum(1, ipTypeV4),                    // iP-type [1] iPV4(0)
		ber.CExplicit(2, ber.COctet(1, ip.To4())), // iP-value [2] IP-value CHOICE -> explicit; iPBinaryAddress [1]
		ber.CEnum(3, ipAssignDyn),                 // iP-assignment [3] dynamic(2)
	)
}

// BuildRTPCC produces the CC PS-PDU for RTP packet i (0-based): an IPMMCC
// holding the whole IPv4/UDP/RTP packet (frameType ipFrame). Each IPMMCC
// carries exactly one packet, so each packet is its own PS-PDU; the CC
// sequence number and timestamp advance per packet.
func BuildRTPCC(m Meta, s VoIPScenario, i int) []byte {
	m.SeqNum += uint64(i)
	m.When = m.When.Add(s.MediaStart + time.Duration(i)*s.Interval)

	samples := uint32(s.Interval / (time.Second / 8000)) // 8 kHz clock for PCMU/PCMA
	media := rtp.Build(rtp.Packet{
		Marker:      i == 0, // first packet of a talkspurt
		PayloadType: s.PayloadType,
		Seq:         s.FirstSeq + uint16(i),
		Timestamp:   s.FirstTimestamp + uint32(i)*samples,
		SSRC:        s.SSRC,
		Payload:     silence(int(samples)),
	})
	packet := ipstack.UDPDatagram(s.TargetIP, s.MediaIP, s.RTPSrcPort, s.RTPDstPort,
		s.IPIdent+uint16(i), s.TTL, media)

	ipMMCC := ber.CCons(12, // CCContents alternative iPMMCC [12] IPMMCC (SEQUENCE)
		ber.CRelOID(0, ipMMCCObjID...),      // iPMMCCObjId      [0] RELATIVE-OID
		ber.COctet(1, packet),               // mMCCContents     [1] OCTET STRING
		ber.CEnum(2, frameIP),               // frameType        [2] ipFrame(0)
		ber.COctet(3, []byte(s.streamID())), // streamIdentifier [3] SDP m= line of the stream
		ber.CEnum(4, mmccRTP),               // mMCCprotocol     [4] rTP(0)
	)
	return ccPayloadPDU(m, dirFromTarget, ipMMCC)
}

// streamID matches the SDP media description the stream was negotiated with,
// so the CC can be correlated with the IRI (TS 102 232-5 streamIdentifier).
func (s VoIPScenario) streamID() string {
	return fmt.Sprintf("m=audio %d RTP/AVP %d", s.RTPSrcPort, s.PayloadType)
}

// silence returns n bytes of G.711 µ-law silence.
func silence(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = 0xff
	}
	return b
}

// BuildVoIPIRIAndCC produces one handover file for the call: the SIP IRI
// PS-PDU followed by one CC PS-PDU per RTP packet. IRI and CC are separate
// sequence number contexts, so the IRI and the first CC both carry m.SeqNum.
func BuildVoIPIRIAndCC(m Meta, s VoIPScenario) []byte {
	return append(BuildSIPIRI(m, s), BuildVoIPCC(m, s)...)
}

// BuildVoIPCC produces just the CC PS-PDUs for the RTP packets.
func BuildVoIPCC(m Meta, s VoIPScenario) []byte {
	var out []byte
	for i := 0; i < s.Packets; i++ {
		out = append(out, BuildRTPCC(m, s, i)...)
	}
	return out
}
