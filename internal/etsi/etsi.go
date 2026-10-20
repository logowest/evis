// Package etsi builds ETSI TS 102 232 handover PDUs (the HI2/HI3 "NHIS" stream)
// for a single DNS request, HTTP request or VoIP (SIP + RTP) call, and annotates decoded PDUs for display.
//
// Structure follows the published ASN.1 modules for TS 102 232-1 V3.38.1
// (ETSI forge, li/schemas-definitions):
//   - TS 102 232-1  LI-PS-PDU   (PS-PDU / PSHeader / Payload)   version 43
//   - TS 102 232-3  IPAccessPDU (IPCC / IPIRIOnly)              version 20
//
// Every field used here is unchanged since v31 / v13 (later versions only add
// extensions), so only the version arcs of the identifiers differ.
//
// Both modules are DEFINITIONS IMPLICIT TAGS, so context tags replace base-type
// tags except on CHOICE types, where the tag is EXPLICIT (handled with
// ber.CExplicit). Every tag number below is taken straight from those modules.
package etsi

import (
	"net"
	"time"

	"evis/internal/ber"
	"evis/internal/dns"
	"evis/internal/ipstack"
)

// li-psDomainId ::= {itu-t(0) identified-organization(4) etsi(0)
//
//	securityDomain(2) lawfulIntercept(2) li-ps(5) genHeader(1) version43(43)}
var liPSDomainID = []uint64{0, 4, 0, 2, 2, 5, 1, 43}

// RELATIVE-OIDs from TS 102 232-3, relative to {...lawfulIntercept(2)}.
var (
	ipCCObjID      = []uint64{5, 3, 20, 2} // li-ps iPAccess v20 cC
	ipIRIOnlyObjID = []uint64{5, 3, 20, 3} // li-ps iPAccess v20 iRIOnly
)

// Meta carries the common PSHeader fields shared by both PDUs.
type Meta struct {
	LIID       string    // lawfulInterceptionIdentifier (PrintableString, <=25)
	OperatorID string    // networkIdentifier.operatorIdentifier
	NEID       string    // networkIdentifier.networkElementIdentifier
	CIN        uint64    // communicationIdentityNumber
	SeqNum     uint64    // PSHeader.sequenceNumber
	When       time.Time // PSHeader.timeStamp
}

// Scenario describes the single DNS request being handed over.
type Scenario struct {
	SrcIP   net.IP
	DstIP   net.IP // the DNS resolver
	SrcPort uint16
	DstPort uint16 // 53
	IPIdent uint16
	TTL     uint8
	DNS     dns.Query
}

// DefaultScenario is a self-contained example: a recursion-desired A query for
// example.com from a subscriber to a resolver, using RFC 5737 documentation
// addresses so nothing resembles a real target.
func DefaultScenario() Scenario {
	return Scenario{
		SrcIP:   net.ParseIP("198.51.100.23"),
		DstIP:   net.ParseIP("203.0.113.53"),
		SrcPort: 49152,
		DstPort: 53,
		IPIdent: 0x1c46,
		TTL:     64,
		DNS: dns.Query{
			ID: 0x1a2b, RD: true, Name: "example.com.",
			QType: dns.TypeA, QClass: dns.ClassIN,
		},
	}
}

// DefaultMeta returns demo handover metadata.
func DefaultMeta() Meta {
	return Meta{
		LIID:       "DEMO-LIID-0001",
		OperatorID: "DEMO-CSP",
		NEID:       "ne-dns-01",
		CIN:        1001,
		SeqNum:     0, // each sequence number context starts at zero (TS 102 232-1 5.2.5)
		When:       time.Date(2026, 10, 12, 21, 11, 0, 0, time.UTC),
	}
}

// psHeader builds PSHeader [1] (TS 102 232-1).
func psHeader(m Meta) []byte {
	networkIdentifier := ber.CCons(0, // [0] NetworkIdentifier
		ber.COctet(0, []byte(m.OperatorID)), // operatorIdentifier       [0] OCTET STRING
		ber.COctet(1, []byte(m.NEID)),       // networkElementIdentifier [1] OCTET STRING
	)
	communicationIdentifier := ber.CCons(3, // [3] CommunicationIdentifier
		networkIdentifier,  // networkIdentifier           [0]
		ber.CInt(1, m.CIN), // communicationIdentityNumber [1] INTEGER
	)
	return ber.CCons(1, // PS-PDU field pSHeader [1] PSHeader
		ber.COID(0, liPSDomainID...), // li-psDomainId                [0] OBJECT IDENTIFIER
		ber.CPrintable(1, m.LIID),    // lawfulInterceptionIdentifier [1] (LIID)
		communicationIdentifier,      // communicationIdentifier      [3]
		ber.CInt(4, m.SeqNum),        // sequenceNumber               [4] INTEGER
		ber.CGenTime(5, m.When),      // timeStamp                    [5] GeneralizedTime
		ber.CEnum(8, 1),              // timeStampQualifier           [8] timeOfInterception(1)
	)
}

// BuildCC produces a PS-PDU whose CC payload carries the intercepted DNS packet
// (full IPv4/UDP/DNS datagram) as IPCC / iPPackets. This is the content-of-
// communication handover of the request.
func BuildCC(m Meta, s Scenario) []byte {
	dnsMsg := dns.Build(s.DNS)
	packet := ipstack.UDPDatagram(s.SrcIP, s.DstIP, s.SrcPort, s.DstPort, s.IPIdent, s.TTL, dnsMsg)
	return ccPDU(m, packet)
}

// ccPDU wraps one intercepted IP packet sent by the target as a CC PS-PDU
// (IPCC / iPPackets).
func ccPDU(m Meta, packet []byte) []byte { return ipccPDU(m, dirFromTarget, packet) }

// ipccPDU wraps one intercepted IP packet as a CC PS-PDU (IPCC / iPPackets)
// with the given payloadDirection.
func ipccPDU(m Meta, dir int, packet []byte) []byte {
	// IPCC ::= SEQUENCE { iPCCObjId [0] RELATIVE-OID, iPCCContents [1] IPCCContents }
	// IPCCContents ::= CHOICE { iPPackets [0] OCTET STRING, ... }
	ipccContents := ber.CExplicit(1, // iPCCContents [1] CHOICE -> explicit
		ber.COctet(0, packet), // iPPackets [0] OCTET STRING
	)
	ipcc := ber.CCons(2, // CCContents alternative iPCC [2] IPCC (implicit, SEQUENCE)
		ber.CRelOID(0, ipCCObjID...), // iPCCObjId [0] RELATIVE-OID
		ipccContents,                 // iPCCContents [1]
	)
	return ccPayloadPDU(m, dir, ipcc)
}

// payloadDirection values (TS 102 232-1 PayloadDirection).
const (
	dirFromTarget = 0
	dirToTarget   = 1
)

// ccPayloadPDU wraps one CCContents alternative (e.g. iPCC [2], iPMMCC [12])
// as a CC PS-PDU.
func ccPayloadPDU(m Meta, dir int, ccContents []byte) []byte {
	ccPayload := ber.Seq( // CCPayload ::= SEQUENCE
		ber.CEnum(0, dir),            // payloadDirection [0]
		ber.CExplicit(2, ccContents), // cCContents [2] CCContents CHOICE -> explicit
	)
	payload := ber.CExplicit(2, // PS-PDU payload [2] Payload CHOICE -> explicit
		ber.CCons(1, ccPayload), // cCPayloadSequence [1] SEQUENCE OF CCPayload
	)
	return ber.Seq(psHeader(m), payload) // PS-PDU ::= SEQUENCE
}

// BuildIRIOnly produces a PS-PDU whose IRI payload carries an IPIRIOnly record:
// the IPv4 + UDP header fields of the DNS request without the packet content.
// This is the header-only intercept-related-information handover.
func BuildIRIOnly(m Meta, s Scenario) []byte {
	dnsMsg := dns.Build(s.DNS)
	udpLen := 8 + len(dnsMsg)

	// UDPInformation ::= SEQUENCE { sourcePort [0], destinationPort [1], length [2], checkSum [3] }
	udpInfo := ber.CCons(2, // ProtocolInformation alternative uDPInformation [2] (SEQUENCE)
		ber.COctet(0, ber.Fixed(2, uint64(s.SrcPort))), // sourcePort      [0]
		ber.COctet(1, ber.Fixed(2, uint64(s.DstPort))), // destinationPort [1]
		ber.COctet(2, ber.Fixed(2, uint64(udpLen))),    // length          [2]
		ber.COctet(3, ber.Fixed(2, 0)),                 // checkSum        [3] (not reported here)
	)
	return iriPDU(m, ipv4Info(s.SrcIP, s.DstIP, 20+udpLen, s.IPIdent, s.TTL, 17), udpInfo)
}

// ipv4Info builds the iPv4Information alternative of IPInformation.
func ipv4Info(src, dst net.IP, totalLen int, ident uint16, ttl, proto uint8) []byte {
	// IPv4Information ::= SEQUENCE { ... source [8], destination [9], ... }
	return ber.CCons(0, // IPInformation alternative iPv4Information [0] (SEQUENCE)
		ber.COctet(2, ber.Fixed(2, uint64(totalLen))), // totalLength    [2]
		ber.COctet(3, ber.Fixed(2, uint64(ident))),    // identification [3]
		ber.COctet(5, []byte{ttl}),                    // ttl            [5]
		ber.COctet(6, []byte{proto}),                  // protocol       [6]
		ber.COctet(8, src.To4()),                      // source         [8]
		ber.COctet(9, dst.To4()),                      // destination    [9]
	)
}

// iriPDU wraps IP and transport header information as an IRI PS-PDU
// (IPIRIOnly). ipInfo is an IPInformation alternative, protoInfo a
// ProtocolInformation alternative; both get their explicit CHOICE wrappers here.
func iriPDU(m Meta, ipInfo, protoInfo []byte) []byte {
	ipIRIOnly := ber.CCons(3, // IRIContents alternative iPIRIOnly [3] IPIRIOnly (SEQUENCE)
		ber.CRelOID(0, ipIRIOnlyObjID...), // iPIRIOnlyObjId [0] RELATIVE-OID
		ber.CExplicit(1, ipInfo),          // iPInformation  [1] CHOICE -> explicit
		ber.CExplicit(2, protoInfo),       // protocolInformation [2] CHOICE -> explicit
	)
	return iriPayloadPDU(m, iriReport, ipIRIOnly)
}

// IRIType values (TS 102 232-1).
const (
	iriBegin    = 1
	iriEnd      = 2
	iriContinue = 3
	iriReport   = 4
)

// iriPayloadPDU wraps one IRIContents alternative (e.g. iPIRIOnly [3],
// iPMMIRI [11]) as an IRI PS-PDU.
func iriPayloadPDU(m Meta, iriType int, iriContents []byte) []byte {
	iriPayload := ber.Seq( // IRIPayload ::= SEQUENCE
		ber.CEnum(0, iriType),         // iRIType [0]
		ber.CExplicit(2, iriContents), // iRIContents [2] IRIContents CHOICE -> explicit
	)
	payload := ber.CExplicit(2, // PS-PDU payload [2] Payload CHOICE -> explicit
		ber.CCons(0, iriPayload), // iRIPayloadSequence [0] SEQUENCE OF IRIPayload
	)
	return ber.Seq(psHeader(m), payload)
}

// BuildIRIAndCC produces a single handover file holding both records for the
// DNS request: the IRI-only PS-PDU followed by the CC PS-PDU. They cannot share
// one PS-PDU (payload is a CHOICE), so they are two concatenated PDUs with the
// same LIID and CIN. IRI and CC are separate sequence number contexts (the
// payload type is part of the context, TS 102 232-1 5.2.5 table 1A), so each
// keeps its own counter: both PDUs carry m.SeqNum.
func BuildIRIAndCC(m Meta, s Scenario) []byte {
	return append(BuildIRIOnly(m, s), BuildCC(m, s)...)
}
