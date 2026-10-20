package etsi

import (
	"strings"

	"evis/internal/ber"
)

// Field descriptions shown as tooltips in the visualiser (ber.Node.Note).
//
// TS 102 232-1 text is summarised from V3.38.1 (2026-08); § numbers refer to
// that document. TS 102 232-3 fields are described from the IPAccessPDU ASN.1
// definitions. Inner protocol fields follow RFC 791 / 768 / 1035.

// fieldNotes describes ASN.1 fields, keyed by the name annotate.go assigns
// (any "[n]" index suffix is stripped before lookup).
var fieldNotes = map[string]string{
	// TS 102 232-1 — PS-PDU and PSHeader
	"PS-PDU":   "One handover PDU: a PSHeader identifying the intercept, plus exactly one payload (IRI, CC, TRI, …). TS 102 232-1 §5, annex A.",
	"pSHeader": "Header fields that let the receiver identify, order and correlate the PDU (TS 102 232-1 §5.1).",
	"li-psDomainId": "Version of the LI-PS-PDU header module in use. The last arc is the module version " +
		"(TS 102 232-1 §5.2.1).",
	"lawfulInterceptionIdentifier": "LIID: identifies the lawful authorization the data was intercepted under. " +
		"Defined in TS 103 280 clause 6 (TS 102 232-1 §5.2.2).",
	"authorizationCountryCode": "ACC: ISO 3166-1 alpha-2 code of the country where the authorization was granted. " +
		"ACC plus a nationally unique LIID is internationally unique (§5.2.3).",
	"communicationIdentifier": "CID: network identifier + communication identity number (+ optional delivery country code). " +
		"Identifies the communication session the data belongs to (§5.2.4).",
	"networkIdentifier":  "NID: operator identifier plus optional network element identifier (§5.2.4).",
	"operatorIdentifier": "OPID: identifies the CSP performing the interception. Mandatory (§5.2.4).",
	"networkElementIdentifier": "NEID: optional; identifies the Mediation Function within the CSP. " +
		"Must be unique within the CSP domain (§5.2.4).",
	"communicationIdentityNumber": "CIN: identifies the communication session within the network element. " +
		"All IRI and CC for one session carry the same CIN, which is how they are correlated (§5.2.4).",
	"deliveryCountryCode": "DCC: ISO 3166-1 alpha-2 location of the Mediation Function; makes the CID internationally unique (§5.2.4).",
	"sequenceNumber": "Counts PS-PDUs within a sequence number context (LIID, CID and payload type). Starts at 0 and " +
		"increments by 1 per PDU; IRI and CC are counted independently. Gaps reveal missing or out-of-order PDUs (§5.2.5).",
	"timeStamp": "Payload timestamp. Mandatory for IRI; CC normally carries one too. Inside IRIPayload/CCPayload it is " +
		"only strictly required when several payloads are aggregated in one PDU (§5.2.6).",
	"interceptionPointID": "IPID: optional identifier (up to 8 characters) of the interception point, unique within the CSP (§5.2.11).",
	"timeStampQualifier": "What the timestamp represents: unknown, timeOfInterception (preferred), timeOfMediation " +
		"or timeOfAggregation (§5.2.6).",

	// TS 102 232-1 — Payload
	"payload": "Payload type (a CHOICE): each PDU carries exactly one of IRI, CC, TRI and the other payload kinds (§5.2.8). " +
		"The [2] tag is explicit because Payload is a CHOICE.",
	"iRIPayloadSequence": "IRI payload: one or more IRIPayload records (SEQUENCE OF). Several records may share one PDU " +
		"by aggregation (§6.2.3).",
	"cCPayloadSequence": "CC payload: one or more CCPayload records (SEQUENCE OF). Several records may share one PDU " +
		"by aggregation (§6.2.3).",
	"tRIPayload": "TRI: information about delivery to the LEA or maintenance of the transport connection, " +
		"e.g. keep-alive, integrityCheck, testPDU (§5.2.8).",
	"iRIPayload": "One IRI record: IRI type, optional timestamp and the service-specific IRI contents.",
	"cCPayload":  "One CC record: optional direction and timestamp plus the service-specific content.",
	"iRIType": "IRI-BEGIN, IRI-CONTINUE and IRI-END bracket a communication; IRI-REPORT is for one-off or " +
		"non-communication events. Mandatory (§5.2.10).",
	"payloadDirection": "Direction of the intercepted data relative to the target (fromTarget, toTarget, …). Optional for CC (§5.2.7).",
	"iRIContents":      "Service-specific IRI (a CHOICE), here iPIRIOnly from TS 102 232-3. The tag is explicit because the type is a CHOICE.",
	"cCContents":       "Service-specific CC (a CHOICE), here iPCC from TS 102 232-3. The tag is explicit because the type is a CHOICE.",

	// TS 102 232-3 — IP access
	"iPCC":         "IP content of communication (TS 102 232-3): carries the intercepted IP packets themselves.",
	"iPCCObjId":    "Relative OID naming the TS 102 232-3 module version and structure (li-ps.iPAccess.vN.cC).",
	"iPCCContents": "CHOICE holding the content; iPPackets is the only alternative defined.",
	"iPPackets":    "The intercepted IP packet, byte for byte, starting at the IP header. Decoded below as IPv4 / UDP / DNS.",
	"iPIRIOnly": "IRI-only intercept (TS 102 232-3): the IP and transport header fields of a packet without its content. " +
		"TS 102 232-1 describes it as derived from the CC.",
	"iPIRIOnlyObjId":      "Relative OID naming the TS 102 232-3 module version and structure (li-ps.iPAccess.vN.iRIOnly).",
	"iPInformation":       "IP header fields, as a CHOICE of iPv4Information or iPv6Information.",
	"iPv4Information":     "Fields copied from the packet's IPv4 header. Only source and destination are mandatory.",
	"protocolInformation": "Transport-layer header fields, as a CHOICE of none, TCP or UDP.",
	"uDPInformation":      "Fields copied from the packet's UDP header; all optional.",
	"totalLength":         "IPv4 total length in bytes (header plus data), as 2 octets.",
	"identification":      "IPv4 identification value, used to reassemble fragments.",
	"ttl":                 "IPv4 time to live: remaining hop count.",
	"protocol":            "IPv4 protocol number of the transport layer (17 = UDP, 6 = TCP).",
	"source":              "Source IPv4 address (mandatory).",
	"destination":         "Destination IPv4 address (mandatory).",
	"sourcePort":          "UDP source port, as 2 octets.",
	"destinationPort":     "UDP destination port, as 2 octets (53 = DNS).",
	"length":              "UDP length in bytes (header plus data), as 2 octets.",
	"checkSum":            "UDP checksum, as 2 octets.",
}

// protoNotes describes the decoded IPv4/UDP/DNS byte ranges inside iPPackets.
// They are not ASN.1: they are fields of the intercepted packet itself.
var protoNotes = map[string]string{
	"IPv4 header":    "IPv4 header of the intercepted packet (RFC 791). Decoded from iPPackets; not ASN.1.",
	"version/IHL":    "IP version (4) and header length in 32-bit words.",
	"totalLength":    "Length of the whole IPv4 packet in bytes.",
	"identification": "Identifies the packet's fragments for reassembly.",
	"flags/fragment": "DF (don't fragment) and MF (more fragments) flags, plus the fragment offset.",
	"ttl":            "Time to live: decremented by each router; the packet is dropped at zero.",
	"protocol":       "Transport protocol carried (17 = UDP, 6 = TCP).",
	"headerChecksum": "Checksum over the IPv4 header only.",
	"source":         "Source IPv4 address.",
	"destination":    "Destination IPv4 address.",

	"UDP header":      "UDP header of the intercepted packet (RFC 768).",
	"sourcePort":      "UDP source port (the client's ephemeral port).",
	"destinationPort": "UDP destination port (53 = DNS).",
	"length":          "Length of the UDP header plus data, in bytes.",
	"checksum":        "Checksum over a pseudo-header, the UDP header and data. 0 means not computed.",

	"DNS message": "The DNS message carried in the UDP payload (RFC 1035).",
	"DNS header":  "Fixed 12-byte DNS header (RFC 1035 §4.1.1).",
	"id":          "Query ID, copied into the response so the client can match them.",
	"flags":       "QR (query/response), OPCODE, AA, TC, RD (recursion desired), RA and RCODE bits.",
	"qdcount":     "Number of entries in the question section.",
	"ancount":     "Number of resource records in the answer section.",
	"nscount":     "Number of name server records in the authority section.",
	"arcount":     "Number of records in the additional section.",
	"question":    "One question: the name, type and class being asked about (RFC 1035 §4.1.2).",
	"qname":       "Domain name being queried, encoded as length-prefixed labels.",
	"qtype":       "Record type requested (e.g. A = 1, AAAA = 28).",
	"qclass":      "Query class; IN (1) means Internet.",
}

// describe fills Note for n and its descendants from the tables above.
func describe(n *ber.Node) {
	notes := fieldNotes
	if n.Raw {
		notes = protoNotes
	}
	if n.Note == "" {
		name, _, _ := strings.Cut(n.Name, "[")
		n.Note = notes[name]
	}
	for _, c := range n.Children {
		describe(c)
	}
}
