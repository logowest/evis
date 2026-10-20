package etsi

import (
	"strings"

	"evis/internal/ber"
)

// Field descriptions shown as tooltips in the visualiser (ber.Node.Note).
//
// TS 102 232-1 text is summarised from V3.38.1 (2026-08); § numbers refer to
// that document. TS 102 232-3 and TS 102 232-5 fields are described from the
// IPAccessPDU and IPMultimediaPDU ASN.1 definitions. Inner protocol fields follow RFC 791 / 768 / 9293 / 1035 / 9112 /
// 3550.

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
	"iRIContents": "Service-specific IRI (a CHOICE), e.g. iPIRIOnly (TS 102 232-3) or iPMMIRI (TS 102 232-5). " +
		"The tag is explicit because the type is a CHOICE.",
	"cCContents": "Service-specific CC (a CHOICE), e.g. iPCC (TS 102 232-3) or iPMMCC (TS 102 232-5). " +
		"The tag is explicit because the type is a CHOICE.",

	// TS 102 232-3 — IP access
	"iPCC":         "IP content of communication (TS 102 232-3): carries the intercepted IP packets themselves.",
	"iPCCObjId":    "Relative OID naming the TS 102 232-3 module version and structure (li-ps.iPAccess.vN.cC).",
	"iPCCContents": "CHOICE holding the content; iPPackets is the only alternative defined.",
	"iPPackets": "The intercepted IP packet, byte for byte, starting at the IP header. Decoded below as IPv4, " +
		"the transport header (UDP or TCP) and the application message (DNS, RTP or HTTP).",
	"iPIRIOnly": "IRI-only intercept (TS 102 232-3): the IP and transport header fields of a packet without its content. " +
		"TS 102 232-1 describes it as derived from the CC.",
	"iPIRIOnlyObjId":      "Relative OID naming the TS 102 232-3 module version and structure (li-ps.iPAccess.vN.iRIOnly).",
	"iPInformation":       "IP header fields, as a CHOICE of iPv4Information or iPv6Information.",
	"iPv4Information":     "Fields copied from the packet's IPv4 header. Only source and destination are mandatory.",
	"protocolInformation": "Transport-layer header fields, as a CHOICE of none, TCP or UDP.",
	"tCPInformation":      "Fields copied from the packet's TCP header; all optional.",
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

	// TS 102 232-5 — IP multimedia (VoIP)
	"iPMMCC": "IP multimedia content of communication (TS 102 232-5): one intercepted media packet " +
		"(RTP/RTCP, UDPTL or MSRP). Each IPMMCC carries exactly one packet.",
	"iPMMCCObjId": "Relative OID naming the TS 102 232-5 module version and structure (li-ps.iPMultimedia.vN.cC).",
	"mMCCContents": "The intercepted media packet. Which headers are present is given by frameType; " +
		"with ipFrame it starts at the IP header and is decoded below.",
	"frameType": "Which headers mMCCContents includes: ipFrame (all), udpFrame (no IP), rtpFrame (no IP/UDP), " +
		"audioFrame (none), etc. Mandatory for new implementations.",
	"streamIdentifier": "Identifies the media stream within the CIN, e.g. an extract of the SDP m= and c= lines, " +
		"so the CC can be correlated with the SDP in the IRI.",
	"mMCCprotocol": "Protocol of the packets in mMCCContents: rTP, mSRP or uDPTL. Absent means RTP/RTCP or audio per frameType.",
	"iPMMIRI":      "IP multimedia IRI (TS 102 232-5): the call signalling (SIP or H.323) of a multimedia session.",
	"iPMMIRIObjId": "Relative OID naming the TS 102 232-5 module version and structure (li-ps.iPMultimedia.vN.iRI).",
	"iPMMIRIContents": "CHOICE of how the signalling is delivered: the original packet, a SIPMessage, an H323Message, …. " +
		"The tag is explicit because the type is a CHOICE.",
	"targetLocation":       "Location of the target, if known (TS 102 232-1 Location).",
	"additionalSignalling": "Extra signalling information, e.g. individual SIP header lines.",
	"originalIPMMMessage":  "Copy of the signalling packet including its original IP and UDP/TCP headers.",
	"iRIOnlyOriginalIPMMMessage": "IRI-only interception: copy of the signalling packet including its original " +
		"IP and UDP/TCP headers (TS 102 232-5 clause 5.2.6).",
	"iRIOnlyRTPPacket": "Copy of an RTP packet carrying telephony events (e.g. DTMF), with its IP and UDP headers.",
	"sIPMessage": "The SIP message content plus the source and destination IP addresses it was sent between " +
		"(TS 102 232-5 clause 5.2.7).",
	"iRIOnlySIPMessage":         "As sIPMessage, for IRI-only interception (TS 102 232-5 clause 5.2.6).",
	"h323Message":               "H.323 signalling content plus source and destination IP addresses.",
	"nationalIPMMIRIParameters": "Nationally defined parameters; delivered as an IRI-REPORT.",
	"xCAPMessage":               "Copy of an XCAP message including all HTTP headers and contents.",
	"iPSourceAddress":           "Network-layer source address of the intercepted SIP message.",
	"iPDestinationAddress":      "Network-layer destination address of the intercepted SIP message.",
	"sIPContent":                "The SIP message itself, from its start line; decoded below.",

	// TS 102 232-1 — IPAddress
	"iP-type":          "Address family: iPV4 or iPV6.",
	"iP-value":         "The address, as a CHOICE of binary or text form. The tag is explicit because the type is a CHOICE.",
	"iPBinaryAddress":  "The address in binary: 4 octets for IPv4, 16 for IPv6.",
	"iPTextAddress":    "The address as text, e.g. \"192.0.2.1\" or with a prefix length.",
	"iP-assignment":    "How the address was assigned: static, dynamic or notKnown.",
	"iPv6PrefixLength": "Length of the IPv6 prefix delegated to the subscriber.",
	"iPv4SubnetMask":   "IPv4 subnet mask applying to the address.",
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

	"TCP header": "TCP header of the intercepted packet (RFC 9293).",

	"transport payload": "Bytes carried after the transport header, not decoded further.",

	"reassembled HTTP request": "An HTTP request rebuilt from several TCP segments carried in separate CC PS-PDUs, " +
		"ordered by TCP sequence number, with retransmitted bytes dropped. Attached to the PDU that completes it.",
	"reassembled HTTP response": "An HTTP response rebuilt from several TCP segments carried in separate CC PS-PDUs, " +
		"ordered by TCP sequence number, with retransmitted bytes dropped. Attached to the PDU that completes it.",
	"reassembled SIP message": "A SIP message rebuilt from several TCP segments carried in separate PS-PDUs, " +
		"ordered by TCP sequence number, with retransmitted bytes dropped. Attached to the PDU that completes it.",
	"segments": "The TCP segments the message was rebuilt from, in stream order. Hover one to highlight its bytes.",
	"segment":  "One TCP segment's contribution to the message: which PS-PDU it came from and which stream bytes it holds.",
	"missing data": "Stream bytes no captured segment carried (lost, or not delivered). The message is incomplete; " +
		"nothing after the gap is guessed.",
	"decoded content": "The body with its Content-Encoding (gzip or deflate) undone. The value previews the " +
		"decompressed data; the highlight covers the encoded bytes it came from.",
	"chunk":      "One chunk of a chunked body (RFC 9112 §7.1): size line, data, CRLF.",
	"chunk-size": "Chunk length in hex, optionally followed by chunk extensions, then CRLF.",
	"chunk-data": "The chunk's data bytes.",
	"last-chunk": "Zero-length chunk ending the body, followed by any trailer fields and an empty line.",

	"HTTP request": "The HTTP/1.1 request carried in the TCP payload (RFC 9112). Plain HTTP, so the content is readable.",
	"HTTP response": "The start of an HTTP/1.1 response carried in the TCP payload (RFC 9112). A response longer " +
		"than one segment continues in later CC PDUs, which show as plain transport payload (no TCP reassembly).",
	"request-line": "First line of a request: method, target and protocol version, ended by CRLF " +
		"(HTTP: RFC 9112 §3; SIP: RFC 3261 §7.1).",
	"status-line":    "First line of a response: protocol version, status code and reason phrase, ended by CRLF.",
	"method":         "Request method, e.g. GET (HTTP) or INVITE (SIP).",
	"request-target": "Resource being requested; here origin-form, a path on the server named by Host (RFC 9112 §3.2).",
	"HTTP-version":   "Protocol version of the message (RFC 9112 §2.3).",
	"status-code":    "Three-digit result code, e.g. 200 (success) or 180 (ringing, SIP).",
	"reason-phrase":  "Human-readable text for the status code.",
	"header field": "One header field, name: value, ended by CRLF (HTTP: RFC 9110 §5; SIP: RFC 3261 §7.3). " +
		"In HTTP, Host names the site; in SIP, From/To/Call-ID identify the call.",
	"end of headers": "Empty line (CRLF) ending the header section; any body follows it.",
	"message body":   "Message content after the header section.",

	"SIP message": "SIP signalling message (RFC 3261), e.g. the INVITE that sets up a call. Its SDP body " +
		"describes the media streams.",
	"Request-URI": "Who the request is addressed to, e.g. the called party's SIP URI (RFC 3261 §8.1.1.1).",
	"SIP-Version": "Protocol version, SIP/2.0.",
	"SDP body": "Session description (RFC 8866): the media the caller offers, including the address and port " +
		"RTP will be sent to and the codecs.",
	"SDP line": "One SDP line, <type>=<value>. c= gives the media address, m= the media type, port, transport " +
		"and payload types, a=rtpmap maps a payload type to a codec.",

	"RTP packet": "RTP media packet carried in the UDP payload (RFC 3550). RTP has no fixed port, so it is " +
		"recognised from its header: version 2 and a payload type outside the RTCP range.",
	"RTP header":         "Fixed 12-byte RTP header plus any CSRC list (RFC 3550 §5.1).",
	"version/P/X/CC":     "Version (2), P = padding present, X = header extension present, CC = number of CSRCs that follow.",
	"marker/payloadType": "M = marker bit (e.g. start of a talkspurt or end of a video frame); PT = media encoding (RFC 3551 static types, 96–127 dynamic via SDP).",
	"sequenceNumber":     "Increments by one per RTP packet; lets the receiver detect loss and reorder packets.",
	"timestamp":          "Sampling instant of the first media byte, in media clock units (8000 Hz for PCMU/PCMA).",
	"ssrc":               "Synchronisation source: random 32-bit identifier of this media stream.",
	"csrc":               "Contributing source: an SSRC mixed into this packet (e.g. by a conference mixer).",
	"header extension":   "Profile-specific header extension, e.g. RFC 8285 one-byte (0xBEDE) or two-byte elements (RFC 3550 §5.3.1).",
	"profile":            "Identifies the format of the extension data.",
	"extensionLength":    "Length of the extension data in 32-bit words.",
	"extension data":     "Header extension elements, e.g. audio level or absolute send time.",
	"media payload":      "Encoded media (audio samples or video data) in the format named by the payload type.",
	"padding":            "Padding octets; the last octet holds the padding count (RFC 3550 §5.1).",

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

// tcpInfoNotes describes TCPInformation fields in IPIRIOnly. They get their own
// table because names like sourcePort and sequenceNumber mean something else
// in UDPInformation and PSHeader.
var tcpInfoNotes = map[string]string{
	"sourcePort":      "TCP source port, as 2 octets.",
	"destinationPort": "TCP destination port, as 2 octets (80 = HTTP).",
	"sequenceNumber":  "TCP sequence number of the segment's first data byte, as 4 octets.",
	"ackNumber":       "TCP acknowledgement number: the next byte expected from the peer, as 4 octets.",
	"dataOffset":      "TCP header length in 32-bit words, as a 4-bit BIT STRING (the first 4 bits of byte 12).",
	"controlBits":     "TCP flags URG, ACK, PSH, RST, SYN, FIN, as a 6-bit BIT STRING in that order.",
	"windowSize":      "TCP receive window, as 2 octets.",
	"checkSum":        "TCP checksum, as 2 octets.",
	"urgentPointer":   "TCP urgent pointer, as 2 octets.",
	"options":         "TCP options, up to 40 octets.",
}

// tcpHeaderNotes describes the decoded TCP header bytes inside iPPackets.
var tcpHeaderNotes = map[string]string{
	"sourcePort":      "TCP source port (the client's ephemeral port).",
	"destinationPort": "TCP destination port (80 = HTTP).",
	"sequenceNumber":  "Sequence number of the first data byte in this segment.",
	"ackNumber":       "Next sequence number expected from the peer (valid when ACK is set).",
	"dataOffset":      "Upper 4 bits: TCP header length in 32-bit words (5 = 20 bytes, no options).",
	"controlBits":     "Flags: URG, ACK, PSH, RST, SYN, FIN. PSH, ACK marks a data segment on an established connection.",
	"windowSize":      "Receive window: how many bytes the sender is willing to accept.",
	"checksum":        "Checksum over a pseudo-header, the TCP header and data.",
	"urgentPointer":   "Offset of urgent data (only meaningful when URG is set).",
	"options":         "TCP options (MSS, SACK, timestamps, …).",
}

// describe fills Note for n and its descendants from the tables above.
func describe(n *ber.Node) { describeWith(n, nil) }

// describeWith looks n up in notes, or — when notes is nil — in fieldNotes or
// protoNotes depending on whether n is an ASN.1 field or a decoded byte range.
// Children of TCP nodes use the TCP tables.
func describeWith(n *ber.Node, notes map[string]string) {
	if notes == nil {
		notes = fieldNotes
		if n.Raw {
			notes = protoNotes
		}
	}
	if n.Note == "" {
		name, _, _ := strings.Cut(n.Name, "[")
		n.Note = notes[name]
	}
	var child map[string]string
	switch n.Name {
	case "tCPInformation":
		child = tcpInfoNotes
	case "TCP header":
		child = tcpHeaderNotes
	}
	for _, c := range n.Children {
		describeWith(c, child)
	}
}
