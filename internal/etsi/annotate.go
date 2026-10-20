package etsi

import (
	"fmt"
	"net"
	"strings"

	"evis/internal/ber"
	"evis/internal/dns"
	"evis/internal/httpmsg"
	"evis/internal/ipstack"
	"evis/internal/rtp"
	"evis/internal/sip"
)

// Annotate walks decoded top-level nodes as ETSI PS-PDUs, filling in field
// names, ASN.1 types, human-readable values, field descriptions (Note), and —
// for CC and IP multimedia IRI — the nested IPv4, UDP/TCP and DNS/SIP/RTP/HTTP PDUs found inside iPPackets.
//
// It then reassembles TCP streams across PDUs (see reassembleTCP), so HTTP
// and SIP messages split over several CC PDUs are decoded whole.
func Annotate(nodes []*ber.Node) {
	for i, n := range nodes {
		annotatePSPDU(n, i)
	}
	reassembleTCP(nodes)
}

func annotatePSPDU(n *ber.Node, i int) {
	n.Name, n.TypeName = "PS-PDU", "SEQUENCE"
	n.Value = fmt.Sprintf("#%d · ETSI TS 102 232-1 handover PDU", i+1)
	if h := ctx(n, 1); h != nil {
		annotatePSHeader(h)
	}
	if p := ctx(n, 2); p != nil {
		annotatePayload(p)
	}
	fillGaps(n)
	describe(n)
}

func annotatePSHeader(n *ber.Node) {
	n.Name, n.TypeName, n.Value = "pSHeader", "PSHeader", ""
	for _, c := range n.Children {
		switch c.TagNum {
		case 0:
			set(c, "li-psDomainId", "OBJECT IDENTIFIER", oidValue(c))
		case 1:
			set(c, "lawfulInterceptionIdentifier", "LIID", ascii(c.Content))
		case 2:
			set(c, "authorizationCountryCode", "PrintableString", ascii(c.Content))
		case 3:
			annotateCommID(c)
		case 4:
			set(c, "sequenceNumber", "INTEGER", fmt.Sprintf("%d", ber.DecodeInt(c.Content)))
		case 5:
			set(c, "timeStamp", "GeneralizedTime", ascii(c.Content))
		case 6:
			set(c, "interceptionPointID", "PrintableString", ascii(c.Content))
		case 8:
			set(c, "timeStampQualifier", "ENUMERATED", enumVal(c, tsQualifier))
		}
	}
}

func annotateCommID(n *ber.Node) {
	n.Name, n.TypeName = "communicationIdentifier", "CommunicationIdentifier"
	for _, c := range n.Children {
		switch c.TagNum {
		case 0:
			c.Name, c.TypeName = "networkIdentifier", "NetworkIdentifier"
			for _, g := range c.Children {
				switch g.TagNum {
				case 0:
					set(g, "operatorIdentifier", "OCTET STRING", ascii(g.Content))
				case 1:
					set(g, "networkElementIdentifier", "OCTET STRING", ascii(g.Content))
				}
			}
		case 1:
			set(c, "communicationIdentityNumber", "INTEGER", fmt.Sprintf("%d", ber.DecodeInt(c.Content)))
		case 2:
			set(c, "deliveryCountryCode", "PrintableString", ascii(c.Content))
		}
	}
}

// annotatePayload handles the EXPLICIT [2] wrapper around the Payload CHOICE.
func annotatePayload(n *ber.Node) {
	n.Name, n.TypeName, n.Value = "payload", "Payload", "CHOICE (explicit [2])"
	inner := first(n)
	if inner == nil {
		return
	}
	switch inner.TagNum {
	case 0:
		inner.Name, inner.TypeName = "iRIPayloadSequence", "SEQUENCE OF IRIPayload"
		for i, c := range inner.Children {
			annotateIRIPayload(c, i)
		}
	case 1:
		inner.Name, inner.TypeName = "cCPayloadSequence", "SEQUENCE OF CCPayload"
		for i, c := range inner.Children {
			annotateCCPayload(c, i)
		}
	case 2:
		inner.Name, inner.TypeName = "tRIPayload", "TRIPayload"
	}
}

func annotateCCPayload(n *ber.Node, i int) {
	n.Name, n.TypeName, n.Value = fmt.Sprintf("cCPayload[%d]", i), "CCPayload", ""
	for _, c := range n.Children {
		switch c.TagNum {
		case 0:
			set(c, "payloadDirection", "ENUMERATED", enumVal(c, payloadDir))
		case 1:
			set(c, "timeStamp", "GeneralizedTime", ascii(c.Content))
		case 2: // cCContents [2] CHOICE -> explicit
			c.Name, c.TypeName, c.Value = "cCContents", "CCContents", "CHOICE (explicit [2])"
			switch in := first(c); {
			case in != nil && in.TagNum == 2:
				annotateIPCC(in)
			case in != nil && in.TagNum == 12:
				annotateIPMMCC(in)
			}
		}
	}
}

func annotateIPCC(n *ber.Node) {
	n.Name, n.TypeName, n.Value = "iPCC", "IPCC", "TS 102 232-3"
	for _, c := range n.Children {
		switch c.TagNum {
		case 0:
			set(c, "iPCCObjId", "RELATIVE-OID", relOIDValue(c, "iPCC"))
		case 1: // iPCCContents [1] CHOICE -> explicit
			c.Name, c.TypeName, c.Value = "iPCCContents", "IPCCContents", "CHOICE (explicit [1])"
			if pk := first(c); pk != nil && pk.TagNum == 0 {
				set(pk, "iPPackets", "OCTET STRING", fmt.Sprintf("%d bytes — intercepted datagram", len(pk.Content)))
				decodePacket(pk)
			}
		}
	}
}

func annotateIRIPayload(n *ber.Node, i int) {
	n.Name, n.TypeName, n.Value = fmt.Sprintf("iRIPayload[%d]", i), "IRIPayload", ""
	for _, c := range n.Children {
		switch c.TagNum {
		case 0:
			set(c, "iRIType", "ENUMERATED", enumVal(c, iriType))
		case 1:
			set(c, "timeStamp", "GeneralizedTime", ascii(c.Content))
		case 2: // iRIContents [2] CHOICE -> explicit
			c.Name, c.TypeName, c.Value = "iRIContents", "IRIContents", "CHOICE (explicit [2])"
			switch in := first(c); {
			case in != nil && in.TagNum == 3:
				annotateIPIRIOnly(in)
			case in != nil && in.TagNum == 11:
				annotateIPMMIRI(in)
			}
		}
	}
}

func annotateIPIRIOnly(n *ber.Node) {
	n.Name, n.TypeName, n.Value = "iPIRIOnly", "IPIRIOnly", "TS 102 232-3"
	for _, c := range n.Children {
		switch c.TagNum {
		case 0:
			set(c, "iPIRIOnlyObjId", "RELATIVE-OID", relOIDValue(c, "iPIRIOnly"))
		case 1: // iPInformation [1] CHOICE -> explicit
			c.Name, c.TypeName, c.Value = "iPInformation", "IPInformation", "CHOICE (explicit [1])"
			if v4 := first(c); v4 != nil && v4.TagNum == 0 {
				v4.Name, v4.TypeName = "iPv4Information", "IPv4Information"
				annotateIPv4Info(v4)
			}
		case 2: // protocolInformation [2] CHOICE -> explicit
			c.Name, c.TypeName, c.Value = "protocolInformation", "ProtocolInformation", "CHOICE (explicit [2])"
			switch u := first(c); {
			case u != nil && u.TagNum == 1:
				u.Name, u.TypeName = "tCPInformation", "TCPInformation"
				annotateTCPInfo(u)
			case u != nil && u.TagNum == 2:
				u.Name, u.TypeName = "uDPInformation", "UDPInformation"
				annotateUDPInfo(u)
			}
		}
	}
}

func annotateIPv4Info(n *ber.Node) {
	for _, c := range n.Children {
		switch c.TagNum {
		case 2:
			set(c, "totalLength", "OCTET STRING", fmt.Sprintf("%d", ber.DecodeInt(c.Content)))
		case 3:
			set(c, "identification", "OCTET STRING", fmt.Sprintf("0x%s", hexPlain(c.Content)))
		case 5:
			set(c, "ttl", "OCTET STRING", fmt.Sprintf("%d", ber.DecodeInt(c.Content)))
		case 6:
			set(c, "protocol", "OCTET STRING", protoText(c.Content))
		case 8:
			set(c, "source", "OCTET STRING", ipText(c.Content))
		case 9:
			set(c, "destination", "OCTET STRING", ipText(c.Content))
		}
	}
}

func annotateUDPInfo(n *ber.Node) {
	for _, c := range n.Children {
		switch c.TagNum {
		case 0:
			set(c, "sourcePort", "OCTET STRING", fmt.Sprintf("%d", ber.DecodeInt(c.Content)))
		case 1:
			v := ber.DecodeInt(c.Content)
			set(c, "destinationPort", "OCTET STRING", fmt.Sprintf("%d%s", v, ipstack.PortHint(int(v))))
		case 2:
			set(c, "length", "OCTET STRING", fmt.Sprintf("%d", ber.DecodeInt(c.Content)))
		case 3:
			set(c, "checkSum", "OCTET STRING", fmt.Sprintf("0x%s", hexPlain(c.Content)))
		}
	}
}

func annotateTCPInfo(n *ber.Node) {
	for _, c := range n.Children {
		switch c.TagNum {
		case 0:
			set(c, "sourcePort", "OCTET STRING", fmt.Sprintf("%d", ber.DecodeInt(c.Content)))
		case 1:
			v := ber.DecodeInt(c.Content)
			set(c, "destinationPort", "OCTET STRING", fmt.Sprintf("%d%s", v, ipstack.PortHint(int(v))))
		case 2:
			set(c, "sequenceNumber", "OCTET STRING", fmt.Sprintf("%d", ber.DecodeInt(c.Content)))
		case 3:
			set(c, "ackNumber", "OCTET STRING", fmt.Sprintf("%d", ber.DecodeInt(c.Content)))
		case 4:
			v, bits := bitString(c.Content)
			set(c, "dataOffset", "BIT STRING", fmt.Sprintf("%d words (%d bytes), %d bits", v, v*4, bits))
		case 5:
			v, bits := bitString(c.Content)
			set(c, "controlBits", "BIT STRING", fmt.Sprintf("%s, %d bits", ipstack.TCPFlagsText(byte(v)), bits))
		case 6:
			set(c, "windowSize", "OCTET STRING", fmt.Sprintf("%d", ber.DecodeInt(c.Content)))
		case 7:
			set(c, "checkSum", "OCTET STRING", fmt.Sprintf("0x%s", hexPlain(c.Content)))
		case 8:
			set(c, "urgentPointer", "OCTET STRING", fmt.Sprintf("%d", ber.DecodeInt(c.Content)))
		case 9:
			set(c, "options", "OCTET STRING", hexPreview(c.Content, 24))
		}
	}
}

// bitString decodes BIT STRING content (unused-bits octet + data) into its
// value, right-aligned, and the number of bits.
func bitString(b []byte) (v uint64, bits int) {
	if len(b) < 1 {
		return 0, 0
	}
	unused := int(b[0])
	v = ber.DecodeInt(b[1:]) >> unused
	return v, len(b[1:])*8 - unused
}

// annotateIPMMCC labels TS 102 232-5 IP multimedia CC and decodes the media
// packet in mMCCContents according to frameType.
func annotateIPMMCC(n *ber.Node) {
	n.Name, n.TypeName, n.Value = "iPMMCC", "IPMMCC", "TS 102 232-5"
	frame := uint64(frameIP) // absent frameType: treat as a full packet
	if f := ctx(n, 2); f != nil {
		frame = ber.DecodeInt(f.Content)
	}
	for _, c := range n.Children {
		switch c.TagNum {
		case 0:
			set(c, "iPMMCCObjId", "RELATIVE-OID", relOIDValue(c, "iPMMCC"))
		case 1:
			set(c, "mMCCContents", "OCTET STRING", fmt.Sprintf("%d bytes — intercepted media packet", len(c.Content)))
			switch frame {
			case 0: // ipFrame: all headers present
				decodePacket(c)
			case 2, 5: // rtpFrame, artificialRtpFrame: RTP without IP/UDP
				c.Children = append(c.Children, rtpNode(c.Content, c.ContentOffset()))
			}
		case 2:
			set(c, "frameType", "ENUMERATED", enumVal(c, frameType))
		case 3:
			set(c, "streamIdentifier", "OCTET STRING", ascii(c.Content))
		case 4:
			set(c, "mMCCprotocol", "ENUMERATED", enumVal(c, mmccProtocol))
		}
	}
}

// annotateIPMMIRI labels TS 102 232-5 IP multimedia IRI and decodes the
// signalling message it carries.
func annotateIPMMIRI(n *ber.Node) {
	n.Name, n.TypeName, n.Value = "iPMMIRI", "IPMMIRI", "TS 102 232-5"
	for _, c := range n.Children {
		switch c.TagNum {
		case 0:
			set(c, "iPMMIRIObjId", "RELATIVE-OID", relOIDValue(c, "iPMMIRI"))
		case 1: // iPMMIRIContents [1] CHOICE -> explicit
			c.Name, c.TypeName, c.Value = "iPMMIRIContents", "IPIRIContents", "CHOICE (explicit [1])"
			if in := first(c); in != nil {
				annotateIPIRIContents(in)
			}
		case 2:
			c.Name, c.TypeName = "targetLocation", "Location"
		case 3:
			c.Name, c.TypeName = "additionalSignalling", "SEQUENCE OF AdditionalSignalling"
		}
	}
}

func annotateIPIRIContents(n *ber.Node) {
	switch n.TagNum {
	case 0, 5, 7: // original packets, including IP and UDP/TCP headers
		names := map[int]string{0: "originalIPMMMessage", 5: "iRIOnlyOriginalIPMMMessage", 7: "iRIOnlyRTPPacket"}
		set(n, names[n.TagNum], "OCTET STRING", fmt.Sprintf("%d bytes — intercepted packet", len(n.Content)))
		decodePacket(n)
	case 1, 6:
		name := map[int]string{1: "sIPMessage", 6: "iRIOnlySIPMessage"}[n.TagNum]
		n.Name, n.TypeName, n.Value = name, "SIPMessage", ""
		annotateSIPMessage(n)
	case 2:
		n.Name, n.TypeName = "h323Message", "H323Message"
	case 3:
		n.Name, n.TypeName = "nationalIPMMIRIParameters", "NationalIPMMIRIParameters"
	case 4:
		set(n, "xCAPMessage", "OCTET STRING", fmt.Sprintf("%d bytes", len(n.Content)))
	}
}

func annotateSIPMessage(n *ber.Node) {
	for _, c := range n.Children {
		switch c.TagNum {
		case 0:
			c.Name, c.TypeName = "iPSourceAddress", "IPAddress"
			annotateIPAddress(c)
		case 1:
			c.Name, c.TypeName = "iPDestinationAddress", "IPAddress"
			annotateIPAddress(c)
		case 2:
			set(c, "sIPContent", "OCTET STRING", fmt.Sprintf("%d bytes — SIP message", len(c.Content)))
			if sip.LooksLikeMessage(c.Content) {
				c.Children = append(c.Children, sipNode(c.Content, c.ContentOffset()))
			}
		}
	}
}

// annotateIPAddress labels a TS 102 232-1 IPAddress and puts the address in
// the node's own value.
func annotateIPAddress(n *ber.Node) {
	for _, c := range n.Children {
		switch c.TagNum {
		case 1:
			set(c, "iP-type", "ENUMERATED", enumVal(c, ipType))
		case 2: // iP-value [2] CHOICE -> explicit
			c.Name, c.TypeName, c.Value = "iP-value", "IP-value", "CHOICE (explicit [2])"
			switch v := first(c); {
			case v != nil && v.TagNum == 1:
				set(v, "iPBinaryAddress", "OCTET STRING", ipText(v.Content))
				n.Value = v.Value
			case v != nil && v.TagNum == 2:
				set(v, "iPTextAddress", "IA5String", ascii(v.Content))
				n.Value = v.Value
			}
		case 3:
			set(c, "iP-assignment", "ENUMERATED", enumVal(c, ipAssignment))
		case 4:
			set(c, "iPv6PrefixLength", "INTEGER", fmt.Sprintf("%d", ber.DecodeInt(c.Content)))
		case 5:
			set(c, "iPv4SubnetMask", "OCTET STRING", ipText(c.Content))
		}
	}
}

func rtpNode(b []byte, off int) *ber.Node {
	return &ber.Node{Raw: true, Offset: off, Length: len(b), Name: "RTP packet", TypeName: "RFC 3550",
		Value: rtp.Summary(b), Children: rtp.DecodeNodes(b, off)}
}

func sipNode(b []byte, off int) *ber.Node {
	return &ber.Node{Raw: true, Offset: off, Length: len(b), Name: "SIP message", TypeName: "RFC 3261",
		Value: sip.Summary(b), Children: sip.DecodeNodes(b, off)}
}

// decodePacket parses an OCTET STRING holding an IP packet (iPPackets,
// mMCCContents, originalIPMMMessage, …) as IPv4/UDP or IPv4/TCP, then decodes
// the payload as DNS (port 53), SIP (port 5060), RTP (by header heuristic) or
// HTTP, and attaches the decoded layers as children, with absolute offsets for
// byte highlighting.
func decodePacket(pk *ber.Node) {
	base := pk.ContentOffset()
	ipNodes, tr, payloadOff, payload := ipstack.DecodeNodes(pk.Content, base)
	pk.Children = append(pk.Children, ipNodes...)
	if len(payload) == 0 {
		return
	}
	var wrap *ber.Node
	switch {
	case tr.Proto == 17 && tr.HasPort(53):
		wrap = &ber.Node{Name: "DNS message", TypeName: "RFC 1035", Value: dnsSummary(payload),
			Children: dns.DecodeNodes(payload, payloadOff)}
	case tr.HasPort(5060) && sip.LooksLikeMessage(payload):
		pk.Children = append(pk.Children, sipNode(payload, payloadOff))
		return
	case tr.Proto == 17 && rtp.LooksLikeRTP(payload):
		pk.Children = append(pk.Children, rtpNode(payload, payloadOff))
		return
	case tr.Proto == 6 && httpmsg.LooksLikeRequest(payload):
		wrap = &ber.Node{Name: "HTTP request", TypeName: "RFC 9112", Value: httpmsg.Summary(payload),
			Children: httpmsg.DecodeNodes(payload, payloadOff)}
	case tr.Proto == 6 && httpmsg.LooksLikeResponse(payload):
		wrap = &ber.Node{Name: "HTTP response", TypeName: "RFC 9112", Value: httpmsg.Summary(payload),
			Children: httpmsg.DecodeNodes(payload, payloadOff)}
	default:
		wrap = &ber.Node{Name: "transport payload", TypeName: "bytes", Value: fmt.Sprintf("%d bytes", len(payload))}
	}
	wrap.Raw, wrap.Offset, wrap.Length = true, payloadOff, len(payload)
	pk.Children = append(pk.Children, wrap)
}

func dnsSummary(b []byte) string {
	nodes := dns.DecodeNodes(b, 0)
	for _, n := range nodes {
		if strings.HasPrefix(n.Name, "question") {
			return n.Value
		}
	}
	return fmt.Sprintf("%d bytes", len(b))
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func ctx(n *ber.Node, tag int) *ber.Node {
	for _, c := range n.Children {
		if c.Class == ber.Context && c.TagNum == tag {
			return c
		}
	}
	return nil
}

func first(n *ber.Node) *ber.Node {
	if len(n.Children) > 0 {
		return n.Children[0]
	}
	return nil
}

func set(n *ber.Node, name, typ, val string) {
	n.Name, n.TypeName, n.Value = name, typ, val
}

// fillGaps gives any node left unlabelled a sensible generic description so the
// tree never shows blanks, even for PDUs this annotator doesn't model.
func fillGaps(n *ber.Node) {
	if n.Name == "" {
		if n.Raw {
			n.Name = "field"
		} else if n.Constructed {
			n.Name, n.TypeName = "constructed", n.TagString()
		} else {
			n.Name, n.TypeName = "value", n.TagString()
			if n.Value == "" {
				n.Value = hexPreview(n.Content, 24)
			}
		}
	}
	if !n.Raw && !n.Constructed && n.Value == "" {
		n.Value = hexPreview(n.Content, 24)
	}
	for _, c := range n.Children {
		fillGaps(c)
	}
}

var (
	tsQualifier = map[uint64]string{0: "unknown", 1: "timeOfInterception", 2: "timeOfMediation", 3: "timeOfAggregation"}
	payloadDir  = map[uint64]string{0: "fromTarget", 1: "toTarget", 2: "indeterminate", 3: "combined", 4: "notapplicable"}
	iriType     = map[uint64]string{1: "iRI-Begin", 2: "iRI-End", 3: "iRI-Continue", 4: "iRI-Report"}

	frameType = map[uint64]string{0: "ipFrame", 1: "udpFrame", 2: "rtpFrame", 3: "audioFrame", 4: "tcpFrame",
		5: "artificialRtpFrame", 6: "udptlFrame", 7: "msrpFrame"}
	mmccProtocol = map[uint64]string{0: "rTP", 1: "mSRP", 2: "uDPTL"}
	ipType       = map[uint64]string{0: "iPV4", 1: "iPV6"}
	ipAssignment = map[uint64]string{1: "static", 2: "dynamic", 3: "notKnown"}
)

func enumVal(n *ber.Node, m map[uint64]string) string {
	v := ber.DecodeInt(n.Content)
	if name, ok := m[v]; ok {
		return fmt.Sprintf("%s (%d)", name, v)
	}
	return fmt.Sprintf("%d", v)
}

// oidValue labels li-psDomainId for any genHeader version, so captures from
// older (e.g. v31) and newer (v43) mediation both read clearly.
func oidValue(n *ber.Node) string {
	d := ber.DecodeOID(n.Content)
	if v, ok := strings.CutPrefix(d, "0.4.0.2.2.5.1."); ok && !strings.Contains(v, ".") {
		return d + "  (ETSI LI li-psDomainId, genHeader v" + v + ")"
	}
	return d
}

// relOIDValue labels TS 102 232-3 object IDs {li-ps(5) iPAccess(3) vN type}
// and TS 102 232-5 ones {li-ps(5) iPMultimedia(5) vN type} for any module
// version.
func relOIDValue(n *ber.Node, which string) string {
	d := ber.DecodeRelOID(n.Content)
	parts := strings.Split(d, ".")
	if len(parts) != 4 || parts[0] != "5" {
		return d
	}
	label := map[string]struct{ module, kind, typ string }{
		"iPCC":      {"3", "iPAccess", "cC"},
		"iPIRIOnly": {"3", "iPAccess", "iRIOnly"},
		"iPMMCC":    {"5", "iPMultimedia", "cC"},
		"iPMMIRI":   {"5", "iPMultimedia", "iRI"},
	}[which]
	if parts[1] != label.module {
		return d
	}
	return d + "  (li-ps." + label.kind + ".v" + parts[2] + "." + label.typ + ")"
}

func ascii(b []byte) string {
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return hexPreview(b, 24)
		}
	}
	return string(b)
}

func ipText(b []byte) string {
	if len(b) == 4 {
		return net.IP(b).String()
	}
	return hexPreview(b, 24)
}

func protoText(b []byte) string {
	if len(b) == 1 {
		switch b[0] {
		case 6:
			return "TCP (6)"
		case 17:
			return "UDP (17)"
		}
		return fmt.Sprintf("%d", b[0])
	}
	return hexPreview(b, 8)
}

func hexPlain(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		fmt.Fprintf(&sb, "%02x", c)
	}
	return sb.String()
}

func hexPreview(b []byte, max int) string {
	var parts []string
	for i, c := range b {
		if i >= max {
			parts = append(parts, "…")
			break
		}
		parts = append(parts, fmt.Sprintf("%02x", c))
	}
	return strings.Join(parts, " ")
}
