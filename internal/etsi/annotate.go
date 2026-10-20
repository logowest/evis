package etsi

import (
	"fmt"
	"net"
	"strings"

	"evis/internal/ber"
	"evis/internal/dns"
	"evis/internal/ipstack"
)

// Annotate walks decoded top-level nodes as ETSI PS-PDUs, filling in field
// names, ASN.1 types, human-readable values, field descriptions (Note), and —
// for a CC payload — the nested IPv4/UDP/DNS PDUs found inside iPPackets.
func Annotate(nodes []*ber.Node) {
	for _, n := range nodes {
		annotatePSPDU(n)
	}
}

func annotatePSPDU(n *ber.Node) {
	n.Name, n.TypeName = "PS-PDU", "SEQUENCE"
	n.Value = "ETSI TS 102 232-1 handover PDU"
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
			if ipcc := first(c); ipcc != nil && ipcc.TagNum == 2 {
				annotateIPCC(ipcc)
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
			if in := first(c); in != nil && in.TagNum == 3 {
				annotateIPIRIOnly(in)
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
			if u := first(c); u != nil && u.TagNum == 2 {
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
			hint := ""
			if v == 53 {
				hint = " (domain)"
			}
			set(c, "destinationPort", "OCTET STRING", fmt.Sprintf("%d%s", v, hint))
		case 2:
			set(c, "length", "OCTET STRING", fmt.Sprintf("%d", ber.DecodeInt(c.Content)))
		case 3:
			set(c, "checkSum", "OCTET STRING", fmt.Sprintf("0x%s", hexPlain(c.Content)))
		}
	}
}

// decodePacket parses the iPPackets OCTET STRING as IPv4/UDP/DNS and attaches
// the decoded layers as children, with absolute offsets for byte highlighting.
func decodePacket(pk *ber.Node) {
	base := pk.ContentOffset()
	ipNodes, payloadOff, payload := ipstack.DecodeNodes(pk.Content, base)
	pk.Children = append(pk.Children, ipNodes...)
	if len(payload) > 0 {
		dnsNodes := dns.DecodeNodes(payload, payloadOff)
		wrap := &ber.Node{Raw: true, Offset: payloadOff, Length: len(payload),
			Name: "DNS message", TypeName: "RFC 1035", Value: dnsSummary(payload), Children: dnsNodes}
		pk.Children = append(pk.Children, wrap)
	}
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
// for any module version.
func relOIDValue(n *ber.Node, which string) string {
	d := ber.DecodeRelOID(n.Content)
	parts := strings.Split(d, ".")
	if len(parts) != 4 || parts[0] != "5" || parts[1] != "3" {
		return d
	}
	switch which {
	case "iPCC":
		return d + "  (li-ps.iPAccess.v" + parts[2] + ".cC)"
	case "iPIRIOnly":
		return d + "  (li-ps.iPAccess.v" + parts[2] + ".iRIOnly)"
	}
	return d
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
