package etsi

import (
	"fmt"
	"strings"

	"evis/internal/ber"
	"evis/internal/httpmsg"
	"evis/internal/ipstack"
	"evis/internal/sip"
	"evis/internal/tcpreasm"
)

// TCP reassembly across PS-PDUs.
//
// Each CC PS-PDU carries one IP packet, so an HTTP or SIP message longer than
// one TCP segment is spread over several PDUs. After every PDU has been
// annotated on its own, reassembleTCP groups the TCP packets by intercept
// (LIID, network identifier, CIN) and connection direction, reassembles each
// stream, splits it into messages and decodes every message that spans more
// than one segment. The result is attached as a "reassembled …" node under the
// packet of the PDU that completes it.
//
// Highlighting stays one contiguous range per node: a field that continues
// into a later segment highlights the part inside its first segment, and its
// tooltip names the PDUs it continues into. The "segments" child lists every
// segment with its own highlight.

// flowSeg ties a reassembly segment back to the tree.
type flowSeg struct {
	pdu       int       // PS-PDU index, 0-based
	container *ber.Node // node holding the IP packet (iPPackets, mMCCContents, …)
	payload   *ber.Node // decoded TCP payload node under container; nil if none
}

type flow struct {
	segs []tcpreasm.Segment
	refs []flowSeg
}

func reassembleTCP(pdus []*ber.Node) {
	flows := map[string]*flow{}
	var keys []string // first-seen order, so output is deterministic
	for i, pdu := range pdus {
		id := interceptID(pdu)
		eachTCPPacket(pdu, func(container *ber.Node) {
			_, tr, off, payload := ipstack.DecodeNodes(container.Content, container.ContentOffset())
			if tr.Proto != 6 || tr.SrcPort == 0 {
				return
			}
			key := fmt.Sprintf("%s|%s:%d>%s:%d", id, tr.SrcIP, tr.SrcPort, tr.DstIP, tr.DstPort)
			f := flows[key]
			if f == nil {
				f = &flow{}
				flows[key] = f
				keys = append(keys, key)
			}
			f.segs = append(f.segs, tcpreasm.Segment{Seq: tr.Seq, SYN: tr.Flags&ipstack.TCPSyn != 0,
				Payload: payload, FileOff: off, Ref: i})
			f.refs = append(f.refs, flowSeg{pdu: i, container: container, payload: payloadNode(container, off, len(payload))})
		})
	}
	for _, k := range keys {
		flows[k].process()
	}
}

// interceptID identifies the intercept and session a PDU belongs to.
func interceptID(pdu *ber.Node) string {
	var parts []string
	var walk func(n *ber.Node)
	walk = func(n *ber.Node) {
		switch n.Name {
		case "lawfulInterceptionIdentifier", "operatorIdentifier", "networkElementIdentifier",
			"communicationIdentityNumber":
			parts = append(parts, n.Value)
		}
		for _, c := range n.Children {
			walk(c)
		}
	}
	if h := ctx(pdu, 1); h != nil {
		walk(h)
	}
	return strings.Join(parts, "/")
}

// eachTCPPacket calls fn for every node whose decoded children include a TCP
// header, i.e. every OCTET STRING that decodePacket expanded into IPv4/TCP.
func eachTCPPacket(n *ber.Node, fn func(*ber.Node)) {
	for _, c := range n.Children {
		if c.Raw && c.Name == "TCP header" {
			fn(n)
			return
		}
	}
	for _, c := range n.Children {
		if !c.Raw {
			eachTCPPacket(c, fn)
		}
	}
}

func payloadNode(container *ber.Node, off, length int) *ber.Node {
	if length == 0 {
		return nil
	}
	for _, c := range container.Children {
		if c.Raw && c.Offset == off && c.Name != "IPv4 header" && c.Name != "TCP header" {
			return c
		}
	}
	return nil
}

func (f *flow) process() {
	res := tcpreasm.Reassemble(f.segs)
	for i, st := range res.Status {
		p := f.refs[i].payload
		switch {
		case p == nil:
		case st == tcpreasm.Retransmitted:
			p.Value += " — retransmission: bytes already seen, not used"
		case st == tcpreasm.Trimmed:
			p.Value += " — overlaps earlier data; the first copy is used"
		}
	}
	for ci, c := range res.Chunks {
		missing := res.Lead
		if ci > 0 {
			missing = res.Gaps[ci-1].Len
		}
		if p := f.refs[c.Spans[0].Seg].payload; missing > 0 && p != nil {
			p.Value += fmt.Sprintf(" — follows %d missing bytes", missing)
		}
		gapAfter := 0
		if ci < len(res.Gaps) {
			gapAfter = res.Gaps[ci].Len
		}
		for off := 0; off < len(c.Data); {
			d, kind, ok := dialectFor(c.Data[off:])
			if !ok {
				break // mid-message data (e.g. after a gap): nothing to frame
			}
			n, complete := d.MessageLen(c.Data[off:])
			f.message(c, off, n, complete, gapAfter, d, kind)
			off += n
			if !complete {
				break
			}
		}
	}
}

func dialectFor(b []byte) (d httpmsg.Dialect, kind string, ok bool) {
	switch {
	case httpmsg.HTTP.LooksLikeRequest(b):
		return httpmsg.HTTP, "HTTP request", true
	case httpmsg.HTTP.LooksLikeResponse(b):
		return httpmsg.HTTP, "HTTP response", true
	case sip.Dialect.LooksLikeStart(b):
		return sip.Dialect, "SIP message", true
	}
	return d, "", false
}

// message decodes the message at chunk offset off (n bytes) if it spans more
// than one segment, or does not line up with a segment (pipelining), since
// otherwise the per-packet decode already shows it in full.
func (f *flow) message(c tcpreasm.Chunk, off, n int, complete bool, gapAfter int, d httpmsg.Dialect, kind string) {
	fileOff, contiguous, spans := c.Locate(off, n)
	if len(spans) == 0 {
		return
	}
	if len(spans) == 1 && spans[0].StreamOff == c.StreamOff+off && spans[0].Len == n {
		return
	}
	first, last := spans[0], spans[0]
	for _, sp := range spans {
		if sp.Ref < first.Ref {
			first = sp
		}
		if sp.Ref > last.Ref {
			last = sp
		}
	}
	msg := c.Data[off : off+n]

	root := &ber.Node{Raw: true, Offset: fileOff, Length: contiguous, Name: "reassembled " + kind,
		TypeName: "TCP stream", Value: fmt.Sprintf("%s — %d bytes from %d segments, %s",
			httpmsg.Summary(msg), n, len(spans), pduRange(first.Ref, last.Ref))}
	if !complete {
		if gapAfter > 0 {
			root.Value += fmt.Sprintf(", cut off by %d missing bytes", gapAfter)
		} else {
			root.Value += ", runs to the end of the captured stream"
		}
	}

	segs := &ber.Node{Raw: true, Offset: fileOff, Length: contiguous, Name: "segments", TypeName: "TCP",
		Value: fmt.Sprintf("%d segments in stream order", len(spans))}
	for _, sp := range spans {
		// Only the part of the span inside this message.
		lo := max(sp.StreamOff, c.StreamOff+off)
		hi := min(sp.StreamOff+sp.Len, c.StreamOff+off+n)
		segs.Children = append(segs.Children, &ber.Node{Raw: true, Offset: sp.FileOff + lo - sp.StreamOff,
			Length: hi - lo, Name: "segment", TypeName: "TCP payload",
			Value: fmt.Sprintf("PS-PDU #%d, stream bytes %d–%d (%d bytes)", sp.Ref+1, lo, hi-1, hi-lo)})
	}

	fields := d.DecodeNodes(msg, 0)
	continues := map[*ber.Node]string{}
	var remap func(n *ber.Node)
	remap = func(n *ber.Node) {
		start, length := off+n.Offset, n.Length
		if length == 0 {
			fo, _, _ := c.Locate(max(start-1, 0), 1)
			n.Offset = fo + min(start, 1)
		} else {
			fo, cont, sp := c.Locate(start, length)
			n.Offset, n.Length = fo, cont
			lo, hi := sp[0].Ref, sp[0].Ref
			for _, s := range sp {
				lo, hi = min(lo, s.Ref), max(hi, s.Ref)
			}
			if lo != hi {
				continues[n] = fmt.Sprintf(" This field spans %s; only the part in PS-PDU #%d is highlighted.",
					pduRange(lo, hi), sp[0].Ref+1)
			}
		}
		for _, ch := range n.Children {
			remap(ch)
		}
	}
	for _, fn := range fields {
		remap(fn)
	}
	root.Children = append([]*ber.Node{segs}, fields...)
	if !complete && gapAfter > 0 {
		end, _, _ := c.Locate(len(c.Data)-1, 1)
		root.Children = append(root.Children, &ber.Node{Raw: true, Offset: end + 1, Name: "missing data",
			TypeName: "gap", Value: fmt.Sprintf("%d bytes not captured (stream bytes %d–%d)",
				gapAfter, c.StreamOff+len(c.Data), c.StreamOff+len(c.Data)+gapAfter-1)})
	}

	describe(root)
	for n, note := range continues {
		n.Note += note
	}

	f.refs[last.Seg].container.Children = append(f.refs[last.Seg].container.Children, root)
	for i, sp := range spans {
		p := f.refs[sp.Seg].payload
		if p == nil {
			continue
		}
		if i == 0 && sp.StreamOff == c.StreamOff+off {
			p.Value += fmt.Sprintf(" — first of %d segments; reassembled in PS-PDU #%d", len(spans), last.Ref+1)
		} else {
			p.Value += fmt.Sprintf(" — part of the %s reassembled in PS-PDU #%d", kind, last.Ref+1)
		}
	}
}

// pduRange formats 0-based PDU indexes as "PS-PDU #3" or "PS-PDUs #3–#5".
func pduRange(first, last int) string {
	if first == last {
		return fmt.Sprintf("PS-PDU #%d", first+1)
	}
	return fmt.Sprintf("PS-PDUs #%d–#%d", first+1, last+1)
}
