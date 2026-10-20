package main

import (
	"fmt"
	"strings"

	"evis/internal/ber"
	"evis/internal/etsi"
)

// View is the model passed to the result fragment template.
type View struct {
	Source       string // e.g. "sample · CC payload" or "upload · capture.etsi"
	Summary      string // one-line human description
	Bytes        []byte
	Nodes        []*ber.Node
	Err          string
	ActiveSample string // e.g. "cc", "http-iri", "voip-both", or "" for an upload
}

// buildView parses+annotates bytes and derives a summary.
func buildView(source, active string, b []byte) View {
	v := View{Source: source, ActiveSample: active, Bytes: b}
	nodes, err := ber.Parse(b)
	v.Nodes = nodes
	if err != nil {
		v.Err = err.Error()
	}
	etsi.Annotate(nodes)
	v.Summary = summarise(nodes)
	return v
}

// summarise scans the annotated tree for the payload kind and DNS question.
func summarise(nodes []*ber.Node) string {
	var kinds []string
	seen := map[string]bool{}
	var dns string
	var walk func(n *ber.Node)
	walk = func(n *ber.Node) {
		kind := map[string]string{
			"iPPackets": "CC · content of communication",
			"iPIRIOnly": "IRI-only · packet headers",
			"iPMMCC":    "CC · multimedia",
			"iPMMIRI":   "IRI · multimedia signalling",
		}[n.Name]
		if kind != "" && !seen[kind] {
			seen[kind] = true
			kinds = append(kinds, kind)
		}
		if strings.HasPrefix(n.Name, "question") && dns == "" {
			dns = n.Value
		}
		for _, c := range n.Children {
			walk(c)
		}
	}
	for _, n := range nodes {
		walk(n)
	}
	kind := strings.Join(kinds, " + ")
	if kind == "" {
		kind = "unrecognised payload"
	}
	kind = fmt.Sprintf("%d PS-PDU(s) · %s", len(nodes), kind)
	if dns != "" {
		return kind + " — DNS query " + dns
	}
	return kind
}

// ---- Datastar expression helpers (kept out of the .templ for readability) ----

// hoverExpr sets the selection signals when a node is hovered.
func hoverExpr(off, length int) string {
	return fmt.Sprintf("o.value = %d; l.value = %d", off, length)
}

// byteClassExpr highlights hex byte i when it falls in the selected range.
func byteClassExpr(i int) string {
	return fmt.Sprintf("{hl: %d >= o.value && %d < o.value + l.value}", i, i)
}

func offLabel(row int) string { return fmt.Sprintf("%08x", row*16) }

func hexByte(b byte) string { return fmt.Sprintf("%02x", b) }

func asciiOf(b byte) string {
	if b < 0x20 || b > 0x7e {
		return "."
	}
	if b == ' ' {
		return " " // keep spacing visible
	}
	return string(rune(b))
}

// indent renders a depth marker string (purely decorative; CSS also indents).
func rowBytes(b []byte, row int) []int {
	start := row * 16
	end := start + 16
	if end > len(b) {
		end = len(b)
	}
	idx := make([]int, 0, 16)
	for i := start; i < end; i++ {
		idx = append(idx, i)
	}
	return idx
}

func numRows(n int) int { return (n + 15) / 16 }

func asciiRow(b []byte, row int) string {
	var sb strings.Builder
	for _, i := range rowBytes(b, row) {
		sb.WriteString(asciiOf(b[i]))
	}
	return sb.String()
}

func offInfo(n *ber.Node) string { return fmt.Sprintf("@%d +%d", n.Offset, n.TotalLen()) }

func hasKids(n *ber.Node) bool { return len(n.Children) > 0 }

func byteLen(v View) string     { return fmt.Sprintf("%d", len(v.Bytes)) }
func offLabelLen(v View) string { return fmt.Sprintf("%d bytes", len(v.Bytes)) }

// depthClass bounds the visual indent so very deep trees stay readable.
func depthClass(d int) string {
	if d > 10 {
		d = 10
	}
	return fmt.Sprintf("d%d", d)
}
