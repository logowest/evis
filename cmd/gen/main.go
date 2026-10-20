// Command gen writes ETSI TS 102 232 handover files for a single DNS request:
// one CC (content-of-communication) PDU carrying the DNS packet, one IRI-only
// PDU carrying the IPv4/UDP header fields, and a combined file holding both
// PDUs back to back. For each it emits the raw BER (.etsi) and an annotated
// hex dump (.hex).
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"evis/internal/ber"
	"evis/internal/etsi"
)

func main() {
	out := flag.String("out", "samples", "output directory")
	flag.Parse()

	if err := os.MkdirAll(*out, 0o755); err != nil {
		fail(err)
	}

	m := etsi.DefaultMeta()
	s := etsi.DefaultScenario()

	files := []struct {
		name  string
		bytes []byte
		desc  string
	}{
		{"dns-request-cc", etsi.BuildCC(m, s), "CC payload: full IPv4/UDP/DNS datagram as IPCC/iPPackets"},
		{"dns-request-iri-only", etsi.BuildIRIOnly(m, s), "IRI-only payload: IPv4+UDP header fields as IPIRIOnly"},
		{"dns-request-iri-cc", etsi.BuildIRIAndCC(m, s), "IRI + CC: IRI-only PS-PDU then CC PS-PDU in one file"},
	}

	for _, f := range files {
		etsiPath := filepath.Join(*out, f.name+".etsi")
		hexPath := filepath.Join(*out, f.name+".hex")
		if err := os.WriteFile(etsiPath, f.bytes, 0o644); err != nil {
			fail(err)
		}
		if err := os.WriteFile(hexPath, []byte(hexDump(f.bytes)), 0o644); err != nil {
			fail(err)
		}
		fmt.Printf("%-26s %4d bytes  %s\n", filepath.Base(etsiPath), len(f.bytes), f.desc)

		// Parse + annotate + print the PDU tree, as a built-in sanity check.
		nodes, err := ber.Parse(f.bytes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  warning: parse error: %v\n", err)
			continue
		}
		etsi.Annotate(nodes)
		for _, n := range nodes {
			printTree(n, 1)
		}
		fmt.Println()
	}
}

func printTree(n *ber.Node, depth int) {
	indent := strings.Repeat("  ", depth)
	tag := n.TagString()
	if tag != "" {
		tag += " "
	}
	line := fmt.Sprintf("%s%s%s", indent, tag, n.Name)
	if n.TypeName != "" {
		line += "  " + n.TypeName
	}
	if n.Value != "" {
		line += "  = " + n.Value
	}
	fmt.Println(line)
	for _, c := range n.Children {
		printTree(c, depth+1)
	}
}

func hexDump(b []byte) string {
	var sb strings.Builder
	for i := 0; i < len(b); i += 16 {
		fmt.Fprintf(&sb, "%08x  ", i)
		end := i + 16
		if end > len(b) {
			end = len(b)
		}
		for j := i; j < i+16; j++ {
			if j < end {
				fmt.Fprintf(&sb, "%02x ", b[j])
			} else {
				sb.WriteString("   ")
			}
			if j == i+7 {
				sb.WriteString(" ")
			}
		}
		sb.WriteString(" |")
		for j := i; j < end; j++ {
			c := b[j]
			if c < 0x20 || c > 0x7e {
				c = '.'
			}
			sb.WriteByte(c)
		}
		sb.WriteString("|\n")
	}
	return sb.String()
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "gen:", err)
	os.Exit(1)
}
