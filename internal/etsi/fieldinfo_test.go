package etsi

import (
	"testing"

	"evis/internal/ber"
)

// Every node in the generated samples should carry a tooltip description, so
// a field added to annotate.go without a matching fieldNotes entry fails here.
func TestEveryNodeDescribed(t *testing.T) {
	m, s := DefaultMeta(), DefaultScenario()
	for name, b := range map[string][]byte{
		"cc":     BuildCC(m, s),
		"iri":    BuildIRIOnly(m, s),
		"iri+cc": BuildIRIAndCC(m, s),
	} {
		nodes, err := ber.Parse(b)
		if err != nil {
			t.Fatalf("%s: parse: %v", name, err)
		}
		Annotate(nodes)
		var walk func(n *ber.Node)
		walk = func(n *ber.Node) {
			if n.Note == "" {
				t.Errorf("%s: %q (%s at @%d) has no description", name, n.Name, n.TypeName, n.Offset)
			}
			for _, c := range n.Children {
				walk(c)
			}
		}
		for _, n := range nodes {
			walk(n)
		}
	}
}
