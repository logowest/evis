package rtp

import "testing"

func TestBuildDecode(t *testing.T) {
	b := Build(Packet{Marker: true, PayloadType: 0, Seq: 7, Timestamp: 1120, SSRC: 0x5eed1e55,
		CSRC: []uint32{0xc0ffee01}, Payload: make([]byte, 160)})
	if !LooksLikeRTP(b) {
		t.Fatal("built packet not recognised as RTP")
	}
	nodes := DecodeNodes(b, 100)
	want := []struct {
		name   string
		offset int
		length int
	}{{"RTP header", 100, 16}, {"media payload", 116, 160}}
	if len(nodes) != len(want) {
		t.Fatalf("got %d top-level nodes, want %d", len(nodes), len(want))
	}
	for i, w := range want {
		if n := nodes[i]; n.Name != w.name || n.Offset != w.offset || n.Length != w.length {
			t.Errorf("node %d = %q @%d+%d, want %q @%d+%d", i, n.Name, n.Offset, n.Length, w.name, w.offset, w.length)
		}
	}
	if got := nodes[0].Children[1].Value; got != "M=1 PT=0 (PCMU)" {
		t.Errorf("marker/payloadType = %q", got)
	}
	if got := nodes[0].Children[5].Value; got != "0xc0ffee01" {
		t.Errorf("csrc[0] = %q", got)
	}
}

// A hand-built packet with a one-byte-header extension and 4 octets of padding.
func TestExtensionAndPadding(t *testing.T) {
	b := []byte{
		0xb0, 0x60, 0x00, 0x01, 0x00, 0x00, 0x03, 0x20, 0x11, 0x22, 0x33, 0x44, // V=2 P=1 X=1, PT 96
		0xbe, 0xde, 0x00, 0x01, 0x10, 0x7f, 0x00, 0x00, // extension: 1 word
		0xaa, 0xbb, 0xcc, // payload
		0x00, 0x00, 0x00, 0x04, // padding, count 4
	}
	var names []string
	var lens []int
	for _, n := range DecodeNodes(b, 0) {
		names, lens = append(names, n.Name), append(lens, n.Length)
	}
	want := []string{"RTP header", "header extension", "media payload", "padding"}
	wantLen := []int{12, 8, 3, 4}
	for i := range want {
		if i >= len(names) || names[i] != want[i] || lens[i] != wantLen[i] {
			t.Fatalf("got %v %v, want %v %v", names, lens, want, wantLen)
		}
	}
}

func TestNotRTP(t *testing.T) {
	for name, b := range map[string][]byte{
		"short":   {0x80, 0x00},
		"version": append([]byte{0x40}, make([]byte, 11)...),
		"rtcp sr": append([]byte{0x80, 200}, make([]byte, 26)...),
		"cc":      append([]byte{0x8f}, make([]byte, 11)...), // claims 15 CSRCs
	} {
		if LooksLikeRTP(b) {
			t.Errorf("%s: recognised as RTP", name)
		}
	}
}
