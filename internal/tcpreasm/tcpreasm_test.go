package tcpreasm

import (
	"reflect"
	"testing"
)

// seg makes a segment whose payload sits at file offset fileOff.
func seg(seq uint32, data string, fileOff int) Segment {
	return Segment{Seq: seq, Payload: []byte(data), FileOff: fileOff, Ref: fileOff}
}

func chunks(r Result) []string {
	var out []string
	for _, c := range r.Chunks {
		out = append(out, string(c.Data))
	}
	return out
}

func TestReassemble(t *testing.T) {
	for _, tc := range []struct {
		name   string
		segs   []Segment
		chunks []string
		gaps   []Gap
		status []Status
		lead   int
	}{
		{"in order", []Segment{seg(100, "abc", 0), seg(103, "def", 10)},
			[]string{"abcdef"}, nil, []Status{Used, Used}, 0},
		{"out of order", []Segment{seg(103, "def", 0), seg(100, "abc", 10)},
			[]string{"abcdef"}, nil, []Status{Used, Used}, 0},
		{"retransmission", []Segment{seg(100, "abc", 0), seg(100, "abc", 10), seg(103, "def", 20)},
			[]string{"abcdef"}, nil, []Status{Used, Retransmitted, Used}, 0},
		{"partial overlap, first copy wins", []Segment{seg(100, "abcd", 0), seg(102, "XXef", 10)},
			[]string{"abcdef"}, nil, []Status{Used, Trimmed}, 0},
		{"gap", []Segment{seg(100, "abc", 0), seg(106, "ghi", 10)},
			[]string{"abc", "ghi"}, []Gap{{3, 3}}, []Status{Used, Used}, 0},
		{"syn makes leading loss visible",
			[]Segment{{Seq: 99, SYN: true}, seg(105, "fgh", 0)},
			[]string{"fgh"}, nil, []Status{Used, Used}, 5},
		{"wraparound", []Segment{seg(0xfffffffe, "ab", 0), seg(0, "cd", 10)},
			[]string{"abcd"}, nil, []Status{Used, Used}, 0},
		{"empty payloads ignored", []Segment{seg(100, "", 0), seg(100, "abc", 10)},
			[]string{"abc"}, nil, []Status{Used, Used}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := Reassemble(tc.segs)
			if got := chunks(r); !reflect.DeepEqual(got, tc.chunks) {
				t.Errorf("chunks = %q, want %q", got, tc.chunks)
			}
			if !reflect.DeepEqual(r.Gaps, tc.gaps) {
				t.Errorf("gaps = %v, want %v", r.Gaps, tc.gaps)
			}
			if !reflect.DeepEqual(r.Status, tc.status) {
				t.Errorf("status = %v, want %v", r.Status, tc.status)
			}
			if r.Lead != tc.lead {
				t.Errorf("lead = %d, want %d", r.Lead, tc.lead)
			}
		})
	}
}

// Spans must point at the file bytes each stream byte came from, including
// after an overlap trim.
func TestSpansAndLocate(t *testing.T) {
	file := []byte("..abcd....XXef..")
	r := Reassemble([]Segment{seg(100, "abcd", 2), seg(102, "XXef", 10)})
	c := r.Chunks[0]
	for _, sp := range c.Spans {
		got := string(file[sp.FileOff : sp.FileOff+sp.Len])
		want := string(c.Data[sp.StreamOff-c.StreamOff : sp.StreamOff-c.StreamOff+sp.Len])
		if got != want {
			t.Errorf("span %+v: file has %q, stream has %q", sp, got, want)
		}
	}
	// "cdef" starts in the first segment and continues in the second.
	off, n, spans := c.Locate(2, 4)
	if off != 4 || n != 2 || len(spans) != 2 {
		t.Errorf("Locate(2,4) = %d, %d, %d spans; want 4, 2, 2 spans", off, n, len(spans))
	}
	if off, n, spans := c.Locate(4, 2); off != 12 || n != 2 || len(spans) != 1 {
		t.Errorf("Locate(4,2) = %d, %d, %d spans; want 12, 2, 1 span", off, n, len(spans))
	}
}
