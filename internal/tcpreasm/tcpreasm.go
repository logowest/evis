// Package tcpreasm reassembles one direction of a TCP connection from captured
// segments. It orders segments by sequence number, drops retransmitted bytes,
// trims overlaps and reports gaps, and records where every reassembled byte
// sits in the original file so decoded fields can still be highlighted.
package tcpreasm

import "sort"

// Segment is one captured TCP segment of a single flow direction.
type Segment struct {
	Seq     uint32 // TCP sequence number of the first payload byte
	SYN     bool   // the SYN consumes one sequence number before the data
	Payload []byte
	FileOff int // absolute file offset of Payload[0]
	Ref     int // caller's reference, e.g. the PS-PDU index; copied into Spans
}

// Span maps a contiguous run of stream bytes back to the file.
type Span struct {
	StreamOff int // offset in the stream (relative sequence space)
	FileOff   int
	Len       int
	Seg       int // index into the Segments passed to Reassemble
	Ref       int
}

// Chunk is a run of stream bytes with no gaps.
type Chunk struct {
	StreamOff int
	Data      []byte
	Spans     []Span // in stream order, covering Data exactly
}

// Gap is a range of stream bytes that no segment carried.
type Gap struct {
	StreamOff, Len int
}

// Status says what happened to each input segment.
type Status int

const (
	Used          Status = iota // all payload bytes went into the stream
	Trimmed                     // some bytes were already covered by earlier segments
	Retransmitted               // every byte was already covered; nothing used
)

// Result is a reassembled flow direction.
type Result struct {
	Chunks []Chunk  // in stream order
	Gaps   []Gap    // Gaps[i] lies between Chunks[i] and Chunks[i+1]
	Lead   int      // bytes missing between the SYN and the first chunk (0 if no SYN seen)
	Status []Status // per input segment
}

// Reassemble orders segs by sequence number and joins their payloads. When
// segments overlap, the copy that appears first in segs (file order) wins.
// Sequence numbers are taken relative to the SYN when one is present,
// otherwise to the lowest sequence number seen, so wraparound is handled.
func Reassemble(segs []Segment) Result {
	res := Result{Status: make([]Status, len(segs))}
	if len(segs) == 0 {
		return res
	}

	// Pick the stream origin. Relative offsets use int32 differences, which is
	// correct for any capture spanning less than 2 GiB of sequence space.
	base, haveSYN := segs[0].Seq, false
	for _, s := range segs {
		if s.SYN {
			base, haveSYN = s.Seq+1, true
			break
		}
	}
	rel := make([]int, len(segs))
	for i, s := range segs {
		start := s.Seq
		if s.SYN {
			start++
		}
		rel[i] = int(int32(start - base))
	}
	if !haveSYN {
		lowest := rel[0]
		for _, r := range rel {
			lowest = min(lowest, r)
		}
		for i := range rel {
			rel[i] -= lowest
		}
	}

	order := make([]int, len(segs))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool { return rel[order[a]] < rel[order[b]] })

	cursor := 0 // next stream offset expected
	started := false
	var cur *Chunk
	for _, i := range order {
		s, r := segs[i], rel[i]
		if len(s.Payload) == 0 {
			continue
		}
		end := r + len(s.Payload)
		if started && end <= cursor {
			res.Status[i] = Retransmitted
			continue
		}
		switch {
		case !started:
			if r > 0 && haveSYN {
				res.Lead = r
			}
			res.Chunks = append(res.Chunks, Chunk{StreamOff: r})
			cursor, started = r, true
		case r > cursor:
			res.Gaps = append(res.Gaps, Gap{StreamOff: cursor, Len: r - cursor})
			res.Chunks = append(res.Chunks, Chunk{StreamOff: r})
			cursor = r
		}
		cur = &res.Chunks[len(res.Chunks)-1]
		skip := cursor - r // bytes at the front already in the stream
		if skip > 0 {
			res.Status[i] = Trimmed
		}
		cur.Spans = append(cur.Spans, Span{StreamOff: cursor, FileOff: s.FileOff + skip,
			Len: len(s.Payload) - skip, Seg: i, Ref: s.Ref})
		cur.Data = append(cur.Data, s.Payload[skip:]...)
		cursor = end
	}
	return res
}

// Locate maps a range of chunk bytes [off, off+length), with off relative to
// c.StreamOff, back to the file. It returns the file offset of the first byte,
// how many bytes are contiguous there (the part inside the first span), and the
// spans the range touches.
func (c Chunk) Locate(off, length int) (fileOff, contiguous int, spans []Span) {
	abs := c.StreamOff + off
	for _, sp := range c.Spans {
		if abs+length <= sp.StreamOff || abs >= sp.StreamOff+sp.Len {
			if length == 0 && abs == sp.StreamOff+sp.Len { // empty range at a span end
				return sp.FileOff + sp.Len, 0, []Span{sp}
			}
			continue
		}
		if len(spans) == 0 {
			d := max(abs-sp.StreamOff, 0)
			fileOff = sp.FileOff + d
			contiguous = min(length, sp.Len-d)
		}
		spans = append(spans, sp)
	}
	return fileOff, contiguous, spans
}
