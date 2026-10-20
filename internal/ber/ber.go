// Package ber is a small, dependency-free BER/DER TLV toolkit, just enough to
// hand-build and inspect ETSI TS 102 232 handover PDUs.
//
// The ETSI LI ASN.1 modules are defined with "DEFINITIONS IMPLICIT TAGS", so
// almost every field is encoded with its context tag replacing the base type's
// universal tag (implicit tagging). The one twist is that a context tag applied
// to a CHOICE type is automatically EXPLICIT (X.680 30.6c): the context tag then
// *wraps* the full TLV of the selected alternative. The helpers below make both
// cases explicit at the call site: CPrim/CCons/CInt/... are implicit; CExplicit
// is the CHOICE wrapper.
package ber

import (
	"fmt"
	"time"
)

// Class is the ASN.1 tag class (top two bits of the identifier octet).
type Class uint8

const (
	Universal   Class = 0
	Application Class = 1
	Context     Class = 2
	Private     Class = 3
)

func (c Class) String() string {
	switch c {
	case Universal:
		return "UNIVERSAL"
	case Application:
		return "APPLICATION"
	case Context:
		return "CONTEXT"
	default:
		return "PRIVATE"
	}
}

// Universal tag numbers used in this project.
const (
	TagBoolean         = 1
	TagInteger         = 2
	TagBitString       = 3
	TagOctetString     = 4
	TagNull            = 5
	TagOID             = 6
	TagEnumerated      = 10
	TagUTF8String      = 12
	TagRelativeOID     = 13
	TagSequence        = 16
	TagSet             = 17
	TagPrintableString = 19
	TagIA5String       = 22
	TagUTCTime         = 23
	TagGeneralizedTime = 24
)

// ---------------------------------------------------------------------------
// Low-level TLV assembly
// ---------------------------------------------------------------------------

// encodeTag renders the identifier octet(s), supporting high-tag-number form.
func encodeTag(c Class, constructed bool, num int) []byte {
	b0 := byte(c) << 6
	if constructed {
		b0 |= 0x20
	}
	if num < 0x1f {
		return []byte{b0 | byte(num)}
	}
	// High tag number form: 0x1f, then base-128 big-endian, MSBs set except last.
	b0 |= 0x1f
	var tmp []byte
	n := num
	for {
		tmp = append([]byte{byte(n & 0x7f)}, tmp...)
		n >>= 7
		if n == 0 {
			break
		}
	}
	for i := 0; i < len(tmp)-1; i++ {
		tmp[i] |= 0x80
	}
	return append([]byte{b0}, tmp...)
}

// encodeLength renders a definite length (short or long form).
func encodeLength(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var tmp []byte
	for n > 0 {
		tmp = append([]byte{byte(n & 0xff)}, tmp...)
		n >>= 8
	}
	return append([]byte{0x80 | byte(len(tmp))}, tmp...)
}

// TLV builds one tag-length-value triple.
func TLV(c Class, constructed bool, num int, content []byte) []byte {
	out := encodeTag(c, constructed, num)
	out = append(out, encodeLength(len(content))...)
	return append(out, content...)
}

// Concat joins already-encoded TLVs (handy for building SEQUENCE contents).
func Concat(items ...[]byte) []byte {
	var out []byte
	for _, it := range items {
		out = append(out, it...)
	}
	return out
}

// ---------------------------------------------------------------------------
// Content encoders (produce the VALUE bytes of a base type)
// ---------------------------------------------------------------------------

func intContent(v uint64) []byte {
	if v == 0 {
		return []byte{0x00}
	}
	var b []byte
	for x := v; x > 0; x >>= 8 {
		b = append([]byte{byte(x & 0xff)}, b...)
	}
	if b[0]&0x80 != 0 { // keep it positive
		b = append([]byte{0x00}, b...)
	}
	return b
}

func base128(v uint64) []byte {
	var tmp []byte
	for {
		tmp = append([]byte{byte(v & 0x7f)}, tmp...)
		v >>= 7
		if v == 0 {
			break
		}
	}
	for i := 0; i < len(tmp)-1; i++ {
		tmp[i] |= 0x80
	}
	return tmp
}

func oidContent(arcs []uint64) []byte {
	out := base128(arcs[0]*40 + arcs[1])
	for _, a := range arcs[2:] {
		out = append(out, base128(a)...)
	}
	return out
}

func relOIDContent(arcs []uint64) []byte {
	var out []byte
	for _, a := range arcs {
		out = append(out, base128(a)...)
	}
	return out
}

func genTimeContent(t time.Time) []byte {
	return []byte(t.UTC().Format("20060102150405Z"))
}

// ---------------------------------------------------------------------------
// UNIVERSAL primitives / constructors
// ---------------------------------------------------------------------------

func Int(v uint64) []byte          { return TLV(Universal, false, TagInteger, intContent(v)) }
func OID(arcs ...uint64) []byte     { return TLV(Universal, false, TagOID, oidContent(arcs)) }
func OctetString(b []byte) []byte   { return TLV(Universal, false, TagOctetString, b) }
func Printable(s string) []byte     { return TLV(Universal, false, TagPrintableString, []byte(s)) }
func Seq(items ...[]byte) []byte    { return TLV(Universal, true, TagSequence, Concat(items...)) }

// ---------------------------------------------------------------------------
// CONTEXT-tagged fields (the common case under IMPLICIT TAGS)
// ---------------------------------------------------------------------------

// CPrim: implicit context-primitive [num] carrying raw value bytes.
func CPrim(num int, value []byte) []byte { return TLV(Context, false, num, value) }

// CCons: implicit context-constructed [num] over already-encoded inner TLVs.
// Used both for SEQUENCE fields and for SEQUENCE OF containers.
func CCons(num int, items ...[]byte) []byte { return TLV(Context, true, num, Concat(items...)) }

// CExplicit: EXPLICIT context [num] wrapping exactly one inner TLV. Required
// whenever a CHOICE type is given a tag under IMPLICIT TAGS.
func CExplicit(num int, inner []byte) []byte { return TLV(Context, true, num, inner) }

// Typed implicit-primitive conveniences.
func CInt(num int, v uint64) []byte          { return CPrim(num, intContent(v)) }
func CEnum(num int, v int) []byte             { return CPrim(num, intContent(uint64(v))) }
func COID(num int, arcs ...uint64) []byte     { return CPrim(num, oidContent(arcs)) }
func CRelOID(num int, arcs ...uint64) []byte  { return CPrim(num, relOIDContent(arcs)) }
func COctet(num int, b []byte) []byte         { return CPrim(num, b) }
func CPrintable(num int, s string) []byte     { return CPrim(num, []byte(s)) }
func CUTF8(num int, s string) []byte          { return CPrim(num, []byte(s)) }
func CGenTime(num int, t time.Time) []byte    { return CPrim(num, genTimeContent(t)) }

// HexByte2 / HexByte4 helpers for building fixed-width OCTET STRING fields.
func Fixed(n int, v uint64) []byte {
	b := make([]byte, n)
	for i := n - 1; i >= 0; i-- {
		b[i] = byte(v & 0xff)
		v >>= 8
	}
	return b
}

var _ = fmt.Sprintf // reserved for debugging
