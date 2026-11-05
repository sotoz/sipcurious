package query

import (
	"math"
	"net/netip"
	"time"
)

// Type is the data type of a field. It decides which operators and which value
// syntax a filter may use with the field; Parse checks this up front.
type Type uint8

// The field types.
const (
	// TypeString is free text: = != ~ !~ =~ in.
	TypeString Type = iota + 1
	// TypeInt is a 64-bit integer: = != < <= > >= in (ranges as 100..199).
	TypeInt
	// TypeFloat is a decimal number: = != < <= > >= in.
	TypeFloat
	// TypeDuration is a time span (250ms, 3s, 1m30s; a bare number is seconds).
	TypeDuration
	// TypeBool is true/false; a bare field name tests for true.
	TypeBool
	// TypeTime is an instant (RFC3339, "2006-01-02 15:04:05" in UTC, or HH:MM[:SS]
	// as a time of day).
	TypeTime
	// TypeAddr is an IP address; = and in match with CIDR semantics.
	TypeAddr
	// TypeEnum is a string drawn from a closed list of values (Field.Values):
	// Parse rejects unknown values. Matching is always case-insensitive.
	TypeEnum
)

// String returns the type name used in diagnostics and Help.
func (t Type) String() string {
	switch t {
	case TypeString:
		return "string"
	case TypeInt:
		return "int"
	case TypeFloat:
		return "float"
	case TypeDuration:
		return "duration"
	case TypeBool:
		return "bool"
	case TypeTime:
		return "time"
	case TypeAddr:
		return "addr"
	case TypeEnum:
		return "enum"
	}
	return "invalid"
}

// Value is what a field getter returns. The zero Value is null ("this message
// or call has no such datum", e.g. status of a request, pdd of a call that
// never rang): null matches no comparison, so a negated comparison (!=, !~,
// not in) is true for it.
//
// A Value is built with the constructors below; it never allocates.
type Value struct {
	s  string
	n  int64 // int, bool (0/1), duration (ns), time (unix ns), float bits
	a  netip.Addr
	l  []string // multi-valued strings: a comparison is true if any element matches
	ok bool
}

// StringValue returns a string Value (also used for TypeEnum fields). The empty
// string is a real value, not null.
func StringValue(s string) Value { return Value{s: s, ok: true} }

// StringsValue returns a multi-valued string Value: comparisons are existential
// over the elements. An empty list behaves like the single value "".
func StringsValue(ss []string) Value {
	if len(ss) == 0 {
		return Value{ok: true}
	}
	return Value{l: ss, ok: true}
}

// IntValue returns an integer Value.
func IntValue(n int64) Value { return Value{n: n, ok: true} }

// FloatValue returns a float Value. NaN is null.
func FloatValue(f float64) Value {
	if math.IsNaN(f) {
		return Value{}
	}
	return Value{n: int64(math.Float64bits(f)), ok: true}
}

// DurationValue returns a duration Value.
func DurationValue(d time.Duration) Value { return Value{n: int64(d), ok: true} }

// BoolValue returns a boolean Value.
func BoolValue(b bool) Value {
	if b {
		return Value{n: 1, ok: true}
	}
	return Value{ok: true}
}

// TimeValue returns a time Value. The zero time, and instants that do not fit
// in int64 nanoseconds since the epoch (before 1678 or after 2262), are null.
func TimeValue(t time.Time) Value {
	if t.IsZero() || t.Year() < 1700 || t.Year() > 2200 {
		return Value{}
	}
	return Value{n: t.UnixNano(), ok: true}
}

// AddrValue returns an address Value; the invalid Addr is null. IPv4-mapped IPv6
// addresses are unmapped and zones dropped so that comparisons are family-stable.
func AddrValue(a netip.Addr) Value {
	if !a.IsValid() {
		return Value{}
	}
	return Value{a: a.Unmap().WithZone(""), ok: true}
}

// IsNull reports whether v is null.
func (v Value) IsNull() bool { return !v.ok }

func (v Value) float() float64 { return math.Float64frombits(uint64(v.n)) }
