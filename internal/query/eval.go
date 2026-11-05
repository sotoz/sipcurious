package query

import (
	"github.com/sotoz/sipcurious/internal/call"
	"github.com/sotoz/sipcurious/internal/trace"
)

// onMsg evaluates a message-field leaf on m. Built-in fields are read straight
// from *m (no allocation); registered extension fields go through their getter.
func (l *leaf) onMsg(m *trace.Message) bool {
	f := l.f
	if f.id == fNone {
		return l.onValue(f.Message(*m), timeNs(m))
	}
	var ok bool
	switch f.Type {
	case TypeString, TypeEnum:
		ok = l.sp(f.strOf(m))
	case TypeAddr:
		a := f.addrOf(m)
		ok = a.IsValid() && l.ap(a)
	case TypeTime:
		n, valid := f.numOf(m)
		if ok = valid; ok {
			if l.tod {
				ok = l.tp(n, n)
			} else {
				ok = l.np(n)
			}
		}
	default: // int, bool
		n, valid := f.numOf(m)
		ok = valid && l.np(n)
	}
	return ok != l.neg
}

func timeNs(m *trace.Message) int64 { return TimeValue(m.Time).n }

// onCall evaluates a call-field leaf on c.
func (l *leaf) onCall(c *call.Call) bool {
	return l.onValue(l.f.Call(c), TimeValue(c.Start).n)
}

// onValue applies the leaf's predicate to a Value. ref is the instant whose
// calendar day anchors a time-of-day comparison.
func (l *leaf) onValue(v Value, ref int64) bool {
	ok := false
	if v.ok {
		switch l.f.Type {
		case TypeString, TypeEnum:
			if v.l == nil {
				ok = l.sp(v.s)
				break
			}
			for _, s := range v.l {
				if l.sp(s) {
					ok = true
					break
				}
			}
		case TypeFloat:
			ok = l.fp(v.float())
		case TypeAddr:
			ok = v.a.IsValid() && l.ap(v.a)
		case TypeTime:
			if l.tod {
				ok = l.tp(v.n, ref)
			} else {
				ok = l.np(v.n)
			}
		default:
			ok = l.np(v.n)
		}
	}
	return ok != l.neg
}
