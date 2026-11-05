package query

import (
	"net/netip"
	"strings"

	"github.com/sotoz/sipcurious/internal/trace"
)

// fid identifies a built-in message field. Built-in fields are read by a
// switch on the id with a *trace.Message: no copy of the (large) message, no
// indirect call that would force it onto the heap, no allocation.
type fid uint8

const (
	fNone fid = iota
	fMethod
	fStatus
	fURI
	fCallID
	fFrom
	fTo
	fFromUser
	fToUser
	fFromTag
	fToTag
	fContact
	fCSeq
	fVia
	fBranch
	fSrc
	fDst
	fSport
	fDport
	fTransport
	fTime
	fUA
	fIsRequest
	fIsResponse
	fHasSDP
	fFile
	fIndex
	fRaw
	fBody
	fHeader
	fHeaderPresent
)

var (
	hdrUserAgent  = newHeaderName("user-agent")
	hdrServer     = newHeaderName("server")
	hdrContentTyp = newHeaderName("content-type")
)

// strOf returns the value of a string- or enum-typed built-in field.
func (f *Field) strOf(m *trace.Message) string {
	switch f.id {
	case fMethod:
		return m.Method
	case fURI:
		return m.RequestURI
	case fCallID:
		return m.CallID
	case fFrom:
		return m.From
	case fTo:
		return m.To
	case fFromUser:
		return trace.URIUser(m.From)
	case fToUser:
		return trace.URIUser(m.To)
	case fFromTag:
		return m.FromTag()
	case fToTag:
		return m.ToTag()
	case fContact:
		return m.Contact
	case fCSeq:
		return m.CSeq
	case fVia:
		return m.Via
	case fBranch:
		return m.Branch()
	case fTransport:
		return m.Transport
	case fUA:
		if v := headerOf(m.Raw, m.HeaderEnd, hdrUserAgent); v != "" {
			return v
		}
		return headerOf(m.Raw, m.HeaderEnd, hdrServer)
	case fFile:
		return m.File
	case fRaw:
		return m.Raw
	case fBody:
		return m.Body()
	case fHeader:
		return headerOf(m.Raw, m.HeaderEnd, f.hdr)
	}
	return ""
}

// numOf returns the value of an int-, bool- or time-typed built-in field; ok is
// false for null.
func (f *Field) numOf(m *trace.Message) (n int64, ok bool) {
	switch f.id {
	case fStatus:
		if m.IsRequest || m.StatusCode <= 0 {
			return 0, false
		}
		return int64(m.StatusCode), true
	case fSport:
		return int64(m.SrcPort), true
	case fDport:
		return int64(m.DstPort), true
	case fIndex:
		return int64(m.Index), true
	case fTime:
		v := TimeValue(m.Time)
		return v.n, v.ok
	case fIsRequest:
		return b2i(m.IsRequest), true
	case fIsResponse:
		return b2i(!m.IsRequest), true
	case fHasSDP:
		return b2i(hasSDP(m)), true
	case fHeaderPresent:
		return b2i(headerOf(m.Raw, m.HeaderEnd, f.hdr) != ""), true
	}
	return 0, false
}

// addrOf returns the value of an address-typed built-in field (invalid = null).
func (f *Field) addrOf(m *trace.Message) netip.Addr {
	var a netip.Addr
	switch f.id {
	case fSrc:
		a = m.Src
	case fDst:
		a = m.Dst
	}
	return a.Unmap().WithZone("")
}

// msgValue evaluates a built-in or dynamic header field to a Value.
func (f *Field) msgValue(m *trace.Message) Value {
	switch f.Type {
	case TypeString, TypeEnum:
		return StringValue(f.strOf(m))
	case TypeAddr:
		return AddrValue(f.addrOf(m))
	}
	n, ok := f.numOf(m)
	return Value{n: n, ok: ok}
}

func b2i(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// hasSDP reports whether the message carries an SDP body, without the
// allocations of trace.Message.SDP in the common (non-multipart) cases. It
// agrees with m.SDP() != "" (checked by the tests).
func hasSDP(m *trace.Message) bool {
	if m.HeaderEnd <= 0 || m.HeaderEnd >= len(m.Raw) {
		return false
	}
	ct := headerOf(m.Raw, m.HeaderEnd, hdrContentTyp)
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	ct = strings.TrimSpace(ct)
	switch {
	case strings.EqualFold(ct, "application/sdp"):
		return true
	case len(ct) >= len("multipart/") && strings.EqualFold(ct[:len("multipart/")], "multipart/"):
		return m.SDP() != ""
	}
	return false
}
