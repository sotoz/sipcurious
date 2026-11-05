package sip

import "github.com/sotoz/sipcurious/internal/trace"

// parse runs Parse with the default options and copies only the SIP header
// fields into m (Raw and HeaderEnd are checked by dedicated tests). On
// failure m is left untouched. Fields absent from the new message are cleared.
func parse(payload []byte, m *trace.Message) bool {
	got, ok := Parse(payload, ParseOptions{})
	if !ok {
		return false
	}
	m.IsRequest, m.Method, m.RequestURI = got.IsRequest, got.Method, got.RequestURI
	m.StatusCode, m.Reason = got.StatusCode, got.Reason
	m.CallID, m.From, m.To, m.Contact, m.CSeq, m.Via = got.CallID, got.From, got.To, got.Contact, got.CSeq, got.Via
	return true
}
