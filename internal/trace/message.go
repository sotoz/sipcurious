// Package trace defines the SIP message model shared by every other package.
package trace

import (
	"fmt"
	"net/netip"
	"time"
)

// Message is one SIP message extracted from a single captured packet (or TCP
// stream segment). Header values are raw: trimmed, with line folding
// removed, not lowercased.
//
// Raw holds the complete message text as captured: start line, headers, the
// blank line, and the body (the body may be absent or truncated, see the
// capture options). The core header fields below are pre-extracted for speed
// and, wherever the parser can, are substrings of Raw (no extra allocation).
// Any other header is available through Header and Headers.
type Message struct {
	File  string    // capture file the packet came from ("-" for stdin)
	Index int       // 1-based packet number inside File
	Time  time.Time // capture timestamp (UTC)

	Src, Dst         netip.Addr
	SrcPort, DstPort uint16
	Transport        string // "UDP", "TCP" or "SCTP"

	IsRequest  bool
	Method     string // request method; for responses, the method taken from CSeq
	RequestURI string // requests only
	StatusCode int    // responses only
	Reason     string // responses only

	CallID  string
	From    string // full From header value (display name, URI, tags)
	To      string // full To header value
	Contact string // full Contact header value
	CSeq    string
	Via     string // topmost Via header value

	Raw       string // whole SIP message text
	HeaderEnd int    // offset in Raw just past the blank line ending the headers; len(Raw) if there is no body
}

// Info is the short description of the message: the method for requests,
// "<code> <reason>" for responses.
func (m Message) Info() string {
	if m.IsRequest {
		return m.Method
	}
	if m.Reason == "" {
		return fmt.Sprint(m.StatusCode)
	}
	return fmt.Sprintf("%d %s", m.StatusCode, m.Reason)
}

// SrcAddr returns the source as an address:port pair.
func (m Message) SrcAddr() netip.AddrPort { return netip.AddrPortFrom(m.Src, m.SrcPort) }

// DstAddr returns the destination as an address:port pair.
func (m Message) DstAddr() netip.AddrPort { return netip.AddrPortFrom(m.Dst, m.DstPort) }

// IsProvisional reports a 1xx response.
func (m Message) IsProvisional() bool {
	return !m.IsRequest && m.StatusCode >= 100 && m.StatusCode < 200
}

// IsFinal reports a final (>= 200) response.
func (m Message) IsFinal() bool { return !m.IsRequest && m.StatusCode >= 200 }
