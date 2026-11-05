package analysis

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/sotoz/sipcurious/internal/call"
	"github.com/sotoz/sipcurious/internal/report"
	"github.com/sotoz/sipcurious/internal/trace"
)

// maxRefs caps the packet references of one finding: enough to prove it,
// short enough to read.
const maxRefs = 12

// refSet collects distinct packet references up to maxRefs.
type refSet struct{ refs []Ref }

func (s *refSet) add(m *trace.Message) {
	if len(s.refs) >= maxRefs {
		return
	}
	r := Ref{File: m.File, Index: m.Index}
	for _, x := range s.refs {
		if x == r {
			return
		}
	}
	s.refs = append(s.refs, r)
}

// addAt adds the messages of c whose timestamp equals t and that carry a body
// (the SDP that created a Media entry).
func (s *refSet) addAt(c *call.Call, t time.Time) {
	for i := range c.Messages {
		m := &c.Messages[i]
		if m.Time.Equal(t) && m.HeaderEnd > 0 && m.HeaderEnd < len(m.Raw) {
			s.add(m)
		}
	}
}

func (s *refSet) result() []Ref { return s.refs }

// hdr returns the first value of the header called name (full name, any case;
// no compact forms) of m, "" if absent. It scans the raw text without
// allocating.
func hdr(m *trace.Message, name string) string {
	end := m.HeaderEnd
	if end <= 0 || end > len(m.Raw) {
		end = len(m.Raw)
	}
	s := m.Raw[:end]
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[i+1:]
	} else {
		return ""
	}
	for len(s) > 0 {
		line := s
		if i := strings.IndexByte(s, '\n'); i >= 0 {
			line, s = s[:i], s[i+1:]
		} else {
			s = ""
		}
		line = strings.TrimSuffix(line, "\r")
		if line == "" {
			return ""
		}
		if len(line) > len(name) && line[len(name)] == ':' && strings.EqualFold(line[:len(name)], name) {
			return strings.TrimSpace(line[len(name)+1:])
		}
	}
	return ""
}

// isLocal reports whether a is not routable on the public Internet:
// private (RFC 1918, ULA), CGNAT (100.64/10), loopback or link-local.
func isLocal(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsValid() && (a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || cgnat.Contains(a))
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// isPublic reports whether a is a globally routable unicast address.
func isPublic(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsValid() && !isLocal(a) && !a.IsUnspecified() && !a.IsMulticast() && !a.IsLinkLocalMulticast()
}

// uriHost returns the host of the first URI in a Contact/To/From style header
// ("" if none). Brackets of IPv6 literals are removed.
func uriHost(h string) string {
	if i := strings.IndexByte(h, '<'); i >= 0 {
		h = h[i+1:]
	}
	if i := strings.IndexByte(h, '>'); i >= 0 {
		h = h[:i]
	}
	h = strings.TrimSpace(h)
	if i := strings.IndexByte(h, ':'); i >= 0 && !strings.HasPrefix(h, "[") {
		if j := strings.IndexByte(h, '@'); j < 0 || j > i {
			h = h[i+1:] // drop scheme
		}
	}
	if i := strings.IndexByte(h, '@'); i >= 0 {
		h = h[i+1:]
	}
	return hostOnly(h)
}

// hostOnly cuts host from "host:port;params" and "[v6]:port".
func hostOnly(h string) string {
	if strings.HasPrefix(h, "[") {
		if i := strings.IndexByte(h, ']'); i >= 0 {
			return h[1:i]
		}
		return ""
	}
	if i := strings.IndexAny(h, ";:?>, "); i >= 0 {
		h = h[:i]
	}
	return h
}

// viaHost returns the sent-by host of a Via header value.
func viaHost(v string) string {
	f := strings.Fields(v)
	if len(f) < 2 {
		return ""
	}
	return hostOnly(strings.TrimSuffix(f[1], ","))
}

// viaParam returns the value of ;name= in a Via value, "" if absent.
func viaParam(v, name string) (string, bool) {
	for {
		i := strings.IndexByte(v, ';')
		if i < 0 {
			return "", false
		}
		v = v[i+1:]
		p := v
		if j := strings.IndexAny(p, ";,"); j >= 0 {
			p = p[:j]
		}
		k, val, _ := strings.Cut(p, "=")
		if strings.EqualFold(strings.TrimSpace(k), name) {
			return strings.TrimSpace(val), true
		}
	}
}

// uriCore returns "user@host" (lower case, scheme and parameters removed)
// of the first URI in a header value.
func uriCore(h string) string {
	if i := strings.IndexByte(h, '<'); i >= 0 {
		h = h[i+1:]
		if j := strings.IndexByte(h, '>'); j >= 0 {
			h = h[:j]
		}
	}
	h = strings.TrimSpace(h)
	if i := strings.IndexByte(h, ':'); i >= 0 {
		h = h[i+1:]
	}
	if i := strings.IndexAny(h, ";?"); i >= 0 {
		h = h[:i]
	}
	return strings.ToLower(h)
}

// captureBounds returns the earliest and latest timestamp known to in.
func captureBounds(in *Input) (first, last time.Time) {
	note := func(t time.Time) {
		if t.IsZero() {
			return
		}
		if first.IsZero() || t.Before(first) {
			first = t
		}
		if t.After(last) {
			last = t
		}
	}
	for i := range in.Messages {
		note(in.Messages[i].Time)
	}
	for i := range in.Streams {
		note(in.Streams[i].Start)
		note(in.Streams[i].End)
	}
	for i := range in.Calls {
		note(in.Calls[i].Start)
		note(in.Calls[i].End)
	}
	return first, last
}

// initialInvite returns the first INVITE request without To tag of c.
func initialInvite(c *call.Call) *trace.Message {
	for i := range c.Messages {
		m := &c.Messages[i]
		if m.IsRequest && strings.EqualFold(m.Method, "INVITE") && m.ToTag() == "" {
			return m
		}
	}
	return nil
}

// finalResponse returns the last response of c with the status of c.FinalCode
// to the method of the call.
func finalResponse(c *call.Call) *trace.Message {
	if c.FinalCode == 0 {
		return nil
	}
	for i := len(c.Messages) - 1; i >= 0; i-- {
		m := &c.Messages[i]
		if !m.IsRequest && m.StatusCode == c.FinalCode && (c.Method == "" || strings.EqualFold(m.Method, c.Method)) {
			return m
		}
	}
	return nil
}

// parties renders "alice -> bob" for titles and details.
func parties(c *call.Call) string {
	from, to := c.FromUser, c.ToUser
	if from == "" {
		from = "?"
	}
	if to == "" {
		to = "?"
	}
	return from + " -> " + to
}

func dur(d time.Duration) string { return report.FormatDuration(d) }

func plur(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

// joinMax joins at most n items with ", " and notes how many were left out.
func joinMax(items []string, n int) string {
	if len(items) <= n {
		return strings.Join(items, ", ")
	}
	return strings.Join(items[:n], ", ") + fmt.Sprintf(" (+%d more)", len(items)-n)
}

// activeAudio returns the first negotiated, active audio entry of c
// (not disabled, not on hold, sendrecv).
func activeAudio(c *call.Call) (call.Media, bool) {
	for _, m := range c.Media {
		if m.Type == "audio" && !m.Disabled && !m.Hold && (m.Direction == "" || m.Direction == "sendrecv") {
			return m, true
		}
	}
	return call.Media{}, false
}

// isInviteCall reports whether c is an INVITE based call.
func isInviteCall(c *call.Call) bool { return c.Kind == call.KindCall }

// answered reports whether c has a 2xx to the INVITE.
func answered(c *call.Call) bool {
	return c.State == call.StateAnswered || c.State == call.StateCompleted && !c.Answered.IsZero()
}

func atoiSafe(s string) (int, bool) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	return n, err == nil
}

// ep renders an address:port, "?" for an unknown one.
func ep(a netip.AddrPort) string {
	if !a.IsValid() {
		return "?"
	}
	return a.String()
}
