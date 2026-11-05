package call

import (
	"strings"

	"github.com/sotoz/sipcurious/internal/trace"
)

// The helpers in this file scan the raw header section directly instead of
// going through trace.Message.Header: that accessor canonicalises (and thus
// allocates) a lowercase copy of every header name it looks at, which is too
// slow when Build visits millions of messages. Continuation (folded) lines are
// ignored: the values read here (User-Agent, Server, Reason, RSeq and the
// correlation headers) are single-line in practice.

// headerSection returns the header lines of m without the start line.
func headerSection(m *trace.Message) string {
	end := m.HeaderEnd
	if end <= 0 || end > len(m.Raw) {
		end = len(m.Raw)
	}
	s := m.Raw[:end]
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[i+1:]
	}
	return ""
}

// nextHeader returns the next header of s (name and value trimmed) and the
// rest of the section; ok is false at the blank line or the end.
func nextHeader(s string) (name, value, rest string, ok bool) {
	for len(s) > 0 {
		line := s
		if i := strings.IndexByte(s, '\n'); i >= 0 {
			line, s = s[:i], s[i+1:]
		} else {
			s = ""
		}
		if n := len(line); n > 0 && line[n-1] == '\r' {
			line = line[:n-1]
		}
		if line == "" {
			return "", "", "", false
		}
		if line[0] == ' ' || line[0] == '\t' {
			continue
		}
		c := strings.IndexByte(line, ':')
		if c < 0 {
			continue
		}
		return strings.TrimSpace(line[:c]), strings.TrimSpace(line[c+1:]), s, true
	}
	return "", "", "", false
}

// eqFold reports whether a equals the lowercase ASCII string lower, ignoring case.
func eqFold(a, lower string) bool {
	if len(a) != len(lower) {
		return false
	}
	for i := range len(a) {
		c := a[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != lower[i] {
			return false
		}
	}
	return true
}

// userAgent returns the User-Agent of a request or the Server of a response,
// falling back to the other header (many phones put User-Agent in responses).
func userAgent(m *trace.Message) string {
	var ua, srv string
	for s := headerSection(m); ; {
		name, value, rest, ok := nextHeader(s)
		if !ok {
			break
		}
		s = rest
		switch len(name) {
		case 10:
			if ua == "" && eqFold(name, "user-agent") {
				ua = value
				if m.IsRequest && ua != "" {
					return ua
				}
			}
		case 6:
			if srv == "" && eqFold(name, "server") {
				srv = value
				if !m.IsRequest && srv != "" {
					return srv
				}
			}
		}
	}
	if m.IsRequest {
		if ua != "" {
			return ua
		}
		return srv
	}
	if srv != "" {
		return srv
	}
	return ua
}

// reasonHeader returns every Reason header value (RFC 3326) joined by ", ".
func reasonHeader(m *trace.Message) string {
	var out string
	for s := headerSection(m); ; {
		name, value, rest, ok := nextHeader(s)
		if !ok {
			break
		}
		s = rest
		if len(name) == 6 && eqFold(name, "reason") && value != "" {
			if out == "" {
				out = value
			} else {
				out += ", " + value
			}
		}
	}
	return out
}

// rawHeader returns the first value of the header whose lowercase name is lower.
func rawHeader(m *trace.Message, lower string) string {
	for s := headerSection(m); ; {
		name, value, rest, ok := nextHeader(s)
		if !ok {
			return ""
		}
		s = rest
		if eqFold(name, lower) {
			return value
		}
	}
}

// cseqNum returns the sequence number of a CSeq value ("102 INVITE"), 0 if unparsable.
func cseqNum(s string) int {
	s = strings.TrimLeft(s, " \t")
	n := 0
	for i := range len(s) {
		c := s[i]
		if c < '0' || c > '9' {
			break
		}
		if n > 1<<40 {
			break
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// isMethod reports whether m's method (or, for responses, its CSeq method) is
// the given upper-case method.
func isMethod(m *trace.Message, method string) bool {
	return m.Method == method || strings.EqualFold(m.Method, method)
}
