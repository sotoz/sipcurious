// Package sip parses SIP messages (RFC 3261) out of captured payloads and
// provides the capture.Handler that extracts them from a packet stream.
//
// The parser is forgiving: missing headers, malformed header lines and
// truncated messages are tolerated; only a valid start line is required. It
// never panics on hostile input.
package sip

import (
	"bytes"
	"strings"
	"unicode"
	"unsafe"

	"github.com/sotoz/sipcurious/internal/trace"
)

// MaxMessageSize is the largest message Parse looks at; longer payloads are
// cut. Real SIP messages are far below this (UDP datagrams are <= 64 KiB by
// construction, and the bound keeps a hostile TCP stream from growing a
// message without limit).
const MaxMessageSize = 64 << 10

// sipVersion is the only protocol version that appears in SIP start lines.
const sipVersion = "SIP/2.0"

// BodyMode selects which message bodies are kept in trace.Message.Raw.
type BodyMode int

const (
	// BodySDP keeps SDP bodies (application/sdp and multipart/*) and drops
	// every other body. It is the zero value, hence the default.
	BodySDP BodyMode = iota
	// BodyNone drops every body: Raw holds the start line and headers only.
	BodyNone
	// BodyAll keeps every body (up to MaxMessageSize in total).
	BodyAll
)

// ParseOptions configures Parse and NewHandler. The zero value is the default.
type ParseOptions struct {
	Bodies BodyMode // which bodies to keep, default BodySDP
}

// Parse recognises a SIP message at the start of payload and returns it, or
// false when payload does not begin with a valid SIP start line
// ("METHOD URI SIP/2.0" or "SIP/2.0 code reason").
//
// Only the SIP-specific fields of the result are filled (Method, IsRequest,
// RequestURI, StatusCode, Reason, CallID, From, To, Contact, CSeq, Via, Raw,
// HeaderEnd); the capture metadata (File, Index, Time, endpoints, Transport)
// is left for the caller.
//
// Raw is the message text without leading CR/LF keep-alives, cut at
// MaxMessageSize and at the end of the headers according to opt.Bodies, in
// ONE string allocation. Every extracted field is a substring of Raw except
// for folded (multi-line) headers, which are joined with a single space into
// a copy. Header names are matched case-insensitively, compact forms (i, f,
// t, m, v) are understood, CRLF and bare LF line endings are accepted, and if
// a header occurs several times the first non-empty occurrence wins. For
// responses Method is taken from CSeq. A payload that ends in the middle of
// a line is parsed as it is; callers that know the data is cut (snaplen)
// should drop the cut line first, see TrimPartial.
func Parse(payload []byte, opt ParseOptions) (trace.Message, bool) {
	// Tolerate leading CRLF keep-alives.
	for len(payload) > 0 && (payload[0] == '\r' || payload[0] == '\n') {
		payload = payload[1:]
	}
	if len(payload) > MaxMessageSize {
		payload = payload[:MaxMessageSize]
	}

	// Reject non-SIP payloads (the vast majority of packets) without
	// allocating: validate the start line on a read-only view of the bytes.
	startEnd := bytes.IndexByte(payload, '\n')
	if startEnd < 0 {
		startEnd = len(payload)
	}
	var probe trace.Message
	if !parseStartLine(unsafe.String(unsafe.SliceData(payload), startEnd), &probe) {
		return trace.Message{}, false
	}

	hs := scanHeaders(payload)
	headerEnd := hs.end
	end := headerEnd
	if hs.complete && (opt.Bodies == BodyAll || opt.Bodies == BodySDP && hs.sdp) {
		end = len(payload)
	}
	raw := string(payload[:end]) // the one allocation

	var m trace.Message
	m.Raw = raw
	m.HeaderEnd = headerEnd
	line, rest := nextLine(raw[:headerEnd])
	parseStartLine(line, &m)
	parseHeaders(rest, &m)

	if !m.IsRequest {
		m.Method = cseqMethod(m.CSeq)
	}
	return m, true
}

// TrimPartial drops a trailing incomplete line from a payload that is known
// to be cut short (capture snaplen), so that a half-captured header such as
// "Call-ID: ab" is not recorded as a Call-ID of "ab". The start line itself is
// never dropped: a message cut right after it is still worth reporting.
func TrimPartial(payload []byte) []byte {
	if len(payload) > 0 && payload[len(payload)-1] != '\n' {
		if i := bytes.LastIndexByte(payload, '\n'); i >= 0 {
			return payload[:i+1]
		}
	}
	return payload
}

// headerScan is what scanHeaders learns about the header section.
type headerScan struct {
	end           int  // offset just past the blank line ending the headers; len(payload) if there is none
	complete      bool // the blank line was seen
	sdp           bool // Content-Type announces SDP or a multipart body
	contentLength int  // Content-Length (compact "l") value, 0 if absent or invalid
}

// maxContentLength bounds the Content-Length values taken at face value.
const maxContentLength = 1 << 30

// scanHeaders walks the header lines of payload once, without allocating.
func scanHeaders(payload []byte) headerScan {
	var hs headerScan
	pos := 0
	first, seenCT, seenCL := true, false, false
	for pos < len(payload) {
		rest := payload[pos:]
		n := bytes.IndexByte(rest, '\n')
		var line []byte
		if n < 0 {
			line, n = rest, len(rest)-1
		} else {
			line = rest[:n]
		}
		pos += n + 1
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
		if first {
			first = false
			continue
		}
		if len(line) == 0 {
			hs.end, hs.complete = pos, true
			return hs
		}
		switch line[0] {
		case 'c', 'C', 'l', 'L':
			name, value, ok := splitHeader(line)
			if !ok {
				continue
			}
			switch {
			case !seenCT && (len(name) == 1 && (name[0] == 'c' || name[0] == 'C') || strings.EqualFold(string(name), "content-type")):
				seenCT = true
				hs.sdp = hasPrefixFold(value, "application/sdp") || hasPrefixFold(value, "multipart/")
			case !seenCL && (len(name) == 1 && (name[0] == 'l' || name[0] == 'L') || strings.EqualFold(string(name), "content-length")):
				seenCL = true
				hs.contentLength = parseLength(value)
			}
		}
	}
	hs.end = len(payload)
	return hs
}

// splitHeader splits "Name : value" at the colon and trims both sides.
func splitHeader(line []byte) (name, value []byte, ok bool) {
	i := bytes.IndexByte(line, ':')
	if i < 0 {
		return nil, nil, false
	}
	return bytes.TrimRight(line[:i], " \t"), bytes.TrimLeft(line[i+1:], " \t"), true
}

// parseLength parses a Content-Length value; anything but a plain decimal
// number below maxContentLength yields 0.
func parseLength(v []byte) int {
	v = bytes.TrimRight(v, " \t")
	if len(v) == 0 || len(v) > 10 {
		return 0
	}
	n := 0
	for _, c := range v {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	if n > maxContentLength {
		return 0
	}
	return n
}

func hasPrefixFold(b []byte, prefix string) bool {
	return len(b) >= len(prefix) && strings.EqualFold(string(b[:len(prefix)]), prefix)
}

// parseHeaders extracts the headers of interest from the header lines in s
// (everything after the start line, ending at the blank line).
func parseHeaders(s string, m *trace.Message) {
	var (
		cur  *string // header being built, for obs-fold continuations
		fold []byte  // cur's value so far once a continuation was seen
	)
	// flush stores the folded value; building it in a byte slice keeps a
	// message with thousands of continuation lines linear.
	flush := func() {
		if cur != nil && fold != nil {
			*cur = string(fold)
		}
		cur, fold = nil, nil
	}
	for len(s) > 0 {
		var line string
		line, s = nextLineString(s)
		if len(line) == 0 {
			break // end of headers
		}
		if line[0] == ' ' || line[0] == '\t' {
			if cur != nil {
				if v := strings.TrimSpace(line); len(v) > 0 {
					if fold == nil {
						fold = append(fold, *cur...)
					}
					if len(fold) > 0 {
						fold = append(fold, ' ')
					}
					fold = append(fold, v...)
				}
			}
			continue
		}
		flush()
		name, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		cur = headerField(m, strings.TrimSpace(name))
		if cur == nil {
			continue
		}
		if *cur != "" { // repeated header: keep the first one
			cur = nil
			continue
		}
		*cur = strings.TrimSpace(value)
	}
	flush()
}

// cseqMethod returns the method of a CSeq value ("42 INVITE" -> "INVITE").
func cseqMethod(cseq string) string {
	i := strings.IndexFunc(cseq, unicode.IsSpace)
	if i < 0 {
		return ""
	}
	rest := strings.TrimLeftFunc(cseq[i:], unicode.IsSpace)
	if j := strings.IndexFunc(rest, unicode.IsSpace); j >= 0 {
		rest = rest[:j]
	}
	return rest
}

// nextLine splits s at the first LF, stripping an optional preceding CR.
func nextLine(s string) (line, rest string) { return nextLineString(s) }

func nextLineString(s string) (line, rest string) {
	i := strings.IndexByte(s, '\n')
	if i < 0 {
		line, rest = s, ""
	} else {
		line, rest = s[:i], s[i+1:]
	}
	if n := len(line); n > 0 && line[n-1] == '\r' {
		line = line[:n-1]
	}
	return line, rest
}

// headerField returns the destination field in m for a header name, or nil if
// the header is not one we record.
func headerField(m *trace.Message, name string) *string {
	switch len(name) {
	case 1:
		switch name[0] {
		case 'i', 'I':
			return &m.CallID
		case 'f', 'F':
			return &m.From
		case 't', 'T':
			return &m.To
		case 'm', 'M':
			return &m.Contact
		case 'v', 'V':
			return &m.Via
		}
	case 2:
		if strings.EqualFold(name, "to") {
			return &m.To
		}
	case 3:
		if strings.EqualFold(name, "via") {
			return &m.Via
		}
	case 4:
		if strings.EqualFold(name, "from") {
			return &m.From
		}
		if strings.EqualFold(name, "cseq") {
			return &m.CSeq
		}
	case 7:
		if strings.EqualFold(name, "call-id") {
			return &m.CallID
		}
		if strings.EqualFold(name, "contact") {
			return &m.Contact
		}
	}
	return nil
}

// parseStartLine parses "METHOD URI SIP/2.0" or "SIP/2.0 code reason" into m.
// The fields stored in m are substrings of line.
func parseStartLine(line string, m *trace.Message) bool {
	if n := len(line); n > 0 && line[n-1] == '\r' {
		line = line[:n-1]
	}
	// Cheap rejection of the vast majority of non-SIP payloads: a start line
	// is printable ASCII and long enough for "SIP/2.0 200".
	if len(line) < len("SIP/2.0 200") {
		return false
	}
	response := hasResponsePrefix(line)
	for i := range len(line) {
		c := line[i]
		if c < 0x20 && c != '\t' || c == 0x7f {
			return false
		}
		// Reason phrases may technically hold UTF-8; accept non-ASCII only
		// for responses.
		if c >= 0x80 && !response {
			return false
		}
	}

	if response {
		rest := line[len(sipVersion)+1:]
		codeStr, reason, _ := strings.Cut(rest, " ")
		if len(codeStr) != 3 {
			return false
		}
		code := 0
		for i := range 3 {
			d := codeStr[i]
			if d < '0' || d > '9' {
				return false
			}
			code = code*10 + int(d-'0')
		}
		if code < 100 || code > 699 {
			return false
		}
		m.IsRequest = false
		m.StatusCode = code
		m.Reason = strings.TrimSpace(reason)
		return true
	}

	method, rest, ok := strings.Cut(line, " ")
	if !ok || !isToken(method) {
		return false
	}
	uri, version, ok := strings.Cut(rest, " ")
	if !ok || uri == "" || strings.ContainsAny(uri, " \t") {
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(version), sipVersion) {
		return false
	}
	m.IsRequest = true
	m.Method = method
	m.RequestURI = uri
	return true
}

func hasResponsePrefix(line string) bool {
	return len(line) > len(sipVersion) &&
		strings.EqualFold(line[:len(sipVersion)], sipVersion) &&
		line[len(sipVersion)] == ' '
}

// isToken reports whether s is a non-empty RFC 3261 token.
func isToken(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("-.!%*_+`'~", c) >= 0:
		default:
			return false
		}
	}
	return true
}
