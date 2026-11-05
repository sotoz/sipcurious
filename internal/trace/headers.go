package trace

import (
	"strconv"
	"strings"
)

// compact maps RFC 3261 compact header names to their long lowercase form.
var compact = map[string]string{
	"i": "call-id", "m": "contact", "e": "content-encoding", "l": "content-length",
	"c": "content-type", "f": "from", "s": "subject", "k": "supported", "t": "to", "v": "via",
}

// canon lowercases a header name and expands compact forms.
func canon(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if long, ok := compact[name]; ok {
		return long
	}
	return name
}

// headerSection returns the start line + headers part of Raw.
func (m Message) headerSection() string {
	end := m.HeaderEnd
	if end <= 0 || end > len(m.Raw) {
		end = len(m.Raw)
	}
	return m.Raw[:end]
}

// eachHeader calls fn for every header (name as written, unfolded value) in
// order until fn returns false. The start line is skipped. Values are
// substrings of Raw unless the header was folded across lines.
func (m Message) eachHeader(fn func(name, value string) bool) {
	s := m.headerSection()
	i := strings.IndexByte(s, '\n')
	if i < 0 {
		return // start line only
	}
	s = s[i+1:]

	var (
		name, value string
		have        bool
	)
	for len(s) > 0 {
		line := s
		if j := strings.IndexByte(s, '\n'); j >= 0 {
			line, s = s[:j], s[j+1:]
		} else {
			s = ""
		}
		line = strings.TrimRight(line, "\r")
		if line == "" {
			break
		}
		if line[0] == ' ' || line[0] == '\t' {
			if have {
				if cont := strings.TrimSpace(line); cont != "" {
					if value == "" {
						value = cont
					} else {
						value += " " + cont
					}
				}
			}
			continue
		}
		if have && !fn(name, value) {
			return
		}
		n, v, ok := strings.Cut(line, ":")
		if !ok {
			have = false
			continue
		}
		name, value, have = strings.TrimSpace(n), strings.TrimSpace(v), true
	}
	if have {
		fn(name, value)
	}
}

// Header returns the first value of the named header (case-insensitive,
// compact forms understood), or "" if absent.
func (m Message) Header(name string) string {
	want := canon(name)
	var out string
	m.eachHeader(func(n, v string) bool {
		if canon(n) == want {
			out = v
			return false
		}
		return true
	})
	return out
}

// Headers returns every value of the named header in order. A header line
// carrying comma-separated values is returned as one element.
func (m Message) Headers(name string) []string {
	want := canon(name)
	var out []string
	m.eachHeader(func(n, v string) bool {
		if canon(n) == want {
			out = append(out, v)
		}
		return true
	})
	return out
}

// HeaderNames returns the header names in order of appearance, as written.
func (m Message) HeaderNames() []string {
	var out []string
	m.eachHeader(func(n, _ string) bool { out = append(out, n); return true })
	return out
}

// Body returns the message body ("" if none or dropped by the capture options).
func (m Message) Body() string {
	if m.HeaderEnd <= 0 || m.HeaderEnd >= len(m.Raw) {
		return ""
	}
	return m.Raw[m.HeaderEnd:]
}

// ContentType returns the Content-Type media type without parameters, lowercased.
func (m Message) ContentType() string {
	ct := m.Header("content-type")
	ct, _, _ = strings.Cut(ct, ";")
	return strings.ToLower(strings.TrimSpace(ct))
}

// SDP returns the SDP text carried by the message ("" if none): the whole body
// for application/sdp, or the application/sdp part of a multipart body.
func (m Message) SDP() string {
	body := m.Body()
	if body == "" {
		return ""
	}
	switch ct := m.ContentType(); {
	case ct == "application/sdp":
		return body
	case strings.HasPrefix(ct, "multipart/"):
		return multipartPart(m.Header("content-type"), body, "application/sdp")
	}
	return ""
}

func multipartPart(contentType, body, want string) string {
	_, params, _ := strings.Cut(contentType, ";")
	boundary := ""
	for _, p := range strings.Split(params, ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(p), "=")
		if ok && strings.EqualFold(k, "boundary") {
			boundary = strings.Trim(v, `"`)
		}
	}
	if boundary == "" {
		return ""
	}
	for _, part := range strings.Split(body, "--"+boundary) {
		part = strings.TrimLeft(part, "\r\n")
		hdr, content, ok := strings.Cut(part, "\r\n\r\n")
		if !ok {
			hdr, content, ok = strings.Cut(part, "\n\n")
		}
		if ok && strings.Contains(strings.ToLower(hdr), want) {
			return content
		}
	}
	return ""
}

// Branch returns the branch parameter of the topmost Via ("" if absent).
func (m Message) Branch() string { return param(m.Via, "branch") }

// FromTag returns the tag parameter of the From header.
func (m Message) FromTag() string { return param(afterURI(m.From), "tag") }

// ToTag returns the tag parameter of the To header.
func (m Message) ToTag() string { return param(afterURI(m.To), "tag") }

// FromUser returns the user part of the From URI (e.g. "alice" for
// "Alice" <sip:alice@example.com>;tag=1), or the whole address for tel: URIs.
func (m Message) FromUser() string { return URIUser(m.From) }

// ToUser returns the user part of the To URI.
func (m Message) ToUser() string { return URIUser(m.To) }

// CSeqNumber returns the numeric part of CSeq (0 if unparsable).
func (m Message) CSeqNumber() int {
	f := strings.Fields(m.CSeq)
	if len(f) == 0 {
		return 0
	}
	n, _ := strconv.Atoi(f[0])
	return n
}

// URIUser extracts the user part from a name-addr / addr-spec header value.
func URIUser(h string) string {
	uri := h
	if i := strings.IndexByte(h, '<'); i >= 0 {
		if j := strings.IndexByte(h[i:], '>'); j >= 0 {
			uri = h[i+1 : i+j]
		} else {
			uri = h[i+1:]
		}
	} else if i := strings.IndexByte(h, ';'); i >= 0 {
		uri = h[:i]
	}
	uri = strings.TrimSpace(uri)
	if i := strings.IndexByte(uri, ':'); i >= 0 {
		uri = uri[i+1:] // drop scheme
	}
	if i := strings.IndexByte(uri, '@'); i >= 0 {
		uri = uri[:i]
	} else if !strings.HasPrefix(h, "tel:") && !strings.Contains(h, "<tel:") {
		return ""
	}
	if i := strings.IndexByte(uri, ';'); i >= 0 {
		uri = uri[:i]
	}
	return uri
}

// afterURI returns the header parameters that follow the URI.
func afterURI(h string) string {
	if i := strings.IndexByte(h, '>'); i >= 0 {
		return h[i+1:]
	}
	if i := strings.IndexByte(h, ';'); i >= 0 {
		return h[i:]
	}
	return ""
}

// param finds ;name=value in a parameter string (case-insensitive name).
func param(s, name string) string {
	for {
		i := strings.IndexByte(s, ';')
		if i < 0 {
			return ""
		}
		s = s[i+1:]
		p := s
		if j := strings.IndexAny(p, ";,"); j >= 0 {
			p = p[:j]
		}
		k, v, ok := strings.Cut(p, "=")
		if ok && strings.EqualFold(strings.TrimSpace(k), name) {
			return strings.Trim(strings.TrimSpace(v), `"`)
		}
	}
}
