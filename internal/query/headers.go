package query

import "strings"

// Header lookup without allocation. trace.Message.Header lowercases every
// header name it looks at (one allocation per header), which is too slow for a
// filter run over millions of messages; this scan implements the same
// semantics (first occurrence, case-insensitive names, RFC 3261 compact forms,
// folded continuation lines joined by one space) and is cross-checked against
// trace.Message.Header by the tests.

var compactForms = [...]struct{ short, long string }{
	{"i", "call-id"}, {"m", "contact"}, {"e", "content-encoding"}, {"l", "content-length"},
	{"c", "content-type"}, {"f", "from"}, {"s", "subject"}, {"k", "supported"}, {"t", "to"}, {"v", "via"},
}

// headerName is a header name in long and (if one exists) compact spelling.
type headerName struct{ long, short string }

func newHeaderName(name string) headerName {
	n := strings.ToLower(strings.TrimSpace(name))
	for _, c := range compactForms {
		if n == c.short || n == c.long {
			return headerName{c.long, c.short}
		}
	}
	return headerName{long: n}
}

func (h headerName) matches(name string) bool {
	name = strings.TrimSpace(name)
	return strings.EqualFold(name, h.long) || h.short != "" && strings.EqualFold(name, h.short)
}

// headerOf returns the first value of header h in the message text raw whose
// header block ends at hdrEnd (0 or out of range: the whole text), or "".
func headerOf(raw string, hdrEnd int, h headerName) string {
	s := raw
	if hdrEnd > 0 && hdrEnd <= len(raw) {
		s = raw[:hdrEnd]
	}
	i := strings.IndexByte(s, '\n')
	if i < 0 {
		return ""
	}
	s = s[i+1:]
	for len(s) > 0 {
		var line string
		line, s = nextLine(s)
		if line == "" {
			return ""
		}
		if line[0] == ' ' || line[0] == '\t' {
			continue
		}
		name, rest, ok := strings.Cut(line, ":")
		if !ok || !h.matches(name) {
			continue
		}
		value := strings.TrimSpace(rest)
		for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
			var cont string
			cont, s = nextLine(s)
			if cont = strings.TrimSpace(cont); cont != "" {
				if value == "" {
					value = cont
				} else {
					value += " " + cont
				}
			}
		}
		return value
	}
	return ""
}

// nextLine splits s at the first LF and strips trailing CRs from the line.
func nextLine(s string) (line, rest string) {
	if j := strings.IndexByte(s, '\n'); j >= 0 {
		line, rest = s[:j], s[j+1:]
	} else {
		line = s
	}
	return strings.TrimRight(line, "\r"), rest
}
