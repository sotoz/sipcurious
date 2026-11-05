package report

import "unicode/utf8"

// mode selects how untrusted text is made safe for one output context.
type mode uint8

const (
	modeText           mode = iota // terminal table: one line, no control characters
	modeCSV                        // CSV field content: line breaks and tabs kept, quoting is separate
	modeMarkdown                   // GFM table cell: Markdown escaped, newline -> <br>
	modeMarkdownInline             // Markdown heading: Markdown escaped, newline -> space
	modeHTML                       // HTML text node in a cell: escaped, newline -> <br>
	modeHTMLInline                 // HTML text node/attribute: escaped, newline -> space
	modeHTMLPre                    // HTML <pre>: escaped, newline and tab kept
	numModes
)

const replacement = "\uFFFD"

// asciiEntry is the treatment of one ASCII byte in one mode.
type asciiEntry struct {
	plain bool   // copy unchanged
	repl  string // replacement if !plain
}

var asciiTab = buildASCIITab()

func buildASCIITab() (t [numModes][utf8.RuneSelf]asciiEntry) {
	for m := mode(0); m < numModes; m++ {
		md := m == modeMarkdown || m == modeMarkdownInline
		html := m == modeHTML || m == modeHTMLInline || m == modeHTMLPre
		for c := range utf8.RuneSelf {
			e := asciiEntry{plain: c >= 0x20 && c < 0x7f}
			switch {
			case c == '\n' || c == '\r':
				e.plain = false
				switch m {
				case modeCSV:
					e.repl = "\n"
					e.plain = c == '\n'
				case modeHTMLPre:
					e.repl = "\n"
					e.plain = c == '\n'
				case modeMarkdown, modeHTML:
					e.repl = "<br>"
				default:
					e.repl = " "
				}
			case c == '\t':
				e.plain = m == modeCSV || m == modeHTMLPre
				e.repl = " "
			case c == '\v' || c == '\f':
				if m == modeCSV || m == modeHTMLPre {
					e.repl = replacement
				} else {
					e.repl = " "
				}
			case c < 0x20 || c == 0x7f:
				e.repl = replacement
			case md:
				switch c {
				case '\\', '|', '<', '>', '`', '*', '[', ']', '&':
					e.plain = false
					e.repl = "\\" + string(rune(c))
				}
			case html:
				switch c {
				case '&':
					e.plain, e.repl = false, "&amp;"
				case '<':
					e.plain, e.repl = false, "&lt;"
				case '>':
					e.plain, e.repl = false, "&gt;"
				case '"':
					e.plain, e.repl = false, "&quot;"
				case '\'':
					e.plain, e.repl = false, "&#39;"
				}
			}
			t[m][c] = e
		}
	}
	return t
}

// nonASCII reports the replacement for a valid non-ASCII rune, and whether
// the rune must be replaced at all. C1 controls are replaced everywhere;
// bidirectional overrides (which can make hostile text look like something
// else), line/paragraph separators and the BOM are neutralised in every mode
// except CSV, whose job is to carry the data through.
func nonASCII(r rune, m mode) (string, bool) {
	switch {
	case r < 0xA0:
		return replacement, true
	case r < 0x2028:
		return "", false
	case m == modeCSV:
		return "", false
	}
	switch {
	case r == 0x2028 || r == 0x2029:
		switch m {
		case modeHTMLPre:
			return "\n", true
		case modeMarkdown, modeHTML:
			return "<br>", true
		}
		return " ", true
	case r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069:
		return replacement, true
	case r == 0xFEFF:
		return "", true
	}
	return "", false
}

// appendSanitized appends s to dst, made safe for mode m: invalid UTF-8 and
// control characters become U+FFFD (ESC can therefore never reach a terminal),
// line breaks, escaping and so on follow the mode. A CRLF pair counts as one
// line break. Strings without anything to change cost one scan and one append.
func appendSanitized(dst []byte, s string, m mode) []byte {
	tab := &asciiTab[m]
	start := 0
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			e := &tab[c]
			if e.plain {
				i++
				continue
			}
			dst = append(dst, s[start:i]...)
			if c != '\r' || i+1 >= len(s) || s[i+1] != '\n' {
				dst = append(dst, e.repl...)
			}
			i++
			start = i
			continue
		}
		r, n := utf8.DecodeRuneInString(s[i:])
		var repl string
		if r == utf8.RuneError && n == 1 {
			repl = replacement
		} else {
			var changed bool
			if repl, changed = nonASCII(r, m); !changed {
				i += n
				continue
			}
		}
		dst = append(dst, s[start:i]...)
		dst = append(dst, repl...)
		i += n
		start = i
	}
	return append(dst, s[start:]...)
}
