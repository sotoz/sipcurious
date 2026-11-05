package report

import (
	"math"
	"strconv"
	"unicode/utf8"
)

// appendFloat appends f like encoding/json: shortest representation that
// round-trips at the original width, exponent form only for very small or
// very large magnitudes. f must be finite.
func appendFloat(dst []byte, f float64, bits int) []byte {
	format := byte('f')
	if abs := math.Abs(f); abs != 0 {
		if bits == 64 && (abs < 1e-6 || abs >= 1e21) || bits == 32 && (float32(abs) < 1e-6 || float32(abs) >= 1e21) {
			format = 'e'
		}
	}
	dst = strconv.AppendFloat(dst, f, format, -1, bits)
	if format == 'e' {
		// clean up e-09 to e-9, as encoding/json does
		n := len(dst)
		if n >= 4 && dst[n-4] == 'e' && dst[n-3] == '-' && dst[n-2] == '0' {
			dst[n-2] = dst[n-1]
			dst = dst[:n-1]
		}
	}
	return dst
}

const hexDigits = "0123456789abcdef"

// appendJSONString appends s as a JSON string literal. Like encoding/json it
// replaces invalid UTF-8 with U+FFFD and escapes control characters and
// U+2028/U+2029, but it does not escape <, > and & (the output is not HTML).
func appendJSONString(dst []byte, s string) []byte {
	dst = append(dst, '"')
	start := 0
	for i := 0; i < len(s); {
		b := s[i]
		if b < utf8.RuneSelf {
			if b >= 0x20 && b != '"' && b != '\\' {
				i++
				continue
			}
			dst = append(dst, s[start:i]...)
			switch b {
			case '"', '\\':
				dst = append(dst, '\\', b)
			case '\n':
				dst = append(dst, '\\', 'n')
			case '\r':
				dst = append(dst, '\\', 'r')
			case '\t':
				dst = append(dst, '\\', 't')
			default:
				dst = append(dst, '\\', 'u', '0', '0', hexDigits[b>>4], hexDigits[b&0xf])
			}
			i++
			start = i
			continue
		}
		r, n := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && n == 1 {
			dst = append(dst, s[start:i]...)
			dst = append(dst, replacement...)
			i++
			start = i
			continue
		}
		if r == 0x2028 || r == 0x2029 {
			dst = append(dst, s[start:i]...)
			dst = append(dst, '\\', 'u', '2', '0', '2', hexDigits[r&0xf])
			i += n
			start = i
			continue
		}
		i += n
	}
	dst = append(dst, s[start:]...)
	return append(dst, '"')
}

// appendJSONValue appends v, which must not be vNil, as a JSON value.
func appendJSONValue(dst []byte, v value, o Options) []byte {
	switch v.k {
	case vStr:
		return appendJSONString(dst, v.s)
	case vTime:
		dst = append(dst, '"')
		dst = appendMachine(dst, v, o)
		return append(dst, '"')
	}
	return appendMachine(dst, v, o)
}

// writeCSV writes t as RFC 4180 CSV. Every column is written, and the header
// holds the column keys (Duration columns end in "_ms").
//
// Strings are sanitised only as far as needed to keep the data well formed:
// invalid UTF-8, NUL and other control characters (except tab and newline)
// become U+FFFD, CR LF and CR become LF. Fields are quoted when they hold a
// comma, quote, line break or start with a space. A record with one empty
// field is written as "" because a blank line would be skipped by readers.
// No attempt is made to defuse spreadsheet formulas (a leading = + - @): that
// would corrupt numbers and SIP URIs, consumers must import text columns as text.
func writeCSV(s *sink, t Table, o Options) {
	if len(t.Columns) == 0 {
		return
	}
	var scratch []byte
	field := func(first bool, b []byte, alone bool) {
		if !first {
			s.buf = append(s.buf, ',')
		}
		s.buf = appendCSVField(s.buf, b, alone)
	}
	alone := len(t.Columns) == 1
	for j, c := range t.Columns {
		scratch = appendSanitized(scratch[:0], c.jsonKey(), modeCSV)
		field(j == 0, scratch, alone)
	}
	s.buf = append(s.buf, '\n')
	for _, row := range t.Rows {
		for j := range t.Columns {
			v := normalize(cell(row, j))
			scratch = scratch[:0]
			switch v.k {
			case vStr:
				scratch = appendSanitized(scratch, v.s, modeCSV)
			case vNil:
			default:
				scratch = appendMachine(scratch, v, o)
			}
			field(j == 0, scratch, alone)
		}
		s.buf = append(s.buf, '\n')
		s.maybeFlush()
	}
}

// appendCSVField appends b, quoted if it needs to be. alone is set when the
// record has a single column.
func appendCSVField(dst, b []byte, alone bool) []byte {
	if len(b) == 0 {
		if alone {
			return append(dst, '"', '"')
		}
		return dst
	}
	need := b[0] == ' ' || b[0] == '\t'
	if !need {
		for _, c := range b {
			if c == ',' || c == '"' || c == '\n' || c == '\r' {
				need = true
				break
			}
		}
	}
	if !need {
		return append(dst, b...)
	}
	dst = append(dst, '"')
	for _, c := range b {
		if c == '"' {
			dst = append(dst, '"')
		}
		dst = append(dst, c)
	}
	return append(dst, '"')
}

// quotedKeys returns the JSON string literal of every column key, computed
// once per table.
func quotedKeys(t Table) [][]byte {
	keys := make([][]byte, len(t.Columns))
	for j, c := range t.Columns {
		keys[j] = appendJSONString(nil, c.jsonKey())
	}
	return keys
}

// appendObject appends one row as a JSON object; keys are the quoted keys. In compact form there is no
// whitespace; otherwise the object is indented at depth (its braces at depth,
// members at depth+1). Missing values are omitted.
func appendObject(dst []byte, keys [][]byte, row []any, o Options, compact bool, depth int) []byte {
	dst = append(dst, '{')
	n := 0
	for j, key := range keys {
		v := normalize(cell(row, j))
		if v.k == vNil {
			continue
		}
		if n > 0 {
			dst = append(dst, ',')
		}
		if !compact {
			dst = append(dst, '\n')
			dst = appendIndent(dst, depth+1)
		}
		dst = append(dst, key...)
		dst = append(dst, ':')
		if !compact {
			dst = append(dst, ' ')
		}
		dst = appendJSONValue(dst, v, o)
		n++
	}
	if n > 0 && !compact {
		dst = append(dst, '\n')
		dst = appendIndent(dst, depth)
	}
	return append(dst, '}')
}

func appendIndent(dst []byte, depth int) []byte {
	for range depth {
		dst = append(dst, ' ', ' ')
	}
	return dst
}

// writeJSON writes t as an indented array of objects whose first line starts
// at the current position and whose lines are indented by depth levels. No
// trailing newline.
//
// Keys come from Column.Key (+ "_ms" for durations); every column is present
// except where a cell is missing, in which case the key is omitted. A table
// without rows is "[]". Strings keep their content (invalid UTF-8 becomes
// U+FFFD); times are RFC 3339 with nanoseconds; durations are milliseconds,
// exact to the nanosecond; integers and floats are JSON numbers.
func writeJSON(s *sink, t Table, o Options, depth int) {
	keys := quotedKeys(t)
	if len(t.Rows) == 0 {
		s.buf = append(s.buf, '[', ']')
		return
	}
	s.buf = append(s.buf, '[')
	for i, row := range t.Rows {
		if i > 0 {
			s.buf = append(s.buf, ',')
		}
		s.buf = append(s.buf, '\n')
		s.buf = appendIndent(s.buf, depth+1)
		s.buf = appendObject(s.buf, keys, row, o, false, depth+1)
		s.maybeFlush()
	}
	s.buf = append(s.buf, '\n')
	s.buf = appendIndent(s.buf, depth)
	s.buf = append(s.buf, ']')
}

// writeJSONSections writes {"name": [...], ...}. No trailing newline.
func writeJSONSections(s *sink, secs []Section, o Options) {
	if len(secs) == 0 {
		s.buf = append(s.buf, '{', '}')
		return
	}
	s.buf = append(s.buf, '{')
	for i, sec := range secs {
		if i > 0 {
			s.buf = append(s.buf, ',')
		}
		s.buf = append(s.buf, '\n', ' ', ' ')
		s.buf = appendJSONString(s.buf, sec.name())
		s.buf = append(s.buf, ':', ' ')
		writeJSON(s, sec.Table, o, 1)
	}
	s.buf = append(s.buf, '\n', '}')
}

// writeNDJSON writes one compact object per row, one per line. A table
// without rows produces no output.
func writeNDJSON(s *sink, t Table, o Options) {
	keys := quotedKeys(t)
	for _, row := range t.Rows {
		s.buf = appendObject(s.buf, keys, row, o, true, 0)
		s.buf = append(s.buf, '\n')
		s.maybeFlush()
	}
}

// writeMarkdown writes t as a GitHub flavoured Markdown table. Cells are
// escaped so that no input can form Markdown or HTML markup, pipes included;
// line breaks become <br>. Numeric columns are right aligned.
func writeMarkdown(s *sink, t Table, o Options) {
	cols := visible(t, o)
	if t.Title != "" {
		s.str("### ")
		s.buf = appendSanitized(s.buf, t.Title, modeMarkdownInline)
		s.str("\n\n")
	}
	if len(cols) == 0 {
		return
	}
	for _, j := range cols {
		s.str("| ")
		s.buf = appendSanitized(s.buf, t.Columns[j].Name, modeMarkdown)
		s.buf = append(s.buf, ' ')
	}
	s.str("|\n")
	for _, j := range cols {
		if t.Columns[j].Kind.numeric() {
			s.str("| ---: ")
		} else {
			s.str("| --- ")
		}
	}
	s.str("|\n")
	for _, row := range t.Rows {
		for _, j := range cols {
			s.str("| ")
			s.buf = appendHuman(s.buf, normalize(cell(row, j)), o, modeMarkdown)
			s.buf = append(s.buf, ' ')
		}
		s.str("|\n")
		s.maybeFlush()
	}
}
