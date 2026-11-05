package report

import "unicode/utf8"

// ANSI sequences used by the text table when Options.Color is set.
const (
	ansiReset = "\x1b[0m"
	ansiBold  = "\x1b[1m"
)

// ansiFor returns the escape that starts style st, or "".
func ansiFor(st Style) string {
	switch st {
	case Good:
		return "\x1b[32m"
	case Warn:
		return "\x1b[33m"
	case Bad:
		return "\x1b[31m"
	case Dim:
		return "\x1b[2m"
	}
	return ""
}

// visible returns the columns shown with o.
func visible(t Table, o Options) []int {
	idx := make([]int, 0, len(t.Columns))
	for j, c := range t.Columns {
		if !c.Extra || o.Extra {
			idx = append(idx, j)
		}
	}
	return idx
}

// displayWidth is the number of terminal cells s occupies: one per rune, two
// for East Asian wide and emoji ranges, none for combining marks and the
// zero width joiner/variation selectors.
func displayWidth(b []byte) int {
	n := 0
	for i := 0; i < len(b); {
		if b[i] < utf8.RuneSelf {
			n++
			i++
			continue
		}
		r, w := utf8.DecodeRune(b[i:])
		i += w
		n += runeWidth(r)
	}
	return n
}

func runeWidth(r rune) int {
	switch {
	case r < 0x300:
		return 1
	case r <= 0x36F, r >= 0x200B && r <= 0x200F, r >= 0xFE00 && r <= 0xFE0F, r >= 0x20D0 && r <= 0x20FF:
		return 0
	case r >= 0x1100 && r <= 0x115F,
		r >= 0x2E80 && r <= 0xA4CF,
		r >= 0xAC00 && r <= 0xD7A3,
		r >= 0xF900 && r <= 0xFAFF,
		r >= 0xFE30 && r <= 0xFE6F,
		r >= 0xFF00 && r <= 0xFF60,
		r >= 0xFFE0 && r <= 0xFFE6,
		r >= 0x1F300 && r <= 0x1F64F,
		r >= 0x1F900 && r <= 0x1F9FF,
		r >= 0x20000 && r <= 0x3FFFD:
		return 2
	}
	return 1
}

// writeText renders t as a padded text table.
//
// Cells are rendered into one shared buffer first (two passes are needed to
// know the column widths), then emitted with padding. Columns are separated
// by two spaces; numeric columns are right aligned; lines carry no trailing
// whitespace.
func writeText(s *sink, t Table, o Options) {
	cols := visible(t, o)
	if t.Title != "" {
		s.buf = appendSanitized(s.buf, t.Title, modeText)
		s.buf = append(s.buf, '\n')
	}
	if len(cols) == 0 {
		return
	}
	nc := len(cols)
	widths := make([]int, nc)
	data := make([]byte, 0, (len(t.Rows)+1)*nc*8)
	ends := make([]int, 0, (len(t.Rows)+1)*nc)
	var styles []uint8
	color := o.Color
	if color {
		styles = make([]uint8, 0, cap(ends))
	}
	pos := 0
	add := func(width int, st Style) {
		if width > widths[len(ends)%nc] {
			widths[len(ends)%nc] = width
		}
		ends = append(ends, len(data))
		if color {
			styles = append(styles, uint8(st))
		}
		pos = len(data)
	}
	for _, j := range cols {
		data = appendSanitized(data, t.Columns[j].Name, modeText)
		add(displayWidth(data[pos:]), None)
	}
	for _, row := range t.Rows {
		for _, j := range cols {
			raw := cell(row, j)
			data = appendHuman(data, normalize(raw), o, modeText)
			st := None
			if color {
				if f := t.Columns[j].Style; f != nil {
					st = f(raw)
				}
			}
			add(displayWidth(data[pos:]), st)
		}
	}

	rows := len(ends) / nc
	for r := range rows {
		lineStart := len(s.buf)
		for c := range nc {
			k := r*nc + c
			from := 0
			if k > 0 {
				from = ends[k-1]
			}
			text := data[from:ends[k]]
			width := widths[c]
			pad := width - displayWidth(text)
			right := t.Columns[cols[c]].Kind.numeric()
			if c > 0 {
				s.buf = append(s.buf, ' ', ' ')
			}
			if right {
				s.buf = appendSpaces(s.buf, pad)
			}
			var pre string
			if color {
				if r == 0 {
					pre = ansiBold
				} else {
					pre = ansiFor(Style(styles[k]))
				}
			}
			if pre != "" && len(text) > 0 {
				s.buf = append(s.buf, pre...)
				s.buf = append(s.buf, text...)
				s.buf = append(s.buf, ansiReset...)
			} else {
				s.buf = append(s.buf, text...)
			}
			if !right && c < nc-1 {
				s.buf = appendSpaces(s.buf, pad)
			}
		}
		s.buf = trimTrailingSpaces(s.buf, lineStart)
		s.buf = append(s.buf, '\n')
		if r == 0 && o.HeaderRule {
			ruleStart := len(s.buf)
			for c := range nc {
				if c > 0 {
					s.buf = append(s.buf, ' ', ' ')
				}
				for range widths[c] {
					s.buf = append(s.buf, '-')
				}
			}
			s.buf = trimTrailingSpaces(s.buf, ruleStart)
			s.buf = append(s.buf, '\n')
		}
		s.maybeFlush()
	}
}

func appendSpaces(b []byte, n int) []byte {
	for ; n > 0; n-- {
		b = append(b, ' ')
	}
	return b
}

// trimTrailingSpaces removes trailing spaces from b[start:].
func trimTrailingSpaces(b []byte, start int) []byte {
	for len(b) > start && b[len(b)-1] == ' ' {
		b = b[:len(b)-1]
	}
	return b
}
