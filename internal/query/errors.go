package query

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// SyntaxError is a problem in a filter expression: bad syntax, an unknown
// field, an operator or value that does not fit the field's type, a regexp that
// does not compile. Parse returns it as the error value.
type SyntaxError struct {
	// Pos is the byte offset in the source where the problem starts.
	Pos int
	// Msg describes the problem in one sentence, without the position.
	Msg string

	src string // the expression
	end int    // byte offset just past the offending token (>= Pos)
}

// Error returns "filter: column N: message" (N counts characters from 1).
func (e *SyntaxError) Error() string {
	return fmt.Sprintf("filter: column %d: %s", e.column()+1, e.Msg)
}

// column is the 0-based character column of Pos within its line.
func (e *SyntaxError) column() int {
	_, col, _ := e.locate()
	return col
}

// locate returns the line containing Pos, the character column of Pos in it and
// the width in characters of the offending token on that line.
func (e *SyntaxError) locate() (line string, col, width int) {
	pos := min(max(e.Pos, 0), len(e.src))
	start := strings.LastIndexByte(e.src[:pos], '\n') + 1
	stop := len(e.src)
	if i := strings.IndexByte(e.src[pos:], '\n'); i >= 0 {
		stop = pos + i
	}
	line = e.src[start:stop]
	col = utf8.RuneCountInString(e.src[start:pos])
	end := min(max(e.end, pos), stop)
	width = max(utf8.RuneCountInString(e.src[pos:end]), 1)
	return line, col, width
}

// Pretty renders the error as the offending line of the expression followed by
// a line with a caret under the position (and tildes under the rest of the
// token), then the message:
//
//	status = abc
//	         ^~~ "abc" is not an integer (status is an int field)
//
// Tabs and control characters of the source are shown as spaces so the caret
// lines up. There is no trailing newline.
func (e *SyntaxError) Pretty() string {
	line, col, width := e.locate()
	var b strings.Builder
	for _, r := range line {
		if r < ' ' || r == 0x7f {
			r = ' '
		}
		b.WriteRune(r)
	}
	b.WriteByte('\n')
	b.WriteString(strings.Repeat(" ", col))
	b.WriteByte('^')
	b.WriteString(strings.Repeat("~", width-1))
	b.WriteByte(' ')
	b.WriteString(e.Msg)
	return b.String()
}
