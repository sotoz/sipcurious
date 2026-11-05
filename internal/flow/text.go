package flow

import (
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/sotoz/sipcurious/internal/report"
)

// clean makes captured text safe for every output format: control and
// white-space characters (newlines, tabs, ESC, NUL, NEL, U+2028, no-break
// space, ...) and invisible format characters (bidi overrides, zero-width
// joiners, BOM) become a plain space; combining marks are dropped (they have
// no column of their own); invalid UTF-8 and Unicode non-characters become
// U+FFFD. The result is valid XML 1.0 text without any line break.
func clean(s string) string {
	i := 0
	for i < len(s) && s[i] >= 0x20 && s[i] < 0x7f {
		i++
	}
	if i == len(s) {
		return s
	}
	return strings.Map(cleanRune, s)
}

func cleanRune(r rune) rune {
	switch {
	case r == ' ':
		return r
	case r == utf8.RuneError:
		return utf8.RuneError
	case unicode.IsControl(r), unicode.IsSpace(r), unicode.Is(unicode.Cf, r):
		return ' '
	case unicode.Is(unicode.Mn, r), unicode.Is(unicode.Me, r):
		return -1
	case r&0xFFFE == 0xFFFE, r >= 0xFDD0 && r <= 0xFDEF:
		return utf8.RuneError
	}
	return r
}

// text cleans s, trims it and caps it at n runes (see truncate).
func text(s string, n int) string { return truncate(strings.TrimSpace(clean(s)), n) }

// truncate shortens s to at most n runes ending in an ellipsis; "" becomes "?".
func truncate(s string, n int) string {
	if s == "" {
		return "?"
	}
	return report.Truncate(s, n)
}

// wideRanges are the (approximate) East Asian wide / fullwidth / emoji blocks
// that occupy two terminal cells.
var wideRanges = [...][2]rune{
	{0x1100, 0x115F}, {0x2329, 0x232A}, {0x2E80, 0x303E}, {0x3041, 0x33FF},
	{0x3400, 0x4DBF}, {0x4E00, 0x9FFF}, {0xA000, 0xA4CF}, {0xA960, 0xA97F},
	{0xAC00, 0xD7A3}, {0xF900, 0xFAFF}, {0xFE10, 0xFE19}, {0xFE30, 0xFE6F},
	{0xFF00, 0xFF60}, {0xFFE0, 0xFFE6}, {0x1F300, 0x1F64F}, {0x1F680, 0x1F6FF},
	{0x1F900, 0x1F9FF}, {0x20000, 0x2FFFD}, {0x30000, 0x3FFFD},
}

// runeWidth is the number of terminal columns r occupies (1 or 2); cleaned
// text has no zero-width runes.
func runeWidth(r rune) int {
	if r < 0x1100 {
		return 1
	}
	for _, w := range wideRanges {
		if r < w[0] {
			return 1
		}
		if r <= w[1] {
			return 2
		}
	}
	return 1
}

// width is the number of terminal columns of cleaned text s.
func width(s string) int {
	ascii := true
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			ascii = false
			break
		}
	}
	if ascii {
		return len(s)
	}
	n := 0
	for _, r := range s {
		n += runeWidth(r)
	}
	return n
}

// fmtDur renders d as seconds with millisecond precision ("1.250s"); negative
// values get a leading "-".
func fmtDur(d time.Duration) string {
	sign := ""
	if d < 0 {
		sign, d = "-", -d
	}
	ms := d.Round(time.Millisecond).Milliseconds()
	return fmt.Sprintf("%s%d.%03ds", sign, ms/1000, ms%1000)
}

// fmtOffset renders an offset from the call start: "+1.250s".
func fmtOffset(d time.Duration) string {
	if d < 0 {
		return fmtDur(d)
	}
	return "+" + fmtDur(d)
}

// fmtClock renders the time of day of t with millisecond precision.
func fmtClock(t time.Time, utc bool) string {
	if utc {
		t = t.UTC()
	} else {
		t = t.Local()
	}
	return t.Format("15:04:05.000")
}
