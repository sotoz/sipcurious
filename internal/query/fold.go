package query

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// Case-insensitive text matching uses Unicode simple case folding, the same
// equivalence as strings.EqualFold, without allocating (no ToLower copies).

// foldEq reports whether a and b are equal under simple case folding.
func foldEq(a, b rune) bool {
	if a == b {
		return true
	}
	for f := unicode.SimpleFold(a); f != a; f = unicode.SimpleFold(f) {
		if f == b {
			return true
		}
	}
	return false
}

// hasPrefixFold reports whether s starts with sub under simple case folding.
func hasPrefixFold(s, sub string) bool {
	for len(sub) > 0 {
		if len(s) == 0 {
			return false
		}
		a, b := s[0], sub[0]
		if a < utf8.RuneSelf && b < utf8.RuneSelf {
			if a != b {
				if 'A' <= a && a <= 'Z' {
					a += 'a' - 'A'
				}
				if 'A' <= b && b <= 'Z' {
					b += 'a' - 'A'
				}
				if a != b {
					return false
				}
			}
			s, sub = s[1:], sub[1:]
			continue
		}
		rs, ws := utf8.DecodeRuneInString(s)
		rb, wb := utf8.DecodeRuneInString(sub)
		if (rs == utf8.RuneError && ws == 1) || (rb == utf8.RuneError && wb == 1) {
			// Invalid UTF-8 only matches the identical byte.
			if ws != wb || s[0] != sub[0] {
				return false
			}
		} else if !foldEq(rs, rb) {
			return false
		}
		s, sub = s[ws:], sub[wb:]
	}
	return true
}

// folder searches for one needle, ignoring case, in many haystacks.
type folder struct {
	sub   string
	cands [3]byte // possible first bytes of a match (ASCII needle start only)
	nc    int     // number of candidates; 0 means "scan every rune start"
}

func newFolder(sub string) *folder {
	f := &folder{sub: sub}
	if sub == "" || sub[0] >= utf8.RuneSelf {
		return f
	}
	c := sub[0]
	switch {
	case 'a' <= c && c <= 'z':
		f.cands[0], f.cands[1], f.nc = c, c-('a'-'A'), 2
	case 'A' <= c && c <= 'Z':
		f.cands[0], f.cands[1], f.nc = c, c+('a'-'A'), 2
	default:
		f.cands[0], f.nc = c, 1
	}
	// k and s are the only ASCII letters with a non-ASCII fold partner
	// (U+212A KELVIN SIGN, U+017F LATIN SMALL LETTER LONG S).
	switch f.cands[0] | 0x20 {
	case 'k':
		f.cands[f.nc], f.nc = 0xE2, f.nc+1
	case 's':
		f.cands[f.nc], f.nc = 0xC5, f.nc+1
	}
	return f
}

// contains reports whether s contains the needle ignoring case.
func (f *folder) contains(s string) bool {
	if f.sub == "" {
		return true
	}
	if f.nc == 0 {
		for i := 0; i < len(s); i++ {
			if utf8.RuneStart(s[i]) && hasPrefixFold(s[i:], f.sub) {
				return true
			}
		}
		return false
	}
	next := [3]int{-1, -1, -1} // next occurrence of each candidate byte at or after from
	from := 0
	for {
		best := len(s)
		for k := 0; k < f.nc; k++ {
			if next[k] < from {
				next[k] = indexByteFrom(s, from, f.cands[k])
			}
			best = min(best, next[k])
		}
		if best >= len(s) {
			return false
		}
		if hasPrefixFold(s[best:], f.sub) {
			return true
		}
		from = best + 1
	}
}

// indexByteFrom returns the index of c in s at or after from, or len(s).
func indexByteFrom(s string, from int, c byte) int {
	if from >= len(s) {
		return len(s)
	}
	k := strings.IndexByte(s[from:], c)
	if k < 0 {
		return len(s)
	}
	return from + k
}
