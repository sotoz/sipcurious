package query

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

type tokKind uint8

const (
	tkEOF tokKind = iota
	tkWord
	tkString
	tkLParen
	tkRParen
	tkComma
	tkOp // = != ~ !~ =~ < <= > >=
	tkAnd
	tkOr
	tkNot
	tkErr
)

// token is one lexical element. pos and end are byte offsets into the source.
type token struct {
	kind     tokKind
	pos, end int
	text     string // word text, unescaped string, operator text, or error message
}

// lexer produces tokens on demand, so that a syntax problem early in the
// expression is reported before a lexical problem later in it.
type lexer struct {
	src  string
	pos  int
	done bool
	prev tokKind // kind of the previous token
}

// wordEnd reports whether the byte at s[i] ends a bare word. A word may
// contain a lone '!', '&' or '|' ("Hi!", "a&b"); only "!=", "!~", "&&" and
// "||" end it, as do whitespace, parentheses, comma, double quote and the
// operator characters = ~ < >.
//
// In value position (right after an operator or a comma) '=', '~', '<' and '>'
// are ordinary characters, so that body ~ a=inactive and reason ~ cause=16 need
// no quotes.
func wordEnd(s string, i int, value bool) bool {
	switch s[i] {
	case '(', ')', ',', '"', ' ', '\t', '\n', '\r', '\v', '\f':
		return true
	case '=', '~', '<', '>':
		return !value
	case '!':
		return i+1 < len(s) && (s[i+1] == '=' || s[i+1] == '~')
	case '&', '|':
		return i+1 < len(s) && s[i+1] == s[i]
	}
	return false
}

func (l *lexer) errTok(pos, end int, msg string) token {
	l.done = true
	return token{kind: tkErr, pos: pos, end: end, text: msg}
}

// next returns the next token; after tkEOF or tkErr it keeps returning tkEOF.
func (l *lexer) next() token {
	t := l.scan()
	l.prev = t.kind
	return t
}

func (l *lexer) scan() token {
	if l.done {
		return token{kind: tkEOF, pos: len(l.src), end: len(l.src)}
	}
	s := l.src
	for l.pos < len(s) {
		r, w := utf8.DecodeRuneInString(s[l.pos:])
		if r == utf8.RuneError && w == 1 || !unicode.IsSpace(r) {
			break
		}
		l.pos += w
	}
	if l.pos >= len(s) {
		l.done = true
		return token{kind: tkEOF, pos: len(s), end: len(s)}
	}
	start := l.pos
	c := s[start]
	at := func(k int) byte {
		if start+k < len(s) {
			return s[start+k]
		}
		return 0
	}
	simple := func(kind tokKind, n int, text string) token {
		l.pos = start + n
		return token{kind: kind, pos: start, end: l.pos, text: text}
	}
	switch c {
	case '(':
		return simple(tkLParen, 1, "(")
	case ')':
		return simple(tkRParen, 1, ")")
	case ',':
		return simple(tkComma, 1, ",")
	case '"', '\'':
		return l.quoted(c)
	case '=':
		switch at(1) {
		case '=':
			return simple(tkOp, 2, "=")
		case '~':
			return simple(tkOp, 2, "=~")
		}
		return simple(tkOp, 1, "=")
	case '!':
		switch at(1) {
		case '=':
			return simple(tkOp, 2, "!=")
		case '~':
			return simple(tkOp, 2, "!~")
		}
		return simple(tkNot, 1, "!")
	case '~':
		return simple(tkOp, 1, "~")
	case '<':
		if at(1) == '=' {
			return simple(tkOp, 2, "<=")
		}
		return simple(tkOp, 1, "<")
	case '>':
		if at(1) == '=' {
			return simple(tkOp, 2, ">=")
		}
		return simple(tkOp, 1, ">")
	case '&':
		if at(1) == '&' {
			return simple(tkAnd, 2, "&&")
		}
		return l.errTok(start, start+1, `"&" is not an operator; use "&&" or "and"`)
	case '|':
		if at(1) == '|' {
			return simple(tkOr, 2, "||")
		}
		return l.errTok(start, start+1, `"|" is not an operator; use "||" or "or"`)
	}
	// Bare word.
	i := start
	for i < len(s) {
		b := s[i]
		if wordEnd(s, i, l.prev == tkOp || l.prev == tkComma) {
			break
		}
		if b < utf8.RuneSelf {
			if b < ' ' || b == 0x7f {
				return l.errTok(i, i+1, "control character in expression")
			}
			i++
			continue
		}
		r, w := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && w == 1 {
			return l.errTok(i, i+1, "invalid UTF-8 in expression")
		}
		if unicode.IsSpace(r) {
			break
		}
		i += w
	}
	l.pos = i
	text := s[start:i]
	kind := tkWord
	switch {
	case strings.EqualFold(text, "and"):
		kind = tkAnd
	case strings.EqualFold(text, "or"):
		kind = tkOr
	case strings.EqualFold(text, "not"):
		kind = tkNot
	}
	return token{kind: kind, pos: start, end: i, text: text}
}

// quoted scans a quoted string starting at l.pos. Inside, a backslash before
// the quote characters or another backslash yields that character; any other
// backslash is kept literally so regular expressions need no double escaping.
func (l *lexer) quoted(q byte) token {
	s := l.src
	start := l.pos
	i := start + 1
	var b strings.Builder
	plain := true
	for i < len(s) {
		c := s[i]
		switch {
		case c == q:
			l.pos = i + 1
			text := s[start+1 : i]
			if !plain {
				text = b.String()
			}
			return token{kind: tkString, pos: start, end: l.pos, text: text}
		case c == '\\' && i+1 < len(s) && (s[i+1] == '\\' || s[i+1] == '"' || s[i+1] == '\''):
			if plain {
				plain = false
				b.WriteString(s[start+1 : i])
			}
			b.WriteByte(s[i+1])
			i += 2
			continue
		}
		if !plain {
			b.WriteByte(c)
		}
		i++
	}
	return l.errTok(start, len(s), "unterminated quoted string: missing closing "+string(q))
}
