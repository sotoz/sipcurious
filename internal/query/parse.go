package query

import (
	"fmt"
	"strings"
)

// maxDepth bounds the nesting of parentheses and "not" so that hostile input
// cannot exhaust the stack.
const maxDepth = 200

// parser is a hand-written recursive-descent parser over the token slice.
//
//	expr    = or
//	or      = and { ("or" | "||") and }
//	and     = not { ("and" | "&&") not }
//	not     = ("not" | "!") not | primary
//	primary = "(" expr ")" | field op value | field "in" list | field | word
type parser struct {
	src  string
	toks []token
	i    int
	cs   bool
}

func (p *parser) peek(k int) token {
	if p.i+k < len(p.toks) {
		return p.toks[p.i+k]
	}
	return p.toks[len(p.toks)-1] // the EOF (or error) token
}

func (p *parser) next() token {
	t := p.peek(0)
	if p.i < len(p.toks)-1 {
		p.i++
	}
	return t
}

func (p *parser) errAt(pos, end int, msg string) *SyntaxError {
	return &SyntaxError{Pos: pos, Msg: msg, src: p.src, end: max(end, pos)}
}

// bad reports a problem at token t; a lexical error token supplies its own message.
func (p *parser) bad(t token, msg string) *SyntaxError {
	if t.kind == tkErr {
		msg = t.text
	}
	return p.errAt(t.pos, t.end, msg)
}

// describe names a token for diagnostics.
func (p *parser) describe(t token) string {
	switch t.kind {
	case tkEOF:
		return "the end of the expression"
	case tkString:
		return fmt.Sprintf("the quoted text %q", t.text)
	}
	return fmt.Sprintf("%q", p.src[t.pos:t.end])
}

// Parse compiles a filter expression. Every problem - bad syntax, an unknown
// field, an operator or value that does not fit the field's type, an invalid
// CIDR, regexp, number, duration or time - is returned as a *SyntaxError that
// carries the position of the offending token. An empty expression is an
// error; combine optional filters with And instead.
func Parse(src string, opt Options) (*Query, error) {
	p := &parser{src: src, cs: opt.CaseSensitive}
	lx := lexer{src: src}
	for {
		t := lx.next()
		p.toks = append(p.toks, t)
		if t.kind == tkEOF || t.kind == tkErr {
			break
		}
	}
	if t := p.toks[0]; t.kind == tkEOF {
		return nil, p.errAt(0, len(src), "empty expression; expected a condition such as: status >= 500")
	}
	n, err := p.or(0)
	if err != nil {
		return nil, err
	}
	if t := p.peek(0); t.kind != tkEOF {
		return nil, p.trailing(t)
	}
	return &Query{root: n, needsCalls: n.needsCalls(), opt: opt}, nil
}

// trailing explains why token t cannot follow a complete condition.
func (p *parser) trailing(t token) error {
	switch t.kind {
	case tkRParen:
		return p.bad(t, `unmatched ")": there is no "(" to close`)
	case tkOp:
		return p.bad(t, fmt.Sprintf("unexpected %s; the operator must follow a field name, and a condition takes only one", p.describe(t)))
	case tkWord, tkString, tkLParen:
		return p.bad(t, fmt.Sprintf(`unexpected %s: join conditions with "and" / "or" (quote the text to search for a phrase)`, p.describe(t)))
	}
	return p.bad(t, fmt.Sprintf(`unexpected %s: expected "and", "or" or the end of the expression`, p.describe(t)))
}

func (p *parser) or(depth int) (*node, error) {
	n, err := p.and(depth)
	if err != nil {
		return nil, err
	}
	kids := []*node{n}
	for p.peek(0).kind == tkOr {
		p.next()
		r, err := p.and(depth)
		if err != nil {
			return nil, err
		}
		kids = append(kids, r)
	}
	if len(kids) == 1 {
		return n, nil
	}
	return &node{kind: nOr, kids: kids}, nil
}

func (p *parser) and(depth int) (*node, error) {
	n, err := p.not(depth)
	if err != nil {
		return nil, err
	}
	kids := []*node{n}
	for p.peek(0).kind == tkAnd {
		p.next()
		r, err := p.not(depth)
		if err != nil {
			return nil, err
		}
		kids = append(kids, r)
	}
	if len(kids) == 1 {
		return n, nil
	}
	return &node{kind: nAnd, kids: kids}, nil
}

func (p *parser) not(depth int) (*node, error) {
	if t := p.peek(0); t.kind == tkNot {
		if depth >= maxDepth {
			return nil, p.bad(t, "expression nested too deeply")
		}
		p.next()
		c, err := p.not(depth + 1)
		if err != nil {
			return nil, err
		}
		return &node{kind: nNot, kids: []*node{c}}, nil
	}
	return p.primary(depth)
}

func (p *parser) primary(depth int) (*node, error) {
	t := p.peek(0)
	switch t.kind {
	case tkLParen:
		if depth >= maxDepth {
			return nil, p.bad(t, "expression nested too deeply")
		}
		p.next()
		n, err := p.or(depth + 1)
		if err != nil {
			return nil, err
		}
		if c := p.peek(0); c.kind != tkRParen {
			if c.kind == tkEOF {
				return nil, p.errAt(t.pos, t.end, `unclosed "(": add a matching ")"`)
			}
			if c.kind == tkErr {
				return nil, p.bad(c, "")
			}
			return nil, p.bad(c, fmt.Sprintf(`unexpected %s: expected ")" to close the "(" at column %d`, p.describe(c), p.column(t.pos)))
		}
		p.next()
		return n, nil
	case tkString:
		if k := p.peek(1).kind; k == tkOp {
			return nil, p.bad(t, "quoted text cannot be a field name; write the field name unquoted")
		}
		p.next()
		return p.wordLeaf(t.text)
	case tkWord:
		if p.opFollows() {
			return p.comparison()
		}
		p.next()
		return p.bareWord(t)
	case tkOp:
		return nil, p.bad(t, fmt.Sprintf("unexpected %s: an operator must come after a field name (for example status %s 500)", p.describe(t), t.text))
	case tkRParen:
		return nil, p.bad(t, `unexpected ")": expected a condition`)
	case tkComma:
		return nil, p.bad(t, `unexpected ",": a list is only valid after "in", inside parentheses`)
	case tkAnd, tkOr:
		return nil, p.bad(t, fmt.Sprintf("unexpected %s: expected a condition before it", p.describe(t)))
	case tkEOF:
		return nil, p.bad(t, "unexpected end of expression: expected a condition")
	}
	return nil, p.bad(t, "unexpected "+p.describe(t))
}

func (p *parser) column(pos int) int {
	e := SyntaxError{Pos: pos, src: p.src}
	return e.column() + 1
}

func isIn(t token) bool { return t.kind == tkWord && strings.EqualFold(t.text, "in") }

// opFollows reports whether the token after the current word starts an
// operator: = != ~ !~ =~ < <= > >=, "in" or "not in".
func (p *parser) opFollows() bool {
	n := p.peek(1)
	return n.kind == tkOp || isIn(n) || n.kind == tkNot && isIn(p.peek(2))
}

func (p *parser) searchField() *Field {
	f, _ := lookupField("raw")
	return f
}

// wordLeaf builds the substring search of a bare word over the raw message.
func (p *parser) wordLeaf(text string) (*node, error) {
	l, pr := buildLeaf(p.searchField(), "raw", opContains, false, []valSrc{{text: text}}, p.cs)
	if pr != nil {
		return nil, fmt.Errorf("internal error: word search: %s", pr.msg)
	}
	l.bare = true
	return &node{kind: nLeaf, leaf: l}, nil
}

// bareWord handles a word without operator: a boolean field, or a text search.
func (p *parser) bareWord(t token) (*node, error) {
	if name, ok := headerFieldName(t.text); ok {
		return &node{kind: nLeaf, leaf: trueLeaf(headerField(name, true), "header."+name)}, nil
	}
	if f, ok := lookupField(t.text); ok {
		if f.Type == TypeBool {
			return &node{kind: nLeaf, leaf: trueLeaf(f, f.Name)}, nil
		}
		return nil, p.bad(t, fmt.Sprintf("%q is %s field and needs an operator and a value, e.g. %s; quote the word (%q) to search for the text",
			t.text, typeNoun(f.Type), exampleFor(f), t.text))
	}
	return p.wordLeaf(t.text)
}

// exampleFor returns a short example condition for f.
func exampleFor(f *Field) string {
	switch f.Type {
	case TypeString:
		return f.Name + " ~ text"
	case TypeInt:
		return f.Name + " >= 100"
	case TypeFloat:
		return f.Name + " < 3.5"
	case TypeDuration:
		return f.Name + " > 3s"
	case TypeTime:
		return f.Name + " > 10:30"
	case TypeAddr:
		return f.Name + " = 10.0.0.0/8"
	case TypeEnum:
		if len(f.Values) > 0 {
			return f.Name + " = " + f.Values[0]
		}
	}
	return f.Name + " = value"
}

// comparison parses  field op value  or  field [not] in list.
func (p *parser) comparison() (*node, error) {
	ft := p.next()
	f, ok := lookupField(ft.text)
	if !ok {
		return nil, p.bad(ft, unknownFieldMsg(ft.text))
	}
	fname := f.Name
	if name, isHdr := headerFieldName(ft.text); isHdr {
		fname = "header." + name
	}
	ot := p.next()
	var op opKind
	neg := false
	switch {
	case ot.kind == tkOp:
		switch ot.text {
		case "=":
			op = opEq
		case "!=":
			op, neg = opEq, true
		case "~":
			op = opContains
		case "!~":
			op, neg = opContains, true
		case "=~":
			op = opRegex
		case "<":
			op = opLt
		case "<=":
			op = opLe
		case ">":
			op = opGt
		case ">=":
			op = opGe
		}
	case ot.kind == tkNot: // not in
		in := p.next()
		op, neg = opIn, true
		ot.end = in.end
	default: // in
		op = opIn
	}
	var vals []valSrc
	if op == opIn {
		var err error
		if vals, err = p.list(f, ot); err != nil {
			return nil, err
		}
	} else {
		v, err := p.value(f, ot)
		if err != nil {
			return nil, err
		}
		vals = []valSrc{v}
	}
	l, pr := buildLeaf(f, fname, op, neg, vals, p.cs)
	if pr != nil {
		pos, end := ot.pos, ot.end
		if pr.val >= 0 {
			v := vals[pr.val]
			pos, end = v.pos, v.end
			if pr.off > 0 {
				pos = min(v.pos+pr.off+b2int(v.quoted), end-1)
			}
		} else if pr.val == -1 {
			pos, end = ot.pos, ot.end
		}
		return nil, p.errAt(pos, end, pr.msg)
	}
	return &node{kind: nLeaf, leaf: l}, nil
}

func b2int(b bool) int {
	if b {
		return 1
	}
	return 0
}

func unknownFieldMsg(word string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "unknown field %q", word)
	if s := suggestField(word); s != "" {
		fmt.Fprintf(&b, "; did you mean %q?", s)
	} else {
		b.WriteByte(';')
	}
	b.WriteString(" valid fields: ")
	b.WriteString(strings.Join(fieldNames(), ", "))
	b.WriteString(", header.<Name>")
	return b.String()
}

// value parses one value after operator token op.
func (p *parser) value(f *Field, op token) (valSrc, error) {
	t := p.peek(0)
	switch t.kind {
	case tkWord, tkString:
		p.next()
		v := valSrc{text: t.text, pos: t.pos, end: t.end, quoted: t.kind == tkString}
		if f.Type == TypeTime && t.kind == tkWord && isDate(t.text) {
			// "2024-05-01 10:30:00" without quotes: a date followed by a time of day.
			if n := p.peek(0); n.kind == tkWord && n.pos > t.end && p.src[t.end:n.pos] == " " {
				if _, _, _, _, ok := parseTimeOfDay(n.text); ok {
					p.next()
					v.text, v.end = t.text+" "+n.text, n.end
				}
			}
		}
		return v, nil
	case tkAnd, tkOr, tkNot:
		return valSrc{}, p.bad(t, fmt.Sprintf("%s is a keyword, not a value; quote it to use it as text", p.describe(t)))
	case tkLParen:
		return valSrc{}, p.bad(t, fmt.Sprintf(`a parenthesised list is only valid after "in", not after %q`, p.src[op.pos:op.end]))
	}
	if t.kind == tkEOF || t.kind == tkRParen {
		return valSrc{}, p.errAt(t.pos, t.end, fmt.Sprintf("expected a value after %q", p.src[op.pos:op.end]))
	}
	return valSrc{}, p.bad(t, fmt.Sprintf("expected a value after %q, found %s", p.src[op.pos:op.end], p.describe(t)))
}

// list parses the values after "in": a single value or "(" v {"," v} ")".
func (p *parser) list(f *Field, op token) ([]valSrc, error) {
	open := p.peek(0)
	if open.kind != tkLParen {
		v, err := p.value(f, op)
		if err != nil {
			return nil, err
		}
		return []valSrc{v}, nil
	}
	p.next()
	var vals []valSrc
	for {
		t := p.peek(0)
		if t.kind == tkRParen && len(vals) == 0 {
			return nil, p.bad(t, `empty list: put at least one value between "(" and ")"`)
		}
		v, err := p.value(f, op)
		if err != nil {
			if t.kind == tkEOF {
				return nil, p.errAt(open.pos, open.end, `unclosed "(": add a matching ")"`)
			}
			return nil, err
		}
		vals = append(vals, v)
		switch c := p.peek(0); c.kind {
		case tkComma:
			p.next()
		case tkRParen:
			p.next()
			return vals, nil
		case tkEOF:
			return nil, p.errAt(open.pos, open.end, `unclosed "(": add a matching ")"`)
		default:
			return nil, p.bad(c, fmt.Sprintf(`unexpected %s in a list: separate values with "," and end with ")"`, p.describe(c)))
		}
	}
}

// isDate reports whether s looks like YYYY-MM-DD.
func isDate(s string) bool {
	if len(s) != 10 || s[4] != '-' || s[7] != '-' {
		return false
	}
	for i := range len(s) {
		if i != 4 && i != 7 && (s[i] < '0' || s[i] > '9') {
			return false
		}
	}
	return true
}
