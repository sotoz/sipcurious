// Package query implements the filter expression language of sipcurious: a
// small, typed boolean language over SIP messages and calls
// ("from ~ alice and status >= 500", "duration > 30s and not has_media").
//
// Parse type-checks an expression and compiles it into a Query that can be
// evaluated against a single message (MatchMessage) or a whole call
// (MatchCall). Fields come from a registry (RegisterField, Fields), so new
// fields appear in the language and in Help without touching the parser.
package query

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/sotoz/sipcurious/internal/call"
	"github.com/sotoz/sipcurious/internal/trace"
)

// Options tunes Parse.
type Options struct {
	// CaseSensitive makes string equality, substring and regexp matches
	// case-sensitive. The default is case-insensitive. Enum fields (state,
	// kind, transport...) always match case-insensitively.
	CaseSensitive bool
}

// Query is a compiled filter expression. It is immutable and safe for
// concurrent use. A nil *Query matches everything.
type Query struct {
	root       *node
	needsCalls bool
	opt        Options
}

type nodeKind uint8

const (
	nLeaf nodeKind = iota + 1
	nAnd
	nOr
	nNot
)

// node is one element of the compiled expression tree. Leaves hold predicates
// (closures) specialised at Parse time; evaluation walks the tree with
// concrete method calls so that a trace.Message is never copied to the heap.
type node struct {
	kind nodeKind
	kids []*node
	leaf *leaf
}

func (n *node) needsCalls() bool {
	if n.kind == nLeaf {
		return n.leaf.f.Call != nil
	}
	for _, k := range n.kids {
		if k.needsCalls() {
			return true
		}
	}
	return false
}

// matchMsg evaluates n on one message; call-field leaves read c.
func (n *node) matchMsg(m *trace.Message, c *call.Call) bool {
	switch n.kind {
	case nLeaf:
		l := n.leaf
		if l.f.Call != nil {
			return c != nil && l.onCall(c)
		}
		return l.onMsg(m)
	case nAnd:
		for _, k := range n.kids {
			if !k.matchMsg(m, c) {
				return false
			}
		}
		return true
	case nOr:
		for _, k := range n.kids {
			if k.matchMsg(m, c) {
				return true
			}
		}
		return false
	case nNot:
		return !n.kids[0].matchMsg(m, c)
	}
	return false
}

// matchCall evaluates n on a call; message-field leaves are existential over
// the call's messages.
func (n *node) matchCall(c *call.Call) bool {
	switch n.kind {
	case nLeaf:
		l := n.leaf
		if l.f.Call != nil {
			return l.onCall(c)
		}
		for i := range c.Messages {
			if l.onMsg(&c.Messages[i]) {
				return true
			}
		}
		return false
	case nAnd:
		for _, k := range n.kids {
			if !k.matchCall(c) {
				return false
			}
		}
		return true
	case nOr:
		for _, k := range n.kids {
			if k.matchCall(c) {
				return true
			}
		}
		return false
	case nNot:
		return !n.kids[0].matchCall(c)
	}
	return false
}

// MatchMessage reports whether message m satisfies the query. Message fields
// are read from m. Call fields (state, duration, ...) are read from c, the call
// m belongs to; when the query NeedsCalls and c is nil, every call-field
// comparison is false (also the negated ones such as "state != failed"), so
// "not state = failed" is true for a nil c. A nil *Query matches everything.
func (q *Query) MatchMessage(m trace.Message, c *call.Call) bool {
	if q == nil {
		return true
	}
	return q.root.matchMsg(&m, c)
}

// MatchCall reports whether call c satisfies the query. A comparison on a
// message field is true if ANY message of the call satisfies it, and each
// comparison is judged separately: "from ~ alice and status >= 500" selects
// calls that contain a message from alice and a message with a 5xx status, not
// necessarily the same one. Negation applies to that result: "not status >= 500"
// is a call without any such message, while "status != 500" is a call with at
// least one message whose status is not 500 (requests count). A call without
// messages matches no message-field comparison. A nil *Query matches everything.
func (q *Query) MatchCall(c *call.Call) bool {
	if q == nil {
		return true
	}
	return q.root.matchCall(c)
}

// NeedsCalls reports whether the query uses call-level fields, i.e. whether
// MatchMessage needs a non-nil call. It is false for a nil *Query.
func (q *Query) NeedsCalls() bool { return q != nil && q.needsCalls }

// And combines queries: the result matches when all of them match. Nil
// queries are skipped (nil means "match all"); with no non-nil query the
// result is nil.
func And(qs ...*Query) *Query {
	var kids []*node
	var out *Query
	for _, q := range qs {
		if q == nil {
			continue
		}
		if out == nil {
			out = &Query{opt: q.opt}
		}
		out.needsCalls = out.needsCalls || q.needsCalls
		if q.root.kind == nAnd {
			kids = append(kids, q.root.kids...)
		} else {
			kids = append(kids, q.root)
		}
	}
	switch len(kids) {
	case 0:
		return nil
	case 1:
		out.root = kids[0]
		return out
	}
	out.root = &node{kind: nAnd, kids: kids}
	return out
}

// Contains returns the query "field contains text" (the ~ operator) with text
// taken literally. It is meant for CLI flags with a fixed field name: it panics
// if field is not a registered string field.
func Contains(field, text string, caseSensitive bool) *Query {
	f, ok := lookupField(field)
	if !ok || f.Type != TypeString {
		panic(fmt.Sprintf("query.Contains: %q is not a string field", field))
	}
	return mustLeaf(f, f.Name, opContains, text, caseSensitive)
}

// Eq returns the query "field = value" with value taken literally (so "10.0.0.1",
// "4xx", "250ms" work as in an expression, but no quoting or operators are
// interpreted). The error describes a value that does not fit the field's type.
func Eq(field, value string, caseSensitive bool) (*Query, error) {
	f, ok := lookupField(field)
	if !ok {
		return nil, errors.New(unknownFieldMsg(field))
	}
	return literalQuery(f, opEq, value, caseSensitive)
}

// InCIDR returns the query "field in cidr" for an address field (src, dst,
// caller, callee). cidr may also be a plain IP address.
func InCIDR(field string, cidr string) (*Query, error) {
	f, ok := lookupField(field)
	if !ok {
		return nil, errors.New(unknownFieldMsg(field))
	}
	if f.Type != TypeAddr {
		return nil, fmt.Errorf("field %q is %s field, not an address", field, typeNoun(f.Type))
	}
	return literalQuery(f, opIn, cidr, false)
}

func literalQuery(f *Field, op opKind, text string, cs bool) (*Query, error) {
	l, pr := buildLeaf(f, f.Name, op, false, []valSrc{{text: text}}, cs)
	if pr != nil {
		return nil, errors.New(pr.msg)
	}
	n := &node{kind: nLeaf, leaf: l}
	return &Query{root: n, needsCalls: n.needsCalls(), opt: Options{CaseSensitive: cs}}, nil
}

func mustLeaf(f *Field, name string, op opKind, text string, cs bool) *Query {
	q, err := literalQuery(f, op, text, cs)
	if err != nil {
		panic("query: " + err.Error())
	}
	return q
}

// String returns the normalised expression: canonical field names, explicit
// operators, one space between tokens, values quoted where needed and
// parentheses only where precedence requires them. Parsing the result gives an
// equivalent query (with the same Options). A nil query returns "".
func (q *Query) String() string {
	if q == nil {
		return ""
	}
	var b strings.Builder
	q.root.write(&b, precOr)
	return b.String()
}

const (
	precOr = iota
	precAnd
	precNot
)

func (n *node) write(b *strings.Builder, ctx int) {
	switch n.kind {
	case nLeaf:
		n.leaf.write(b)
	case nAnd, nOr:
		prec, sep := precAnd, " and "
		if n.kind == nOr {
			prec, sep = precOr, " or "
		}
		paren := ctx > prec
		if paren {
			b.WriteByte('(')
		}
		for i, k := range n.kids {
			if i > 0 {
				b.WriteString(sep)
			}
			k.write(b, prec+1)
		}
		if paren {
			b.WriteByte(')')
		}
	case nNot:
		b.WriteString("not ")
		n.kids[0].write(b, precNot)
	}
}

func (l *leaf) write(b *strings.Builder) {
	if l.bare {
		if l.f.id == fRaw {
			b.WriteString(quoteAlways(l.lits[0]))
		} else {
			b.WriteString(l.fname)
		}
		return
	}
	b.WriteString(l.fname)
	b.WriteByte(' ')
	b.WriteString(l.op.text(l.neg))
	b.WriteByte(' ')
	if l.op == opIn {
		b.WriteByte('(')
		for i, s := range l.lits {
			if i > 0 {
				b.WriteString(", ")
			}
			b.WriteString(quote(s))
		}
		b.WriteByte(')')
		return
	}
	b.WriteString(quote(l.lits[0]))
}

// quote renders a value so that the lexer reads it back as the same text: bare
// when that is unambiguous, otherwise in double quotes.
func quote(s string) string {
	if bareSafe(s) {
		return s
	}
	return quoteAlways(s)
}

func bareSafe(s string) bool {
	if s == "" {
		return false
	}
	switch strings.ToLower(s) {
	case "and", "or", "not", "in":
		return false
	}
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			continue
		}
		if r == utf8.RuneError || r >= utf8.RuneSelf || strings.IndexRune("._-:@/+%", r) < 0 {
			return false
		}
	}
	return true
}

// quoteAlways double-quotes s. A backslash is doubled only where the lexer
// would otherwise treat it as an escape (before \, " or ', or at the end).
func quoteAlways(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for i := range len(s) {
		c := s[i]
		switch {
		case c == '"':
			b.WriteString(`\"`)
		case c == '\\' && (i+1 == len(s) || s[i+1] == '\\' || s[i+1] == '"' || s[i+1] == '\''):
			b.WriteString(`\\`)
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
	return b.String()
}
