package query

import (
	"errors"
	"fmt"
	"math"
	"net/netip"
	"regexp"
	"regexp/syntax"
	"strconv"
	"strings"
	"time"
)

// opKind is a comparison operator after normalisation: "!=", "!~" and "not in"
// are the positive operator with leaf.neg set.
type opKind uint8

const (
	opEq opKind = iota + 1
	opLt
	opLe
	opGt
	opGe
	opIn
	opContains
	opRegex
)

func (o opKind) text(neg bool) string {
	switch o {
	case opEq:
		if neg {
			return "!="
		}
		return "="
	case opLt:
		return "<"
	case opLe:
		return "<="
	case opGt:
		return ">"
	case opGe:
		return ">="
	case opIn:
		if neg {
			return "not in"
		}
		return "in"
	case opContains:
		if neg {
			return "!~"
		}
		return "~"
	case opRegex:
		return "=~"
	}
	return "?"
}

// opAllowed lists the operators of each type, in the order shown to users.
var opAllowed = map[Type][]string{
	TypeString:   {"=", "!=", "~", "!~", "=~", "in", "not in"},
	TypeEnum:     {"=", "!=", "in", "not in"},
	TypeInt:      {"=", "!=", "<", "<=", ">", ">=", "in", "not in"},
	TypeFloat:    {"=", "!=", "<", "<=", ">", ">=", "in", "not in"},
	TypeDuration: {"=", "!=", "<", "<=", ">", ">=", "in", "not in"},
	TypeTime:     {"=", "!=", "<", "<=", ">", ">=", "in", "not in"},
	TypeBool:     {"=", "!="},
	TypeAddr:     {"=", "!=", "in", "not in"},
}

func opOK(t Type, op opKind, neg bool) bool {
	if op == opRegex && neg {
		return false
	}
	want := op.text(neg)
	for _, s := range opAllowed[t] {
		if s == want {
			return true
		}
	}
	return false
}

// valSrc is one value as written: its text (unescaped) and where it was.
type valSrc struct {
	text     string
	pos, end int
	quoted   bool
}

// problem is a type error found while compiling a leaf. val is the index of
// the offending value (-1: the operator) and off the byte offset inside the
// value text where the problem starts (regexps).
type problem struct {
	val, off int
	msg      string
}

func opProblem(f *Field, fname string, op opKind, neg bool) *problem {
	return &problem{val: -1, msg: fmt.Sprintf("operator %q does not apply to %s field %q; use %s",
		op.text(neg), typeNoun(f.Type), fname, strings.Join(opAllowed[f.Type], " "))}
}

func typeNoun(t Type) string {
	if t == TypeInt || t == TypeEnum || t == TypeAddr {
		return "an " + t.String()
	}
	return "a " + t.String()
}

// leaf is one compiled comparison.
type leaf struct {
	f     *Field
	fname string // spelling used by String
	op    opKind
	neg   bool
	bare  bool     // written without operator: boolean field, or bare word search
	lits  []string // canonical value literals for String

	sp func(string) bool
	np func(int64) bool
	fp func(float64) bool
	ap func(netip.Addr) bool

	// tod marks a time field compared with a time of day: tp(n, ref) tests the
	// instant n against the ranges placed on the calendar day (UTC) of ref.
	tod bool
	tp  func(n, ref int64) bool
}

// buildLeaf type-checks op and vals against f and compiles the predicate.
func buildLeaf(f *Field, fname string, op opKind, neg bool, vals []valSrc, caseSensitive bool) (*leaf, *problem) {
	if !opOK(f.Type, op, neg) {
		return nil, opProblem(f, fname, op, neg)
	}
	l := &leaf{f: f, fname: fname, op: op, neg: neg}
	var pr *problem
	switch f.Type {
	case TypeString:
		pr = l.compileString(vals, caseSensitive)
	case TypeEnum:
		pr = l.compileEnum(vals)
	case TypeInt, TypeDuration, TypeTime:
		pr = l.compileInt(vals)
	case TypeFloat:
		pr = l.compileFloat(vals)
	case TypeBool:
		pr = l.compileBool(vals)
	case TypeAddr:
		pr = l.compileAddr(vals)
	}
	if pr != nil {
		return nil, pr
	}
	return l, nil
}

func trueLeaf(f *Field, name string) *leaf {
	return &leaf{f: f, fname: name, op: opEq, bare: true, lits: []string{"true"}, np: func(n int64) bool { return n == 1 }}
}

// ---- strings ---------------------------------------------------------------

func (l *leaf) compileString(vals []valSrc, cs bool) *problem {
	texts := make([]string, len(vals))
	for i, v := range vals {
		texts[i] = v.text
	}
	l.lits = texts
	switch l.op {
	case opEq, opIn:
		switch {
		case len(texts) == 1 && cs:
			t := texts[0]
			l.sp = func(s string) bool { return s == t }
		case len(texts) == 1:
			t := texts[0]
			l.sp = func(s string) bool { return strings.EqualFold(s, t) }
		case cs:
			l.sp = func(s string) bool {
				for _, t := range texts {
					if s == t {
						return true
					}
				}
				return false
			}
		default:
			l.sp = func(s string) bool {
				for _, t := range texts {
					if strings.EqualFold(s, t) {
						return true
					}
				}
				return false
			}
		}
	case opContains:
		t := texts[0]
		if cs {
			l.sp = func(s string) bool { return strings.Contains(s, t) }
		} else {
			fo := newFolder(t)
			l.sp = fo.contains
		}
	case opRegex:
		pat := texts[0]
		re, err := regexp.Compile(pat)
		if err != nil {
			return &problem{val: 0, off: regexpErrOffset(err, pat), msg: "invalid regular expression: " + regexpMsg(err)}
		}
		if !cs {
			// pat compiled on its own, so the flag prefix cannot break it.
			re = regexp.MustCompile("(?i)" + pat)
		}
		l.sp = re.MatchString
	}
	return nil
}

// regexpMsg turns "error parsing regexp: missing closing ): `(abc`" into
// "missing closing ): `(abc`".
func regexpMsg(err error) string {
	return strings.TrimPrefix(err.Error(), "error parsing regexp: ")
}

// regexpErrOffset finds where in pat the fragment named by a regexp error
// starts (0 if it cannot be found).
func regexpErrOffset(err error, pat string) int {
	var se *syntax.Error
	if errors.As(err, &se) && se.Expr != "" {
		if i := strings.Index(pat, se.Expr); i >= 0 {
			return i
		}
	}
	return 0
}

// ---- enums -----------------------------------------------------------------

func (l *leaf) compileEnum(vals []valSrc) *problem {
	canon := make([]string, len(vals))
	for i, v := range vals {
		canon[i] = v.text
		if len(l.f.Values) == 0 || v.text == "" {
			continue // "" matches the empty value (ended_by = "")
		}
		found := false
		for _, want := range l.f.Values {
			if strings.EqualFold(want, v.text) {
				canon[i], found = want, true
				break
			}
		}
		if !found {
			msg := fmt.Sprintf("%q is not a valid %s", v.text, l.fname)
			if best := closest(v.text, l.f.Values); best != "" {
				msg += fmt.Sprintf(" (did you mean %q?)", best)
			}
			return &problem{val: i, msg: msg + "; values: " + strings.Join(l.f.Values, ", ")}
		}
	}
	l.lits = canon
	if len(canon) == 1 {
		t := canon[0]
		l.sp = func(s string) bool { return strings.EqualFold(s, t) }
		return nil
	}
	l.sp = func(s string) bool {
		for _, t := range canon {
			if strings.EqualFold(s, t) {
				return true
			}
		}
		return false
	}
	return nil
}

// closest returns the candidate nearest to s by edit distance, if near enough.
func closest(s string, cands []string) string {
	best, bestD := "", 1<<30
	for _, c := range cands {
		if d := editDistance(strings.ToLower(s), strings.ToLower(c)); d < bestD {
			best, bestD = c, d
		}
	}
	if bestD <= max(1, min(3, len(s)/3)) && bestD < len(s) {
		return best
	}
	return ""
}

// ---- integers, durations, times --------------------------------------------

type irange struct{ lo, hi int64 }

func (l *leaf) compileInt(vals []valSrc) *problem {
	rs := make([]irange, len(vals))
	lits := make([]string, len(vals))
	tod := false
	for i, v := range vals {
		r, lit, isTod, msg := parseIntValue(l.f, v.text)
		if msg != "" {
			return &problem{val: i, msg: msg}
		}
		if l.f.Type == TypeTime {
			if i > 0 && isTod != tod {
				return &problem{val: i, msg: "cannot mix a time of day (HH:MM) with dates in one condition"}
			}
			tod = isTod
		}
		if strings.Contains(v.text, "..") && l.op != opEq && l.op != opIn {
			return &problem{val: i, msg: fmt.Sprintf("a range is only valid with = and in, not with %q", l.op.text(l.neg))}
		}
		rs[i], lits[i] = r, lit
	}
	l.lits = lits
	test := intPredicate(l.op, rs)
	if tod {
		l.tod = true
		l.tp = func(n, ref int64) bool { return test(n - (ref - timeOfDay(ref))) }
	} else {
		l.np = test
	}
	return nil
}

const dayNs = int64(24 * time.Hour)

// timeOfDay returns the UTC time of day of n (unix ns) in nanoseconds.
func timeOfDay(n int64) int64 {
	r := n % dayNs
	if r < 0 {
		r += dayNs
	}
	return r
}

func intPredicate(op opKind, rs []irange) func(int64) bool {
	test := func(n int64) bool {
		switch op {
		case opEq, opIn:
			for _, r := range rs {
				if n >= r.lo && n <= r.hi {
					return true
				}
			}
			return false
		case opLt:
			return n < rs[0].lo
		case opLe:
			return n <= rs[0].hi
		case opGt:
			return n > rs[0].hi
		case opGe:
			return n >= rs[0].lo
		}
		return false
	}
	if len(rs) == 1 && (op == opEq || op == opIn) {
		lo, hi := rs[0].lo, rs[0].hi
		if lo == hi {
			return func(n int64) bool { return n == lo }
		}
		return func(n int64) bool { return n >= lo && n <= hi }
	}
	return test
}

// parseIntValue parses one value of an int, duration or time field. It returns
// the inclusive range it denotes, the canonical literal, whether it is a time
// of day, and an error message ("" if fine).
func parseIntValue(f *Field, text string) (r irange, lit string, tod bool, msg string) {
	if a, b, ok := strings.Cut(text, ".."); ok {
		ra, la, ta, m := parseIntScalar(f, a, false)
		if m != "" {
			return r, "", false, m
		}
		rb, lb, tb, m := parseIntScalar(f, b, false)
		if m != "" {
			return r, "", false, m
		}
		if ta != tb {
			return r, "", false, "cannot mix a time of day (HH:MM) with dates in one range"
		}
		if ra.lo > rb.hi {
			return r, "", false, fmt.Sprintf("empty range: %s is greater than %s", la, lb)
		}
		return irange{ra.lo, rb.hi}, la + ".." + lb, ta, ""
	}
	return parseIntScalar(f, text, f.classes)
}

func parseIntScalar(f *Field, text string, classes bool) (r irange, lit string, tod bool, msg string) {
	text = strings.TrimSpace(text)
	switch f.Type {
	case TypeInt:
		if classes && len(text) == 3 && text[0] >= '1' && text[0] <= '9' && strings.EqualFold(text[1:], "xx") {
			lo := int64(text[0]-'0') * 100
			return irange{lo, lo + 99}, text[:1] + "xx", false, ""
		}
		n, err := strconv.ParseInt(text, 10, 64)
		if err != nil {
			hint := "e.g. 486"
			if f.classes {
				hint = "e.g. 486 or 4xx"
			}
			return r, "", false, fmt.Sprintf("%q is not an integer (%s is an int field, %s)", text, f.Name, hint)
		}
		return irange{n, n}, strconv.FormatInt(n, 10), false, ""
	case TypeDuration:
		d, err := time.ParseDuration(text)
		if f, ok := parseFloat(text); err != nil && ok && math.Abs(f) < 9e9 {
			d, err = time.Duration(f*float64(time.Second)), nil // a bare number is seconds
		}
		if err != nil {
			return r, "", false, fmt.Sprintf("%q is not a duration with a unit (%s is a duration field, e.g. 250ms, 3s, 1m30s)", text, f.Name)
		}
		return irange{int64(d), int64(d)}, d.String(), false, ""
	case TypeTime:
		return parseTimeScalar(f, text)
	}
	return r, "", false, "unsupported type"
}

// ---- times -----------------------------------------------------------------

var timeLayouts = []struct {
	layout string
	gran   time.Duration // precision when there is no fraction; 0 = derive from the fraction
}{
	{"2006-01-02T15:04:05.999999999Z07:00", 0},
	{"2006-01-02 15:04:05.999999999Z07:00", 0},
	{"2006-01-02T15:04:05.999999999", 0},
	{"2006-01-02 15:04:05.999999999", 0},
	{"2006-01-02T15:04", time.Minute},
	{"2006-01-02 15:04", time.Minute},
	{"2006-01-02", 24 * time.Hour},
}

const timeHint = `use RFC3339 (2024-05-01T10:00:00Z), "2024-05-01 10:00:00" (UTC), a date (2024-05-01) or a time of day (10:30, 10:30:15)`

func parseTimeScalar(f *Field, text string) (r irange, lit string, tod bool, msg string) {
	bad := fmt.Sprintf("%q is not a time (%s is a time field; %s)", text, f.Name, timeHint)
	if h, m, s, frac, ok := parseTimeOfDay(text); ok {
		gran := int64(time.Second)
		switch {
		case frac > 0:
			gran = int64(math.Pow10(9 - frac))
		case s < 0:
			gran = int64(time.Minute)
		}
		lo := (int64(h)*3600+int64(m)*60+int64(max(s, 0)))*int64(time.Second) + fracNs(text, frac)
		return irange{lo, lo + gran - 1}, text, true, ""
	}
	for _, tl := range timeLayouts {
		t, err := time.Parse(tl.layout, text)
		if err != nil {
			continue
		}
		if t.Year() < 1700 || t.Year() > 2200 {
			return r, "", false, fmt.Sprintf("%q is outside the supported years 1700-2200", text)
		}
		gran := int64(tl.gran)
		if gran == 0 {
			gran = int64(time.Second)
			if i := strings.IndexByte(text, '.'); i >= 0 {
				n := 0
				for j := i + 1; j < len(text) && text[j] >= '0' && text[j] <= '9'; j++ {
					n++
				}
				gran = int64(math.Pow10(9 - min(n, 9)))
			}
		}
		lo := t.UnixNano()
		return irange{lo, lo + gran - 1}, text, false, ""
	}
	return r, "", false, bad
}

// parseTimeOfDay parses H:MM, HH:MM, HH:MM:SS and HH:MM:SS.fraction. s is -1
// when seconds are absent; frac is the number of fractional digits.
func parseTimeOfDay(text string) (h, m, s, frac int, ok bool) {
	parts := strings.Split(text, ":")
	if len(parts) < 2 || len(parts) > 3 {
		return
	}
	num := func(p string, maxLen int) (int, bool) {
		if p == "" || len(p) > maxLen {
			return 0, false
		}
		n := 0
		for i := 0; i < len(p); i++ {
			if p[i] < '0' || p[i] > '9' {
				return 0, false
			}
			n = n*10 + int(p[i]-'0')
		}
		return n, true
	}
	var ok1, ok2 bool
	if h, ok1 = num(parts[0], 2); !ok1 || h > 23 {
		return
	}
	if m, ok2 = num(parts[1], 2); !ok2 || m > 59 || len(parts[1]) != 2 {
		return
	}
	s = -1
	if len(parts) == 3 {
		sec, fr, hasFrac := strings.Cut(parts[2], ".")
		var ok3 bool
		if s, ok3 = num(sec, 2); !ok3 || s > 59 || len(sec) != 2 {
			return 0, 0, 0, 0, false
		}
		if hasFrac {
			if fr == "" || len(fr) > 9 {
				return 0, 0, 0, 0, false
			}
			if _, ok4 := num(fr, 9); !ok4 {
				return 0, 0, 0, 0, false
			}
			frac = len(fr)
		}
	}
	return h, m, s, frac, true
}

// fracNs returns the fractional-second part of a time of day as nanoseconds.
func fracNs(text string, frac int) int64 {
	if frac == 0 {
		return 0
	}
	i := strings.IndexByte(text, '.')
	n, _ := strconv.ParseInt(text[i+1:], 10, 64)
	return n * int64(math.Pow10(9-frac))
}

// ---- floats ----------------------------------------------------------------

type frange struct{ lo, hi float64 }

func (l *leaf) compileFloat(vals []valSrc) *problem {
	rs := make([]frange, len(vals))
	lits := make([]string, len(vals))
	for i, v := range vals {
		a, b, isRange := strings.Cut(v.text, "..")
		if !isRange {
			b = a
		} else if l.op != opEq && l.op != opIn {
			return &problem{val: i, msg: fmt.Sprintf("a range is only valid with = and in, not with %q", l.op.text(l.neg))}
		}
		lo, ok1 := parseFloat(a)
		hi, ok2 := parseFloat(b)
		if !ok1 || !ok2 {
			bad := a
			if ok1 {
				bad = b
			}
			return &problem{val: i, msg: fmt.Sprintf("%q is not a number (%s is a float field, e.g. 3.5)", strings.TrimSpace(bad), l.f.Name)}
		}
		if lo > hi {
			return &problem{val: i, msg: fmt.Sprintf("empty range: %s is greater than %s", fmtFloat(lo), fmtFloat(hi))}
		}
		rs[i] = frange{lo, hi}
		lits[i] = fmtFloat(lo)
		if isRange {
			lits[i] += ".." + fmtFloat(hi)
		}
	}
	l.lits = lits
	op := l.op
	l.fp = func(x float64) bool {
		switch op {
		case opEq, opIn:
			for _, r := range rs {
				if x >= r.lo && x <= r.hi {
					return true
				}
			}
		case opLt:
			return x < rs[0].lo
		case opLe:
			return x <= rs[0].hi
		case opGt:
			return x > rs[0].hi
		case opGe:
			return x >= rs[0].lo
		}
		return false
	}
	return nil
}

func parseFloat(s string) (float64, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c == '.' || c == '-' || c == '+' || c == 'e' || c == 'E') {
			return 0, false
		}
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
		return 0, false
	}
	return f, true
}

func fmtFloat(f float64) string { return strconv.FormatFloat(f, 'g', -1, 64) }

// ---- booleans and addresses --------------------------------------------------

func (l *leaf) compileBool(vals []valSrc) *problem {
	var want int64
	switch strings.ToLower(vals[0].text) {
	case "true", "yes", "on", "1":
		want = 1
		l.lits = []string{"true"}
	case "false", "no", "off", "0":
		l.lits = []string{"false"}
	default:
		return &problem{val: 0, msg: fmt.Sprintf("%q is not a boolean (%s is a bool field; use true or false)", vals[0].text, l.f.Name)}
	}
	l.np = func(n int64) bool { return n == want }
	return nil
}

func (l *leaf) compileAddr(vals []valSrc) *problem {
	type net struct {
		addr   netip.Addr
		prefix netip.Prefix
		isPfx  bool
	}
	nets := make([]net, len(vals))
	lits := make([]string, len(vals))
	for i, v := range vals {
		text := strings.TrimSpace(v.text)
		if strings.Contains(text, "/") {
			p, err := netip.ParsePrefix(text)
			if err != nil {
				return &problem{val: i, msg: fmt.Sprintf("%q is not a valid CIDR (%s is an addr field, e.g. 10.0.0.0/8, 2001:db8::/32)", text, l.f.Name)}
			}
			if p.Addr().Is4In6() && p.Bits() >= 96 {
				p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
			}
			nets[i], lits[i] = net{prefix: p, isPfx: true}, p.String()
			continue
		}
		a, err := netip.ParseAddr(text)
		if err != nil || a.Zone() != "" {
			return &problem{val: i, msg: fmt.Sprintf("%q is not an IP address or CIDR (%s is an addr field, e.g. 10.0.0.1, 10.0.0.0/8, 2001:db8::1)", text, l.f.Name)}
		}
		a = a.Unmap()
		nets[i], lits[i] = net{addr: a}, a.String()
	}
	l.lits = lits
	if len(nets) == 1 {
		n := nets[0]
		if n.isPfx {
			l.ap = n.prefix.Contains
		} else {
			l.ap = func(a netip.Addr) bool { return a == n.addr }
		}
		return nil
	}
	l.ap = func(a netip.Addr) bool {
		for _, n := range nets {
			if n.isPfx && n.prefix.Contains(a) || !n.isPfx && a == n.addr {
				return true
			}
		}
		return false
	}
	return nil
}
