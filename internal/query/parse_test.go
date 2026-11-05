package query

import (
	"errors"
	"strings"
	"testing"
)

func TestParseValid(t *testing.T) {
	tests := []struct{ src, want string }{
		{"status >= 500", "status >= 500"},
		{"status>=500", "status >= 500"},
		{"STATUS  =  4XX", "status = 4xx"},
		{"code = 404", "status = 404"},
		{"status != 486", "status != 486"},
		{"status == 486", "status = 486"},
		{"status in (404, 500..599)", "status in (404, 500..599)"},
		{"status not in (404,486)", "status not in (404, 486)"},
		{"status in 404", "status in (404)"},
		{"method IN (invite, bye)", "method in (invite, bye)"},
		{"from ~ alice", "from ~ alice"},
		{"from !~ alice", "from !~ alice"},
		{"uri =~ '^sip:\\+49'", `uri =~ "^sip:\+49"`},
		{`from ~ "Alice Smith"`, `from ~ "Alice Smith"`},
		{`from ~ 'Alice Smith'`, `from ~ "Alice Smith"`},
		{`from ~ "say \"hi\""`, `from ~ "say \"hi\""`},
		{`from ~ 'it\'s'`, `from ~ "it's"`},
		{`from ~ ""`, `from ~ ""`},
		{"has_sdp", "has_sdp"},
		{"not has_sdp", "not has_sdp"},
		{"!has_sdp", "not has_sdp"},
		{"has_sdp = false", "has_sdp = false"},
		{"is_request = yes", "is_request = true"},
		{"alice", `"alice"`},
		{`"two words"`, `"two words"`},
		{"alice bob", ""}, // invalid, see TestParseErrors; guarded below
		{"a or b and c", `"a" or "b" and "c"`},
		{"(a or b) and c", `("a" or "b") and "c"`},
		{"a and (b or c)", `"a" and ("b" or "c")`},
		{"a && b || c", `"a" and "b" or "c"`},
		{"a || b && c", `"a" or "b" and "c"`},
		{"not a and b", `not "a" and "b"`},
		{"not (a and b)", `not ("a" and "b")`},
		{"not not a", `not not "a"`},
		{"! ! a", `not not "a"`},
		{"a AND b OR NOT c", `"a" and "b" or not "c"`},
		{"((a))", `"a"`},
		{"a and (b and c)", `"a" and ("b" and "c")`},
		{"src = 10.0.0.0/8", "src = 10.0.0.0/8"},
		{"src_ip = 10.0.0.1", "src = 10.0.0.1"},
		{"dst in (192.168.1.0/24, 2001:db8::/32, ::1)", "dst in (192.168.1.0/24, 2001:db8::/32, ::1)"},
		{"src = ::ffff:10.0.0.1", "src = 10.0.0.1"},
		{"duration > 1m30s", "duration > 1m30s"},
		{"pdd < 250ms", "pdd < 250ms"},
		{"pdd < 2", "pdd < 2s"},
		{"duration in 3s..5s", "duration in (3s..5s)"},
		{"mos < 3.5", "mos < 3.5"},
		{"loss in 0.5..2", "loss in (0.5..2)"},
		{"time > 2026-03-01T12:00:00Z", "time > 2026-03-01T12:00:00Z"},
		{"time > 2026-03-01 12:00:05", `time > "2026-03-01 12:00:05"`},
		{`time >= "2026-03-01 12:00"`, `time >= "2026-03-01 12:00"`},
		{"time >= 10:30", "time >= 10:30"},
		{"start < 12:00:05", "start < 12:00:05"},
		{"time in 09:00..17:30", "time in (09:00..17:30)"},
		{"header.Subject ~ urgent", "header.Subject ~ urgent"},
		{"H.p-asserted-identity = 4930", "header.p-asserted-identity = 4930"},
		{"header.Subject", "header.Subject"},
		{"h.i = abc", "header.i = abc"},
		{"call-id = x", "callid = x"},
		{"Hi! and a&b", `"Hi!" and "a&b"`},
		{"ua ~ a!b", `ua ~ "a!b"`},
		{"from ~ élise", "from ~ élise"},
		{"state = FAILED", "state = failed"},
		{"transport in (udp, tcp)", "transport in (UDP, TCP)"},
		{"ended_by = \"\"", `ended_by = ""`},
		{"from ~ and", ""}, // keyword value, error; guarded
	}
	for _, tc := range tests {
		t.Run(tc.src, func(t *testing.T) {
			q, err := Parse(tc.src, Options{})
			if tc.want == "" {
				if err == nil {
					t.Fatalf("Parse(%q) = %q, want an error", tc.src, q)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse(%q): %v", tc.src, err)
			}
			if got := q.String(); got != tc.want {
				t.Fatalf("String() = %q, want %q", got, tc.want)
			}
			q2, err := Parse(q.String(), Options{})
			if err != nil {
				t.Fatalf("re-Parse(%q): %v", q.String(), err)
			}
			if q2.String() != q.String() {
				t.Fatalf("String not stable: %q -> %q", q.String(), q2.String())
			}
		})
	}
}

func TestParseErrors(t *testing.T) {
	deep := strings.Repeat("(", 1000) + "a" + strings.Repeat(")", 1000)
	tests := []struct {
		src  string
		pos  int
		frag string // substring of the message
	}{
		{"", 0, "empty expression"},
		{"   ", 0, "empty expression"},
		{"status =", 8, `expected a value after "="`},
		{"status = ", 9, `expected a value after "="`},
		{"= 5", 0, "operator must come after a field"},
		{"(status = 5", 0, `unclosed "("`},
		{"a and (b or c", 6, `unclosed "("`},
		{"status = 5)", 10, `unmatched ")"`},
		{"status = 5 and", 14, "expected a condition"},
		{"and status = 5", 0, "expected a condition before it"},
		{"status = 5 or or a", 14, "expected a condition before it"},
		{"status = abc", 9, `"abc" is not an integer`},
		{"status = 4xxx", 9, "not an integer"},
		{"status = 6.5", 9, "not an integer"},
		{"stauts = 4", 0, `did you mean "status"?`},
		{"form ~ a", 0, `did you mean "from"?`},
		{"headr.X = 1", 0, `did you mean "header.X"?`},
		{"zzzzzz = 1", 0, "unknown field"},
		{"a and zzzzzz > 1", 6, "unknown field"},
		{"status ~ 5", 7, `operator "~" does not apply to an int field`},
		{"method < INVITE", 7, `operator "<" does not apply`},
		{"has_sdp ~ x", 8, "does not apply to a bool field"},
		{"src > 10.0.0.1", 4, "does not apply to an addr field"},
		{"state ~ fail", 6, "does not apply to an enum field"},
		{"uri =~ \"(\"", 7, "invalid regular expression"},
		{"uri =~ \"a(b\"", 7, "missing closing )"},
		{"uri =~ \"[z-a]\"", 9, "invalid regular expression"},
		{"src = 10.0.0.0/33", 6, "not a valid CIDR"},
		{"src = 300.1.1.1", 6, "not an IP address"},
		{"src = 10.0.0.1%eth0", 6, "not an IP address"},
		{"src in (10.0.0.1, 10.0.0.0/99)", 18, "not a valid CIDR"},
		{"dst = banana", 6, "not an IP address"},
		{"duration > 5parsecs", 11, "not a duration"},
		{"duration > abc", 11, "not a duration"},
		{"duration = 3s..1s", 11, "empty range"},
		{"duration > 1s..2s", 11, "range is only valid with = and in"},
		{"mos < x", 6, "not a number"},
		{"mos in 4..1", 7, "empty range"},
		{"loss > 1..2", 7, "range is only valid"},
		{"time > 25:00", 7, "not a time"},
		{"time > 12:60", 7, "not a time"},
		{"time > 2026-13-01", 7, "not a time"},
		{"time > 2026-02-30", 7, "not a time"},
		{"time > 12:00..2026-03-01", 7, "mix a time of day"},
		{"time > 1000-01-01", 7, "supported years"},
		{"time > noon", 7, "not a time"},
		{"state = faild", 8, `did you mean "failed"?`},
		{"kind = banana", 7, "not a valid kind"},
		{"transport = quic", 12, "not a valid transport"},
		{"has_sdp = maybe", 10, "not a boolean"},
		{"status in ()", 11, "empty list"},
		{"status in (1,2", 10, `unclosed "("`},
		{"status in (1 2)", 13, "in a list"},
		{"status in (1,)", 13, "expected a value"},
		{"status in 1,2", 11, `unexpected ","`},
		{`"abc" = 5`, 0, "quoted text cannot be a field name"},
		{`status = "abc`, 9, "unterminated quoted string"},
		{`status = 'abc`, 9, "unterminated quoted string"},
		{"a & b", 2, `use "&&" or "and"`},
		{"a | b", 2, `use "||" or "or"`},
		{"not", 3, "expected a condition"},
		{"!", 1, "expected a condition"},
		{"status = and", 9, "keyword"},
		{"status = (1)", 9, `only valid after "in"`},
		{"status = )", 9, `expected a value after "="`},
		{"status = = 5", 9, "expected a value"},
		{"a b", 2, `join conditions with "and"`},
		{"a (b)", 2, `join conditions with "and"`},
		{`a "b"`, 2, `join conditions with "and"`},
		{"status = 5 = 6", 11, "unexpected"},
		{"status = 5=6", 9, "not an integer"},
		{"(a b)", 3, `expected ")"`},
		{")", 0, `unexpected ")"`},
		{",", 0, `unexpected ","`},
		{"callid", 0, "needs an operator and a value"},
		{"!status", 1, "needs an operator and a value"},
		{"a\x01b", 1, "control character"},
		{"a \xffb", 2, "invalid UTF-8"},
		{"status = 5 \x00", 11, "control character"},
		{deep, 200, "nested too deeply"},
		{strings.Repeat("not ", 500) + "a", 800, "nested too deeply"},
	}
	for _, tc := range tests {
		name := tc.src
		if len(name) > 40 {
			name = name[:40]
		}
		t.Run(name, func(t *testing.T) {
			q, err := Parse(tc.src, Options{})
			if err == nil {
				t.Fatalf("Parse(%q) = %q, want error", tc.src, q)
			}
			var se *SyntaxError
			if !errors.As(err, &se) {
				t.Fatalf("error is %T, want *SyntaxError", err)
			}
			if se.Pos != tc.pos {
				t.Errorf("Pos = %d, want %d (msg %q)", se.Pos, tc.pos, se.Msg)
			}
			if !strings.Contains(se.Msg, tc.frag) {
				t.Errorf("Msg = %q, want substring %q", se.Msg, tc.frag)
			}
			if !strings.HasPrefix(err.Error(), "filter: column ") || !strings.HasSuffix(err.Error(), se.Msg) {
				t.Errorf("Error() = %q", err.Error())
			}
			if p := se.Pretty(); !strings.Contains(p, "^") || !strings.HasSuffix(p, se.Msg) || strings.HasSuffix(p, "\n") {
				t.Errorf("Pretty() = %q", p)
			}
		})
	}
}

func TestSyntaxErrorRendering(t *testing.T) {
	tests := []struct {
		src        string
		wantPretty string
		wantError  string
	}{
		{
			"status = abc",
			"status = abc\n         ^~~ \"abc\" is not an integer (status is an int field, e.g. 486 or 4xx)",
			`filter: column 10: "abc" is not an integer (status is an int field, e.g. 486 or 4xx)`,
		},
		{
			// the column counts characters, not bytes
			"from ~ é and status = x",
			"from ~ é and status = x\n                      ^ \"x\" is not an integer (status is an int field, e.g. 486 or 4xx)",
			`filter: column 23: "x" is not an integer (status is an int field, e.g. 486 or 4xx)`,
		},
		{
			// tabs are shown as spaces so the caret lines up
			"a\tand\t&",
			"a and  \n      ^ \"&\" is not an operator; use \"&&\" or \"and\"",
			`filter: column 7: "&" is not an operator; use "&&" or "and"`,
		},
	}
	for _, tc := range tests {
		_, err := Parse(tc.src, Options{})
		var se *SyntaxError
		if !errors.As(err, &se) {
			t.Fatalf("Parse(%q): %v", tc.src, err)
		}
		if tc.src == "a\tand\t&" {
			// the offending line is shown with tabs replaced
			tc.wantPretty = "a and &\n      ^ \"&\" is not an operator; use \"&&\" or \"and\""
		}
		if got := se.Pretty(); got != tc.wantPretty {
			t.Errorf("Pretty(%q):\n%s\nwant:\n%s", tc.src, got, tc.wantPretty)
		}
		if got := se.Error(); got != tc.wantError {
			t.Errorf("Error(%q) = %q, want %q", tc.src, got, tc.wantError)
		}
	}
}

func TestSyntaxErrorMultiline(t *testing.T) {
	_, err := Parse("status = 5\nand zzzzzz > 1", Options{})
	var se *SyntaxError
	if !errors.As(err, &se) {
		t.Fatal(err)
	}
	if se.Pos != 15 {
		t.Fatalf("Pos = %d", se.Pos)
	}
	if !strings.HasPrefix(se.Pretty(), "and zzzzzz > 1\n    ^~~~~~ unknown field") {
		t.Errorf("Pretty() = %q", se.Pretty())
	}
	if !strings.HasPrefix(se.Error(), "filter: column 5:") {
		t.Errorf("Error() = %q", se.Error())
	}
}

func TestUnknownFieldListsFields(t *testing.T) {
	_, err := Parse("zzzzzz = 1", Options{})
	for _, f := range []string{"method", "status", "duration", "header.<Name>", "user_agent"} {
		if !strings.Contains(err.Error(), f) {
			t.Errorf("error does not list field %q: %v", f, err)
		}
	}
}

// Precedence: the tree of "a or b and c" must group as a or (b and c), and
// "not" must bind tighter than "and".
func TestPrecedenceSemantics(t *testing.T) {
	m := sm{method: "INVITE"}.msg(1) // raw contains INVITE, alice, bob
	tests := []struct {
		src  string
		want bool
	}{
		{"INVITE or zzz and zzz", true},     // a or (b and c)
		{"(INVITE or zzz) and zzz", false},  // grouped differently
		{"zzz and zzz or INVITE", true},     // (a and b) or c
		{"zzz and (zzz or INVITE)", false},  // grouped differently
		{"not zzz and INVITE", true},        // (not a) and b
		{"not (zzz and INVITE)", true},      // not (a and b)
		{"not INVITE and zzz", false},       // (not a) and b
		{"not INVITE or INVITE", true},      // (not a) or b
		{"!INVITE || INVITE && zzz", false}, // (!a) or (b and c)
		{"INVITE && !zzz && alice", true},   // chain
		{"not not INVITE", true},            // double negation
		{"INVITE or", false},                // parse error: handled below
		{"INVITE && (zzz || bob)", true},    // nested
		{"INVITE and (zzz or (not zzz))", true},
	}
	for _, tc := range tests {
		q, err := Parse(tc.src, Options{})
		if tc.src == "INVITE or" {
			if err == nil {
				t.Errorf("%q: want error", tc.src)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%q: %v", tc.src, err)
		}
		if got := q.MatchMessage(m, nil); got != tc.want {
			t.Errorf("%q = %v, want %v (normal form %s)", tc.src, got, tc.want, q)
		}
	}
}

func TestQuoting(t *testing.T) {
	m := sm{method: "INVITE", ua: `Weird "UA" (v1,2) a=b \ x`}.msg(1)
	tests := []struct {
		src  string
		want bool
	}{
		{`ua ~ "(v1,2)"`, true},
		{`ua ~ '"UA"'`, true},
		{`ua ~ "\"UA\""`, true},
		{`ua ~ "a=b"`, true},
		{`ua ~ "a=c"`, false},
		{`ua ~ "b \ x"`, true},
		{`ua ~ 'b \\ x'`, true},    // \\ inside quotes is one backslash
		{`ua =~ "b \\\\ x"`, true}, // \\\\ -> \\ for the regexp = a literal backslash
		{`ua =~ 'b \s\\ x'`, false},
		{`ua =~ 'b\s\S x'`, true}, // other backslashes are kept as written
		{`ua =~ 'v1,\d'`, true},
		{`ua =~ "^Weird"`, true},
		{`ua = 'Weird "UA" (v1,2) a=b \ x'`, true},
		{`"a=b"`, true},
		{`'(v1,2)'`, true},
		{`uri = "sip:bob@example.com"`, true},
	}
	for _, tc := range tests {
		q, err := Parse(tc.src, Options{})
		if err != nil {
			t.Fatalf("%q: %v", tc.src, err)
		}
		got := q.MatchMessage(m, nil)
		if got != tc.want {
			t.Errorf("%q = %v, want %v (normal form %s)", tc.src, got, tc.want, q)
		}
		// the normal form selects the same messages
		q2, err := Parse(q.String(), Options{})
		if err != nil {
			t.Fatalf("re-parse %q: %v", q.String(), err)
		}
		if q2.MatchMessage(m, nil) != got {
			t.Errorf("normal form %s of %q behaves differently", q, tc.src)
		}
	}
}
