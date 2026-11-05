package flow

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/sotoz/sipcurious/internal/call"
)

func TestGolden(t *testing.T) {
	for _, g := range goldenCases {
		t.Run(g.name, func(t *testing.T) {
			want, ok := goldens[g.name]
			if !ok {
				t.Fatalf("no golden for %s", g.name)
			}
			calls := []call.Call{g.c()}
			ascii := render(func(w *strings.Builder) error { return WriteASCII(w, calls, g.o) })
			if ascii != want.ascii {
				t.Errorf("ASCII mismatch\n--- got ---\n%s\n--- want ---\n%s", ascii, want.ascii)
			}
			mer := render(func(w *strings.Builder) error { return WriteMermaid(w, calls, g.o) })
			mer = strings.ReplaceAll(mer, "```", "~~~")
			if mer != want.mermaid {
				t.Errorf("Mermaid mismatch\n--- got ---\n%s\n--- want ---\n%s", mer, want.mermaid)
			}
		})
	}
}

// renderAll renders c in every format and returns the outputs.
func renderAll(t testing.TB, c call.Call, o Options) (ascii, mermaid, svg string) {
	t.Helper()
	calls := []call.Call{c}
	ascii = render(func(w *strings.Builder) error { return WriteASCII(w, calls, o) })
	mermaid = render(func(w *strings.Builder) error { return WriteMermaid(w, calls, o) })
	svg, err := SVG(c, o)
	if err != nil {
		t.Fatal(err)
	}
	return ascii, mermaid, svg
}

// checkSafe verifies the properties every output must have.
func checkSafe(t testing.TB, name, s string, multiline bool) {
	t.Helper()
	if !utf8.ValidString(s) {
		t.Fatalf("%s: invalid UTF-8", name)
	}
	for _, r := range s {
		if r == '\n' && multiline {
			continue
		}
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029' || r == 0xFFFE || r == 0xFFFF {
			t.Fatalf("%s: unsafe rune %U in %q", name, r, s)
		}
	}
	for i, line := range strings.Split(s, "\n") {
		if strings.TrimRight(line, " \t") != line {
			t.Fatalf("%s: trailing whitespace on line %d: %q", name, i+1, line)
		}
	}
}

var entity = regexp.MustCompile(`#[a-z0-9]+;`)

func TestHostileText(t *testing.T) {
	ascii, mer, svg := renderAll(t, hostile(), Options{UTC: true, SDP: true, Media: true})
	checkSafe(t, "ascii", ascii, true)
	checkSafe(t, "mermaid", mer, true)
	checkSafe(t, "svg", svg, true)
	if strings.Contains(mer, "script>") || strings.Contains(svg, "<script") {
		t.Error("markup leaked")
	}
	// Every Mermaid statement must be one line without raw metacharacters.
	for _, line := range strings.Split(mer, "\n") {
		if i := strings.Index(line, ": "); i >= 0 && strings.HasPrefix(strings.TrimSpace(line), "P") {
			text := entity.ReplaceAllString(strings.ReplaceAll(line[i+2:], "<br/>", ""), "")
			if strings.ContainsAny(text, ";%<>") {
				t.Errorf("unescaped metacharacter in %q", line)
			}
		}
	}
}

func TestStructure(t *testing.T) {
	ascii, _, _ := renderAll(t, withStreams(answered()), Options{UTC: true, Media: true})
	for _, want := range []string{"RTP PCMA 245 pkts", "RTP streams:", "caller->callee", "(Linphone)", "(Asterisk)", "(gap 2.000s)"} {
		if !strings.Contains(ascii, want) {
			t.Errorf("ASCII lacks %q", want)
		}
	}
	// Without Media there is no RTP arrow nor footer.
	plain, _, _ := renderAll(t, withStreams(answered()), Options{UTC: true})
	if strings.Contains(plain, "RTP") {
		t.Error("RTP shown without Options.Media")
	}
	// No SDP annotations without Options.SDP.
	if strings.Contains(plain, "audio") {
		t.Error("SDP shown without Options.SDP")
	}
}

func TestEmptyAndMultiple(t *testing.T) {
	var b strings.Builder
	if err := WriteASCII(&b, nil, Options{}); err != nil || b.Len() != 0 {
		t.Errorf("no calls: %q %v", b.String(), err)
	}
	empty := call.Call{CallID: "x"}
	for name, f := range map[string]func(*strings.Builder) error{
		"ascii":   func(w *strings.Builder) error { return WriteASCII(w, []call.Call{empty}, Options{Media: true}) },
		"mermaid": func(w *strings.Builder) error { return WriteMermaid(w, []call.Call{empty}, Options{Media: true}) },
	} {
		out := render(f)
		checkSafe(t, name, out, true)
	}
	if _, err := SVG(empty, Options{Media: true}); err != nil {
		t.Fatal(err)
	}
	two := render(func(w *strings.Builder) error {
		return WriteASCII(w, []call.Call{proxied(), failed()}, Options{UTC: true})
	})
	if strings.Count(two, "Call-ID:") != 2 || !strings.Contains(two, "\n\nCall-ID:") {
		t.Errorf("two calls not separated by a blank line:\n%s", two)
	}
}

func TestDeterministic(t *testing.T) {
	o := Options{UTC: true, SDP: true, Media: true}
	a1, m1, s1 := renderAll(t, withStreams(answered()), o)
	a2, m2, s2 := renderAll(t, withStreams(answered()), o)
	if a1 != a2 || m1 != m2 || s1 != s2 {
		t.Error("output differs between runs")
	}
}

func TestMaxLabel(t *testing.T) {
	c := build(
		sg{at: 0, src: alice, dst: bob, method: "INVITE", cseq: 1, branch: "z9hG4bKa"},
		sg{at: ms(10), src: bob, dst: alice, code: 486, reason: strings.Repeat("é世", 40), cseq: 1, cseqM: "INVITE", branch: "z9hG4bKa", toTag: "tt"},
	)
	m := newModel(c, Options{MaxLabel: 12})
	if got := m.rows[1].label; utf8.RuneCountInString(got) != 12 || !strings.HasSuffix(got, "…") {
		t.Errorf("label %q", got)
	}
	m = newModel(c, Options{})
	if got := utf8.RuneCountInString(m.rows[1].label); got != defaultMaxLabel {
		t.Errorf("default label has %d runes", got)
	}
}

// TestLaneAlignment checks that in ASCII output every lifeline stays in the
// same column on rows that do not cross it, for 2..9 participants including
// messages that skip lanes and self-addressed ones.
func TestLaneAlignment(t *testing.T) {
	for n := 2; n <= 9; n++ {
		addrs := make([]string, n)
		for i := range addrs {
			addrs[i] = fmt.Sprintf("10.0.%d.1:5060", i)
		}
		var list []sg
		for i := 0; i+1 < n; i++ {
			list = append(list, sg{at: ms(i), src: addrs[i], dst: addrs[i+1], method: "INVITE", cseq: 1, branch: fmt.Sprintf("z9hG4bK%d", i)})
		}
		list = append(list,
			sg{at: ms(100), src: addrs[n-1], dst: addrs[0], code: 200, cseq: 1, cseqM: "INVITE", branch: "z9hG4bK0", toTag: "t"},
			sg{at: ms(101), src: addrs[0], dst: addrs[0], method: "OPTIONS", cseq: 5, branch: "z9hG4bKs"},
		)
		out := render(func(w *strings.Builder) error {
			return WriteASCII(w, []call.Call{build(list...)}, Options{UTC: true})
		})
		checkSafe(t, "ascii", out, true)
		var lifeRow string
		for _, l := range strings.Split(out, "\n") {
			if strings.Count(l, "|") == n && strings.TrimSpace(strings.ReplaceAll(l, "|", "")) == "" {
				lifeRow = l
				break
			}
		}
		if lifeRow == "" {
			t.Fatalf("n=%d: no lifeline row\n%s", n, out)
		}
		for _, l := range strings.Split(out, "\n") {
			for i, r := range l {
				if r == '|' && i < len(lifeRow) && lifeRow[i] != '|' {
					t.Errorf("n=%d: stray lifeline at col %d in %q", n, i, l)
				}
			}
		}
		for _, a := range addrs {
			if !strings.Contains(out, a) {
				t.Errorf("n=%d: participant %s missing", n, a)
			}
		}
	}
}

func TestWideRunesDoNotBreak(t *testing.T) {
	c := build(
		sg{at: 0, src: alice, dst: bob, method: "INVITE", cseq: 1, branch: "z9hG4bKa"},
		sg{at: ms(10), src: bob, dst: alice, code: 486, reason: "忙线中忙线中", cseq: 1, cseqM: "INVITE", branch: "z9hG4bKa", toTag: "tt"},
	)
	out := render(func(w *strings.Builder) error { return WriteASCII(w, []call.Call{c}, Options{UTC: true}) })
	var lens []int
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "|") && strings.Contains(l, "+0.") {
			lens = append(lens, width(l[:strings.Index(l, "+0.")]))
		}
	}
	if len(lens) != 2 || lens[0] != lens[1] {
		t.Errorf("time columns differ: %v\n%s", lens, out)
	}
}

func TestRetransMarking(t *testing.T) {
	m := newModel(failed(), Options{})
	var got []bool
	for _, r := range m.rows {
		got = append(got, r.retrans)
	}
	want := []bool{false, true, false, false, true}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("retrans flags %v, want %v", got, want)
	}
}

func TestSolveGaps(t *testing.T) {
	g := solveGaps([]int{10, 10, 10}, []span{{0, 3, 60}, {1, 2, 5}, {0, 1, 12}})
	if sum := g[0] + g[1] + g[2]; sum < 60 || g[0] < 12 {
		t.Errorf("gaps %v", g)
	}
	if g := solveGaps(nil, []span{{0, 1, 5}}); len(g) != 0 {
		t.Errorf("gaps %v", g)
	}
}

func TestRoleOf(t *testing.T) {
	for in, want := range map[string]string{
		"Asterisk PBX 18.1": "Asterisk", "Linphone/4.5": "Linphone", "": "", "  ": "",
		"\x1b[31m": "[31m", "OpenSIPS (3.4)": "OpenSIPS",
		"AVeryLongProductNameIndeed/1": "AVeryLongProduc…",
	} {
		if got := roleOf(in); got != want {
			t.Errorf("roleOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestClean(t *testing.T) {
	for in, want := range map[string]string{
		"plain": "plain", "a\nb": "a b", "a\x00b": "a b", "\x1b[0m": " [0m", "a\u202eb": "a b",
		"e\u0301": "e", "\xff": "\ufffd", "a\u2028b": "a b", "\ufffe": "\ufffd", "\u00a0": " ",
	} {
		if got := clean(in); got != want {
			t.Errorf("clean(%q) = %q, want %q", in, got, want)
		}
	}
}
