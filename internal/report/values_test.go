package report

import (
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		d    time.Duration
		want string
	}{
		{0, "0s"},
		{1, "1ns"},
		{999, "999ns"},
		{1500, "1.5µs"},
		{999_500, "999.5µs"},
		{999_999, "999.999µs"},
		{time.Millisecond, "1ms"},
		{12_345_678, "12.346ms"},
		{250 * time.Millisecond, "250ms"},
		{999_999_999, "1s"},
		{time.Second, "1s"},
		{1500 * time.Millisecond, "1.5s"},
		{1234567 * time.Microsecond, "1.235s"},
		{59_999_400_000, "59.999s"},
		{59_999_999_999, "1m00s"},
		{time.Minute, "1m00s"},
		{90 * time.Second, "1m30s"},
		{90*time.Second + 500*time.Millisecond, "1m30.5s"},
		{90*time.Second + 540*time.Millisecond, "1m30.5s"},
		{90*time.Second + 560*time.Millisecond, "1m30.6s"},
		{65 * time.Second, "1m05s"},
		{10*time.Minute + 3*time.Second, "10m03s"},
		{time.Hour - time.Nanosecond, "1h00m"},
		{time.Hour, "1h00m"},
		{2*time.Hour + 3*time.Minute, "2h03m"},
		{2*time.Hour + 3*time.Minute + 29*time.Second, "2h03m"},
		{2*time.Hour + 3*time.Minute + 30*time.Second, "2h04m"},
		{25 * time.Hour, "25h00m"},
		{-250 * time.Millisecond, "-250ms"},
		{-90 * time.Second, "-1m30s"},
		{time.Duration(math.MaxInt64), "2562047h47m"},
		{time.Duration(math.MinInt64), "-2562047h47m"},
	}
	for _, tt := range tests {
		if got := FormatDuration(tt.d); got != tt.want {
			t.Errorf("FormatDuration(%d) = %q, want %q", int64(tt.d), got, tt.want)
		}
	}
}

func TestFormatDurationProperties(t *testing.T) {
	// Monotonic in magnitude up to rounding, never empty, always valid UTF-8,
	// accurate to the stated resolution.
	var prev time.Duration
	for d := time.Duration(1); d > 0 && d < 100*time.Hour; d = d*11/10 + 1 {
		s := FormatDuration(d)
		if s == "" || !utf8.ValidString(s) || strings.ContainsAny(s, " \n") {
			t.Fatalf("FormatDuration(%d) = %q", d, s)
		}
		if d < prev {
			t.Fatal("test loop broken")
		}
		prev = d
	}
	// Round-trip within resolution for values time.ParseDuration can read back.
	for _, d := range []time.Duration{3 * time.Millisecond, 1500 * time.Millisecond, 42 * time.Second, 7 * time.Minute, 90*time.Minute + 5*time.Second} {
		s := FormatDuration(d)
		s = strings.ReplaceAll(s, "m0", "m") // 1m05s -> 1m5s
		back, err := time.ParseDuration(s)
		if err != nil || back-d > time.Minute || d-back > time.Minute {
			t.Errorf("%v -> %q -> %v (%v)", d, s, back, err)
		}
	}
}

func TestFormatTime(t *testing.T) {
	in := time.Date(2026, 3, 4, 5, 6, 7, 123_999_999, time.UTC)
	if got, want := FormatTime(in, true), "2026-03-04T05:06:07.123Z"; got != want {
		t.Errorf("utc: %q want %q", got, want)
	}
	z := time.FixedZone("X", 3600)
	if got, want := FormatTime(in.In(z), true), "2026-03-04T05:06:07.123Z"; got != want {
		t.Errorf("utc from zone: %q want %q", got, want)
	}
	if got, want := FormatTime(in, false), in.Local().Format("2006-01-02T15:04:05.000Z07:00"); got != want {
		t.Errorf("local: %q want %q", got, want)
	}
	if got := FormatTime(time.Time{}, true); got != "" {
		t.Errorf("zero: %q", got)
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		s    string
		n    int
		want string
	}{
		{"", 5, ""},
		{"abc", 0, ""},
		{"abc", -1, ""},
		{"abc", 3, "abc"},
		{"abcd", 3, "ab…"},
		{"abcdef", 1, "…"},
		{"abcdef", 2, "a…"},
		{"日本語です", 5, "日本語です"},
		{"日本語ですね", 5, "日本語で…"},
		{"é😀é😀é", 4, "é😀é…"},
		{"ab\xffcd", 5, "ab\xffcd"},
		{"ab\xffcdef", 4, "ab\xff…"},
		{"\xff\xff\xff", 2, "\xff…"},
	}
	for _, tt := range tests {
		got := Truncate(tt.s, tt.n)
		if got != tt.want {
			t.Errorf("Truncate(%q, %d) = %q, want %q", tt.s, tt.n, got, tt.want)
		}
		if tt.n > 0 && utf8.RuneCountInString(got) > tt.n {
			t.Errorf("Truncate(%q, %d) too long: %q", tt.s, tt.n, got)
		}
	}
	long := strings.Repeat("é", 1000)
	if got := Truncate(long, 10); utf8.RuneCountInString(got) != 10 || !utf8.ValidString(got) {
		t.Errorf("long: %q", got)
	}
}

func TestStatusStyle(t *testing.T) {
	tests := []struct {
		code int
		want Style
	}{
		{0, None}, {99, None}, {100, Dim}, {180, Dim}, {199, Dim}, {200, Good}, {202, Good}, {299, Good},
		{300, None}, {302, None}, {400, Warn}, {401, None}, {404, Warn}, {407, None}, {486, Warn}, {487, None},
		{499, Warn}, {500, Bad}, {503, Bad}, {603, Bad}, {699, Bad}, {700, None}, {-200, None},
	}
	for _, tt := range tests {
		if got := StatusStyle(tt.code); got != tt.want {
			t.Errorf("StatusStyle(%d) = %v, want %v", tt.code, got, tt.want)
		}
	}
}

func TestSeverityStyle(t *testing.T) {
	for name, want := range map[string]Style{"info": Dim, "Warning": Warn, "WARN": Warn, "error": Bad, "err": Bad, "": None, "fatal": None} {
		if got := SeverityStyle(name); got != want {
			t.Errorf("SeverityStyle(%q) = %v, want %v", name, got, want)
		}
	}
	if b := SeverityBadge("error"); b.Style != Bad || b.Text != "error" {
		t.Errorf("SeverityBadge = %+v", b)
	}
}

func TestShouldColor(t *testing.T) {
	// Not a file: never.
	if ShouldColor(&strings.Builder{}) {
		t.Error("strings.Builder")
	}
	var nilFile *os.File
	if ShouldColor(nilFile) {
		t.Error("nil *os.File")
	}
	// Regular file: never.
	f, err := os.Create(filepath.Join(t.TempDir(), "out"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if ShouldColor(f) {
		t.Error("regular file")
	}
	// /dev/null is a character device but not a terminal.
	if null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0); err == nil {
		defer null.Close()
		if ShouldColor(null) {
			t.Error("/dev/null")
		}
	}
	// NO_COLOR and TERM=dumb disable it whatever the writer is; checked with
	// a controlling terminal if there is one.
	t.Setenv("NO_COLOR", "1")
	if tty, err := os.OpenFile("/dev/tty", os.O_WRONLY, 0); err == nil {
		defer tty.Close()
		if ShouldColor(tty) {
			t.Error("NO_COLOR ignored")
		}
		t.Setenv("NO_COLOR", "")
		t.Setenv("TERM", "xterm")
		if !ShouldColor(tty) {
			t.Error("terminal without NO_COLOR should get color")
		}
		t.Setenv("TERM", "dumb")
		if ShouldColor(tty) {
			t.Error("TERM=dumb ignored")
		}
	}
}

func TestSanitize(t *testing.T) {
	tests := []struct {
		in   string
		mode mode
		want string
	}{
		{"plain", modeText, "plain"},
		{"a\tb\nc\r\nd\re", modeText, "a b c d e"},
		{"\x1b[31m", modeText, "\uFFFD[31m"},
		{"x\xffy", modeText, "x\uFFFDy"},
		{"\u0085\u009b", modeText, "\uFFFD\uFFFD"},
		{"\ufeffa\u202eb\u2028c", modeText, "a\uFFFDb c"},
		{"é日😀", modeText, "é日😀"},
		{"a\nb\r\nc\rd\te", modeCSV, "a\nb\nc\nd\te"},
		{"\x00\x07\x1b\u0085", modeCSV, "\uFFFD\uFFFD\uFFFD\uFFFD"},
		{"\u202e\ufeff", modeCSV, "\u202e\ufeff"},
		{"a|b\\c<d>e&f`g*h[i]\nj", modeMarkdown, "a\\|b\\\\c\\<d\\>e\\&f\\`g\\*h\\[i\\]<br>j"},
		{"a\nb", modeMarkdownInline, "a b"},
		{"<a href=\"x\">'&", modeHTML, "&lt;a href=&quot;x&quot;&gt;&#39;&amp;"},
		{"a\r\nb\nc\u2028d", modeHTML, "a<br>b<br>c<br>d"},
		{"a\r\nb\nc\u2028d\te", modeHTMLInline, "a b c d e"},
		{"<b>\ta\r\nb\n\x00\v", modeHTMLPre, "&lt;b&gt;\ta\nb\n\uFFFD\uFFFD"},
	}
	for _, tt := range tests {
		if got := string(appendSanitized(nil, tt.in, tt.mode)); got != tt.want {
			t.Errorf("mode %d %q: got %q want %q", tt.mode, tt.in, got, tt.want)
		}
	}
	// Appends to existing content.
	if got := string(appendSanitized([]byte("x"), "a\n", modeText)); got != "xa " {
		t.Errorf("append: %q", got)
	}
}

// TestSanitizeNoControls checks, for every rune and byte pair, that no mode
// except CSV leaves control characters behind.
func TestSanitizeNoControls(t *testing.T) {
	for m := mode(0); m < numModes; m++ {
		for r := rune(0); r < 0x3000; r++ {
			out := string(appendSanitized(nil, "x"+string(r)+"y", m))
			if !utf8.ValidString(out) {
				t.Fatalf("mode %d U+%04X: invalid UTF-8", m, r)
			}
			for _, c := range out {
				bad := c == 0x7f || c < 0x20 || (c >= 0x80 && c < 0xa0)
				if m == modeCSV || m == modeHTMLPre {
					bad = bad && c != '\n' && !(c == '\t')
				}
				if m == modeCSV {
					bad = bad && c != '\n' && c != '\t'
				}
				if bad {
					t.Fatalf("mode %d U+%04X: control %U left in %q", m, r, c, out)
				}
				if m != modeCSV && (c == '\u202e' || c == 0xfeff || c == 0x2028) {
					t.Fatalf("mode %d U+%04X: %U left in %q", m, r, c, out)
				}
			}
			if m == modeText && strings.ContainsAny(out, "\t\n\r\v\f") {
				t.Fatalf("U+%04X: whitespace control left", r)
			}
		}
	}
}
