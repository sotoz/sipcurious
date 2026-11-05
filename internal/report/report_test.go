package report

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"math"
	"net/netip"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

var testStart = time.Date(2026, 1, 2, 3, 4, 5, 123456789, time.UTC)

// mixedTable has one column of every Kind, an Extra column, a Style, and rows
// with missing values and a ragged row.
func mixedTable() Table {
	return Table{
		Title: "Calls",
		Columns: []Column{
			{Name: "Call-ID", Key: "call_id"},
			{Name: "Code", Kind: Int, Style: func(v any) Style {
				if n, ok := v.(int); ok {
					return StatusStyle(n)
				}
				return None
			}},
			{Name: "Loss %", Key: "loss_pct", Kind: Float},
			{Name: "Duration", Kind: Duration},
			{Name: "Start", Kind: Time},
			{Name: "Media", Kind: Bool},
			{Name: "UA", Extra: true},
		},
		Rows: [][]any{
			{"a@host", 200, 0.5, 90500 * time.Millisecond, testStart, true, "Asterisk"},
			{"b|c", 486, 12.0, 250 * time.Millisecond, nil, false},
			{"", 100, nil, nil, nil, nil, "x,\"y\""},
		},
	}
}

func render(t *testing.T, f Format, tb Table, o Options) string {
	t.Helper()
	var b bytes.Buffer
	if err := Write(&b, f, tb, o); err != nil {
		t.Fatalf("Write(%s): %v", f, err)
	}
	return b.String()
}

func TestGolden(t *testing.T) {
	tb := mixedTable()
	tests := []struct {
		name string
		f    Format
		o    Options
		want string
	}{
		{"table", FormatTable, Options{UTC: true}, `Calls
Call-ID  Code  Loss %  Duration  Start                     Media
a@host    200     0.5   1m30.5s  2026-01-02T03:04:05.123Z  true
b|c       486      12     250ms                            false
          100
`},
		{"table/extra+rule", FormatTable, Options{UTC: true, Extra: true, HeaderRule: true}, `Calls
Call-ID  Code  Loss %  Duration  Start                     Media  UA
-------  ----  ------  --------  ------------------------  -----  --------
a@host    200     0.5   1m30.5s  2026-01-02T03:04:05.123Z  true   Asterisk
b|c       486      12     250ms                            false
          100                                                     x,"y"
`},
		{"table/color", FormatTable, Options{UTC: true, Color: true}, "Calls\n" +
			"\x1b[1mCall-ID\x1b[0m  \x1b[1mCode\x1b[0m  \x1b[1mLoss %\x1b[0m  \x1b[1mDuration\x1b[0m  \x1b[1mStart\x1b[0m                     \x1b[1mMedia\x1b[0m\n" +
			"a@host    \x1b[32m200\x1b[0m     0.5   1m30.5s  2026-01-02T03:04:05.123Z  true\n" +
			"b|c       \x1b[33m486\x1b[0m      12     250ms                            false\n" +
			"          \x1b[2m100\x1b[0m\n"},
		{"csv", FormatCSV, Options{UTC: true}, `call_id,code,loss_pct,duration_ms,start,media,ua
a@host,200,0.5,90500,2026-01-02T03:04:05.123456789Z,true,Asterisk
b|c,486,12,250,,false,
,100,,,,,"x,""y"""
`},
		{"json", FormatJSON, Options{UTC: true}, `[
  {
    "call_id": "a@host",
    "code": 200,
    "loss_pct": 0.5,
    "duration_ms": 90500,
    "start": "2026-01-02T03:04:05.123456789Z",
    "media": true,
    "ua": "Asterisk"
  },
  {
    "call_id": "b|c",
    "code": 486,
    "loss_pct": 12,
    "duration_ms": 250,
    "media": false
  },
  {
    "call_id": "",
    "code": 100,
    "ua": "x,\"y\""
  }
]
`},
		{"ndjson", FormatNDJSON, Options{UTC: true}, `{"call_id":"a@host","code":200,"loss_pct":0.5,"duration_ms":90500,"start":"2026-01-02T03:04:05.123456789Z","media":true,"ua":"Asterisk"}
{"call_id":"b|c","code":486,"loss_pct":12,"duration_ms":250,"media":false}
{"call_id":"","code":100,"ua":"x,\"y\""}
`},
		{"markdown", FormatMarkdown, Options{UTC: true}, `### Calls

| Call-ID | Code | Loss % | Duration | Start | Media |
| --- | ---: | ---: | ---: | --- | --- |
| a@host | 200 | 0.5 | 1m30.5s | 2026-01-02T03:04:05.123Z | true |
| b\|c | 486 | 12 | 250ms |  | false |
|  | 100 |  |  |  |  |
`},
		{"html", FormatHTML, Options{UTC: true}, `<table class="sc-table">
<caption class="sc-caption">Calls</caption>
<thead><tr><th>Call-ID</th><th class="sc-num">Code</th><th class="sc-num">Loss %</th><th class="sc-num">Duration</th><th>Start</th><th>Media</th></tr></thead>
<tbody>
<tr><td>a@host</td><td class="sc-num sc-good">200</td><td class="sc-num">0.5</td><td class="sc-num">1m30.5s</td><td>2026-01-02T03:04:05.123Z</td><td>true</td></tr>
<tr><td>b|c</td><td class="sc-num sc-warn">486</td><td class="sc-num">12</td><td class="sc-num">250ms</td><td></td><td>false</td></tr>
<tr><td></td><td class="sc-num sc-dim">100</td><td class="sc-num"></td><td class="sc-num"></td><td></td><td></td></tr>
</tbody>
</table>
`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := render(t, tt.f, tb, tt.o); got != tt.want {
				t.Errorf("got:\n%s\nwant:\n%s", got, tt.want)
			}
		})
	}
}

func TestEmptyAndDegenerate(t *testing.T) {
	cols := []Column{{Name: "A"}, {Name: "B", Kind: Int}}
	tests := []struct {
		name string
		tb   Table
		want map[Format]string
	}{
		{"no rows", Table{Columns: cols}, map[Format]string{
			FormatTable:    "A  B\n",
			FormatCSV:      "a,b\n",
			FormatJSON:     "[]\n",
			FormatNDJSON:   "",
			FormatMarkdown: "| A | B |\n| --- | ---: |\n",
		}},
		{"zero columns", Table{Rows: [][]any{{}, {}}}, map[Format]string{
			FormatTable:    "",
			FormatCSV:      "",
			FormatJSON:     "[\n  {},\n  {}\n]\n",
			FormatNDJSON:   "{}\n{}\n",
			FormatMarkdown: "",
		}},
		{"zero everything", Table{}, map[Format]string{
			FormatTable:    "",
			FormatCSV:      "",
			FormatJSON:     "[]\n",
			FormatNDJSON:   "",
			FormatMarkdown: "",
		}},
		{"title only", Table{Title: "T"}, map[Format]string{
			FormatTable:    "T\n",
			FormatMarkdown: "### T\n\n",
		}},
		{"single empty column", Table{Columns: []Column{{Name: "X"}}, Rows: [][]any{{""}, {"v"}}}, map[Format]string{
			FormatTable: "X\n\nv\n", // the empty cell is an empty row
			FormatCSV:   "x\n\"\"\nv\n",
			FormatJSON:  "[\n  {\n    \"x\": \"\"\n  },\n  {\n    \"x\": \"v\"\n  }\n]\n",
		}},
	}
	for _, tt := range tests {
		for f, want := range tt.want {
			t.Run(tt.name+"/"+string(f), func(t *testing.T) {
				if got := render(t, f, tt.tb, Options{UTC: true}); got != want {
					t.Errorf("got %q want %q", got, want)
				}
			})
		}
	}
	// HTML of an empty table is still a well formed table.
	out := render(t, FormatHTML, Table{Columns: cols}, Options{})
	if !strings.Contains(out, "<tbody>\n</tbody>") {
		t.Errorf("html: %q", out)
	}
}

func TestRaggedRows(t *testing.T) {
	tb := Table{Columns: []Column{{Name: "A"}, {Name: "B", Kind: Int}, {Name: "C"}}}
	// Short rows are padded with missing values.
	tb.Rows = [][]any{{"x"}, {"y", 2}}
	if got, want := render(t, FormatCSV, tb, Options{}), "a,b,c\nx,,\ny,2,\n"; got != want {
		t.Errorf("csv: %q want %q", got, want)
	}
	if got, want := render(t, FormatNDJSON, tb, Options{}), "{\"a\":\"x\"}\n{\"a\":\"y\",\"b\":2}\n"; got != want {
		t.Errorf("ndjson: %q want %q", got, want)
	}
	if got, want := render(t, FormatTable, tb, Options{}), "A  B  C\nx\ny  2\n"; got != want {
		t.Errorf("table: %q want %q", got, want)
	}
	// Long rows are an error and nothing is written.
	tb.Rows = append(tb.Rows, []any{"1", 2, "3", "4"})
	for _, f := range []Format{FormatTable, FormatCSV, FormatJSON, FormatNDJSON, FormatMarkdown, FormatHTML} {
		var b bytes.Buffer
		err := Write(&b, f, tb, Options{})
		if !errors.Is(err, errNoColumnsRow) || b.Len() != 0 {
			t.Errorf("%s: err=%v written=%q", f, err, b.String())
		}
	}
	var b bytes.Buffer
	err := WriteSections(&b, FormatJSON, []Section{{Name: "x", Table: tb}}, Options{})
	if !errors.Is(err, errNoColumnsRow) || b.Len() != 0 {
		t.Errorf("sections: err=%v written=%q", err, b.String())
	}
}

func TestKeys(t *testing.T) {
	tests := []struct {
		c    Column
		want string
	}{
		{Column{Name: "Call-ID"}, "call_id"},
		{Column{Name: "  Loss %  "}, "loss"},
		{Column{Name: "From User"}, "from_user"},
		{Column{Name: "A", Key: "from"}, "from"},
		{Column{Name: "Duration", Kind: Duration}, "duration_ms"},
		{Column{Name: "x", Key: "pdd", Kind: Duration}, "pdd_ms"},
		{Column{Name: "x", Key: "pdd_ms", Kind: Duration}, "pdd_ms"},
		{Column{Name: "x", Key: "pdd", Kind: Int}, "pdd"},
		{Column{Name: "ÄÖ 9"}, "9"},
	}
	for _, tt := range tests {
		if got := tt.c.jsonKey(); got != tt.want {
			t.Errorf("%+v: key %q want %q", tt.c, got, tt.want)
		}
	}
	dup := Table{Columns: []Column{{Name: "A", Key: "k"}, {Name: "B", Key: "k"}}}
	for _, f := range []Format{FormatJSON, FormatNDJSON} {
		if err := Write(&bytes.Buffer{}, f, dup, Options{}); err == nil {
			t.Errorf("%s: duplicate keys accepted", f)
		}
	}
	// A duplicate key is harmless for CSV, tables and Markdown.
	if err := Write(&bytes.Buffer{}, FormatCSV, dup, Options{}); err != nil {
		t.Errorf("csv: %v", err)
	}
	// Duration column and a same-named plain column collide.
	dup = Table{Columns: []Column{{Name: "x", Key: "a_ms"}, {Name: "y", Key: "a", Kind: Duration}}}
	if err := Write(&bytes.Buffer{}, FormatJSON, dup, Options{}); err == nil {
		t.Error("a_ms collision accepted")
	}
}

type stringer struct{ s string }

func (s stringer) String() string { return s.s }

type namedInt int
type namedString string

func TestCellTypes(t *testing.T) {
	var nilStringer *stringer
	var nilErr error
	ap := netip.MustParseAddrPort("10.0.0.1:5060")
	tests := []struct {
		name  string
		cell  any
		table string // text table
		csv   string
		json  string // "" = key omitted
	}{
		{"nil", nil, "", "", ""},
		{"string", "s", "s", "s", `"s"`},
		{"empty string", "", "", "", `""`},
		{"bytes", []byte("b"), "b", "b", `"b"`},
		{"int", 5, "5", "5", "5"},
		{"int64 min", int64(math.MinInt64), "-9223372036854775808", "-9223372036854775808", "-9223372036854775808"},
		{"int8", int8(-3), "-3", "-3", "-3"},
		{"uint64 max", uint64(math.MaxUint64), "18446744073709551615", "18446744073709551615", "18446744073709551615"},
		{"uint8", uint8(7), "7", "7", "7"},
		{"uint", uint(3), "3", "3", "3"},
		{"float", 1.5, "1.5", "1.5", "1.5"},
		{"float rounds in table only", 0.12345678, "0.123", "0.12345678", "0.12345678"},
		{"float tiny", 1e-9, "0", "1e-9", "1e-9"},
		{"float huge", 1e21, "1000000000000000000000", "1e+21", "1e+21"},
		{"float32", float32(0.1), "0.1", "0.1", "0.1"},
		{"float neg zero", math.Copysign(0, -1), "0", "-0", "-0"},
		{"float integral", 3.0, "3", "3", "3"},
		{"NaN", math.NaN(), "", "", ""},
		{"+Inf", math.Inf(1), "", "", ""},
		{"duration", 1500 * time.Millisecond, "1.5s", "1500", "1500"},
		{"duration ns", 1500 * time.Nanosecond, "1.5µs", "0.0015", "0.0015"},
		{"duration neg", -2 * time.Second, "-2s", "-2000", "-2000"},
		{"duration max", time.Duration(math.MaxInt64), "2562047h47m", "9223372036854.775807", "9223372036854.775807"},
		{"duration min", time.Duration(math.MinInt64), "-2562047h47m", "-9223372036854.775808", "-9223372036854.775808"},
		{"time", testStart, "2026-01-02T03:04:05.123Z", "2026-01-02T03:04:05.123456789Z", `"2026-01-02T03:04:05.123456789Z"`},
		{"zero time", time.Time{}, "", "", ""},
		{"bool true", true, "true", "true", "true"},
		{"bool false", false, "false", "false", "false"},
		{"stringer", stringer{"st"}, "st", "st", `"st"`},
		{"nil stringer ptr", nilStringer, "", "", ""},
		{"error", errors.New("boom"), "boom", "boom", `"boom"`},
		{"nil error", nilErr, "", "", ""},
		{"named int", namedInt(4), "4", "4", "4"},
		{"named string", namedString("n"), "n", "n", `"n"`},
		{"addr", netip.MustParseAddr("2001:db8::1"), "2001:db8::1", "2001:db8::1", `"2001:db8::1"`},
		{"invalid addr", netip.Addr{}, "", "", ""},
		{"addrport", ap, "10.0.0.1:5060", "10.0.0.1:5060", `"10.0.0.1:5060"`},
		{"invalid addrport", netip.AddrPort{}, "", "", ""},
		{"slice fallback", []int{1, 2}, "[1 2]", "\"[1 2]\"", `"[1 2]"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tb := Table{Columns: []Column{{Name: "k", Kind: String}, {Name: "v"}}, Rows: [][]any{{"x", tt.cell}}}
			// Kind matters little for rendering; use an Int column for numerics to check alignment doesn't change text.
			text := render(t, FormatTable, tb, Options{UTC: true})
			if got, want := text, "k  v\nx"+map[bool]string{true: "  " + tt.table, false: ""}[tt.table != ""]+"\n"; got != want {
				t.Errorf("table %q want %q", got, want)
			}
			wantCSV := "k,v\nx," + tt.csv + "\n"
			if tt.name == "slice fallback" {
				wantCSV = "k,v\nx,[1 2]\n"
			}
			if got := render(t, FormatCSV, tb, Options{UTC: true}); got != wantCSV {
				t.Errorf("csv %q want %q", got, wantCSV)
			}
			wantJSON := `{"k":"x"}`
			if tt.json != "" {
				wantJSON = `{"k":"x","v":` + tt.json + `}`
			}
			if got := render(t, FormatNDJSON, tb, Options{UTC: true}); got != wantJSON+"\n" {
				t.Errorf("ndjson %q want %q", got, wantJSON)
			}
		})
	}
}

// TestJSONMatchesEncodingJSON compares our number and string rendering with
// encoding/json on values where both are defined.
func TestJSONMatchesEncodingJSON(t *testing.T) {
	floats := []float64{0, 1, -1, 0.1, 1.5, 123456789.125, 1e-7, 1e-6, 9.99e-7, 1e20, 1e21, 1.5e300, 5e-324, math.MaxFloat64, -2.5e-10}
	for _, f := range floats {
		want, _ := json.Marshal(f)
		if got := appendFloat(nil, f, 64); string(got) != string(want) {
			t.Errorf("float64 %v: %s want %s", f, got, want)
		}
		f32 := float32(f)
		if math.IsInf(float64(f32), 0) {
			continue
		}
		want, _ = json.Marshal(f32)
		if got := appendFloat(nil, float64(f32), 32); string(got) != string(want) {
			t.Errorf("float32 %v: %s want %s", f32, got, want)
		}
	}
	strs := []string{"", "plain", "quote\"back\\slash", "\x00\x01\x1f\x7f", "tab\tnl\ncr\r", "é日本語😀", "\u2028\u2029", "<&>", "bad\xffutf8\xc3", "\ufeffbom"}
	for _, s := range strs {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(s)
		if got, want := string(appendJSONString(nil, s)), strings.TrimSuffix(buf.String(), "\n"); got != want {
			t.Errorf("string %q: %s want %s", s, got, want)
		}
	}
}

func TestTimeZones(t *testing.T) {
	zone := time.FixedZone("X", 5*3600+30*60)
	in := time.Date(2026, 6, 1, 23, 30, 0, 500_000_000, time.UTC)
	tb := Table{Columns: []Column{{Name: "t", Kind: Time}}, Rows: [][]any{{in}}}
	tests := []struct {
		name         string
		o            Options
		table, nanos string
	}{
		{"utc", Options{UTC: true}, "2026-06-01T23:30:00.500Z", "2026-06-01T23:30:00.5Z"},
		{"utc wins over location", Options{UTC: true, Location: zone}, "2026-06-01T23:30:00.500Z", "2026-06-01T23:30:00.5Z"},
		{"fixed zone", Options{Location: zone}, "2026-06-02T05:00:00.500+05:30", "2026-06-02T05:00:00.5+05:30"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := strings.Fields(render(t, FormatTable, tb, tt.o))[1]; got != tt.table {
				t.Errorf("table %q want %q", got, tt.table)
			}
			if got := strings.Fields(render(t, FormatCSV, tb, tt.o))[1]; got != tt.nanos {
				t.Errorf("csv %q want %q", got, tt.nanos)
			}
			if got := render(t, FormatNDJSON, tb, tt.o); got != `{"t":"`+tt.nanos+"\"}\n" {
				t.Errorf("ndjson %q", got)
			}
		})
	}
	// Local zone: whatever it is, it must agree with time.Local.
	want := in.Local().Format("2006-01-02T15:04:05.000Z07:00")
	if got := strings.Fields(render(t, FormatTable, tb, Options{}))[1]; got != want {
		t.Errorf("local: %q want %q", got, want)
	}
}

func TestColor(t *testing.T) {
	tb := mixedTable()
	off := render(t, FormatTable, tb, Options{UTC: true})
	if strings.ContainsRune(off, '\x1b') {
		t.Errorf("escape sequences without Color: %q", off)
	}
	for _, f := range []Format{FormatCSV, FormatJSON, FormatNDJSON, FormatMarkdown, FormatHTML} {
		if out := render(t, f, tb, Options{UTC: true, Color: true}); strings.ContainsRune(out, '\x1b') {
			t.Errorf("%s: escape sequences with Color: %q", f, out)
		}
	}
	on := render(t, FormatTable, tb, Options{UTC: true, Color: true})
	if got := stripANSI(on); got != off {
		t.Errorf("color changed layout:\n%q\n%q", got, off)
	}
	// Hostile input must not smuggle escapes, with or without Color.
	hostile := Table{Columns: []Column{{Name: "\x1b[31mH"}, {Name: "V", Kind: Int}}, Rows: [][]any{
		{"\x1b[2J\x1b]0;title\x07\x9b31m", 1},
		{"a\u202eb\u2028c", 2},
	}}
	for _, color := range []bool{false, true} {
		out := render(t, FormatTable, hostile, Options{Color: color})
		if left := strings.NewReplacer("\x1b[1m", "", "\x1b[0m", "").Replace(out); strings.ContainsRune(left, '\x1b') || strings.ContainsAny(left, "\x07\u009b\u202e\u2028") {
			t.Errorf("color=%v: hostile control left in %q", color, out)
		}
	}
}

var ansiRE = regexp.MustCompile("\x1b\\[[0-9;]*m")

func stripANSI(s string) string { return ansiRE.ReplaceAllString(s, "") }

// TestTextAlignment checks the text table's structure on awkward cells.
func TestTextAlignment(t *testing.T) {
	tb := Table{Columns: []Column{{Name: "Name"}, {Name: "N", Kind: Int}, {Name: "Note"}}, Rows: [][]any{
		{"日本語", 1, "wide"},
		{"é", 1000, "accent"},
		{"emoji😀", 5, ""},
		{"a\tb\nc\r\nd", 7, "ctl"},
		{"bad\xffbyte", 8, "x"},
	}}
	got := render(t, FormatTable, tb, Options{})
	want := "Name         N  Note\n" +
		"日本語       1  wide\n" +
		"é         1000  accent\n" +
		"emoji😀      5\n" +
		"a b c d      7  ctl\n" +
		"bad\ufffdbyte     8  x\n"
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
	for i, line := range strings.Split(strings.TrimSuffix(got, "\n"), "\n") {
		if strings.TrimRight(line, " ") != line {
			t.Errorf("line %d has trailing whitespace: %q", i, line)
		}
	}
}

func TestParseFormat(t *testing.T) {
	for _, n := range Formats() {
		f, err := ParseFormat(" " + strings.ToUpper(n) + "\n")
		if err != nil || string(f) != n {
			t.Errorf("ParseFormat(%q) = %q, %v", n, f, err)
		}
	}
	if got, want := strings.Join(Formats(), ","), "table,csv,json,ndjson,markdown,html"; got != want {
		t.Errorf("Formats() = %s", got)
	}
	_, err := ParseFormat("xml")
	if err == nil || !strings.Contains(err.Error(), "xml") || !strings.Contains(err.Error(), "ndjson") {
		t.Errorf("err = %v", err)
	}
	if err := Write(&bytes.Buffer{}, "bogus", Table{}, Options{}); err == nil {
		t.Error("unknown format accepted")
	}
	if err := WriteSections(&bytes.Buffer{}, "bogus", nil, Options{}); err == nil {
		t.Error("unknown format accepted by WriteSections")
	}
}

func TestWriteSections(t *testing.T) {
	a := Table{Columns: []Column{{Name: "A"}, {Name: "N", Kind: Int}}, Rows: [][]any{{"x", 1}}}
	b := Table{Title: "Bee", Columns: []Column{{Name: "B"}}}
	secs := []Section{{Name: "First", Table: a}, {Table: b}}
	tests := []struct {
		f    Format
		want string
	}{
		{FormatTable, "First\nA  N\nx  1\n\nBee\nB\n"},
		{FormatMarkdown, "### First\n\n| A | N |\n| --- | ---: |\n| x | 1 |\n\n### Bee\n\n| B |\n| --- |\n"},
		{FormatJSON, "{\n  \"First\": [\n    {\n      \"a\": \"x\",\n      \"n\": 1\n    }\n  ],\n  \"Bee\": []\n}\n"},
		{FormatHTML, "<section class=\"sc-section\">\n<h2 class=\"sc-h\">First</h2>\n<table class=\"sc-table\">\n<thead><tr><th>A</th><th class=\"sc-num\">N</th></tr></thead>\n<tbody>\n<tr><td>x</td><td class=\"sc-num\">1</td></tr>\n</tbody>\n</table>\n</section>\n" +
			"<section class=\"sc-section\">\n<h2 class=\"sc-h\">Bee</h2>\n<table class=\"sc-table\">\n<thead><tr><th>B</th></tr></thead>\n<tbody>\n</tbody>\n</table>\n</section>\n"},
	}
	for _, tt := range tests {
		t.Run(string(tt.f), func(t *testing.T) {
			var buf bytes.Buffer
			if err := WriteSections(&buf, tt.f, secs, Options{}); err != nil {
				t.Fatal(err)
			}
			if buf.String() != tt.want {
				t.Errorf("got:\n%s\nwant:\n%s", buf.String(), tt.want)
			}
		})
	}
	for _, f := range []Format{FormatCSV, FormatNDJSON} {
		var buf bytes.Buffer
		if err := WriteSections(&buf, f, secs, Options{}); err == nil || buf.Len() != 0 {
			t.Errorf("%s: err=%v out=%q", f, err, buf.String())
		}
	}
	var buf bytes.Buffer
	if err := WriteSections(&buf, FormatJSON, []Section{{Name: "x"}, {Name: "x"}}, Options{}); err == nil {
		t.Error("duplicate JSON section names accepted")
	}
	if err := WriteSections(&buf, FormatJSON, []Section{{}}, Options{}); err == nil {
		t.Error("unnamed JSON section accepted")
	}
	buf.Reset()
	if err := WriteSections(&buf, FormatJSON, nil, Options{}); err != nil || buf.String() != "{}\n" {
		t.Errorf("empty sections: %q %v", buf.String(), err)
	}
	// JSON sections must be valid JSON, including hostile names.
	buf.Reset()
	if err := WriteSections(&buf, FormatJSON, []Section{{Name: "a\"\n\x00\xff", Table: a}}, Options{}); err != nil {
		t.Fatal(err)
	}
	var m map[string][]map[string]any
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil || len(m) != 1 {
		t.Errorf("invalid JSON %q: %v", buf.String(), err)
	}
}

// hostileStrings are SIP-header-like attack strings.
var hostileStrings = []string{
	"",
	"plain",
	"tab\there",
	"line\nbreak",
	"cr\rcr",
	"crlf\r\nend",
	"nul\x00byte",
	"vt\vff\f",
	"bell\x07 del\x7f",
	"invalid\xff\xfe\xc3(utf8",
	"\xef\xbb\xbfbom start",
	"mid\ufeffbom",
	"\x1b[31mred\x1b[0m \x1b]0;title\x07 \x1b[2J",
	"c1\u0085\u009b31m",
	"bidi \u202eevil\u202c \u2066x\u2069",
	"sep\u2028para\u2029",
	"a,b\"c'd|e<f>g&h`i*j[k]l\\m",
	"| pipe | row |\n| --- | --- |",
	"<script>alert(1)</script>",
	"\"><img src=x onerror=alert(1)>",
	"' onmouseover='alert(1)",
	"=cmd|' /C calc'!A0",
	"\\.",
	" leading space",
	"\tleading tab",
	"日本語😀 é",
	strings.Repeat("long", 5000),
	strings.Repeat("\xff", 1000),
}

func hostileTable() Table {
	cols := []Column{{Name: "S"}, {Name: "N", Kind: Int}, {Name: "T", Kind: Time}, {Name: "X", Extra: true}}
	tb := Table{Title: "t\nitle|<b>", Columns: cols}
	for i, h := range hostileStrings {
		tb.Rows = append(tb.Rows, []any{h, i, testStart, h})
	}
	return tb
}

// TestHostile pushes every hostile string through every writer and checks the
// structural invariants of each format.
func TestHostile(t *testing.T) {
	tb := hostileTable()
	// Hostile header names too.
	hostileCols := Table{Title: tb.Title, Columns: make([]Column, len(tb.Columns))}
	for i := range hostileCols.Columns {
		hostileCols.Columns[i] = Column{Name: hostileStrings[9+i*3], Key: hostileStrings[11+i], Extra: i == 3}
	}
	hostileCols.Rows = tb.Rows

	for _, table := range []struct {
		name string
		tb   Table
	}{{"cells", tb}, {"headers", hostileCols}} {
		for _, o := range []Options{{UTC: true}, {UTC: true, Color: true, Extra: true, HeaderRule: true}} {
			for _, f := range []Format{FormatTable, FormatCSV, FormatJSON, FormatNDJSON, FormatMarkdown, FormatHTML} {
				t.Run(table.name+"/"+string(f), func(t *testing.T) {
					out := render(t, f, table.tb, o)
					if !utf8.ValidString(out) {
						t.Fatalf("invalid UTF-8 output")
					}
					checkFormat(t, f, table.tb, o, out)
				})
			}
		}
	}
}

// checkFormat verifies structural invariants of out for a table of hostile cells.
func checkFormat(t *testing.T, f Format, tb Table, o Options, out string) {
	t.Helper()
	nrows := len(tb.Rows)
	visibleCols := len(visible(tb, o))
	switch f {
	case FormatTable:
		rest := strings.NewReplacer("\x1b[1m", "", "\x1b[0m", "").Replace(out)
		if strings.ContainsAny(rest, "\x1b\x00\t\r\v\f\x07\u202e\u2028\u2029\ufeff") {
			t.Errorf("control characters in table output")
		}
		lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
		want := 1 + 1 + nrows // title + header + rows
		if o.HeaderRule {
			want++
		}
		if len(lines) != want {
			t.Errorf("%d lines, want %d", len(lines), want)
		}
		for i, l := range lines {
			if strings.TrimRight(l, " ") != l {
				t.Errorf("line %d trailing whitespace: %.60q", i, l)
			}
		}
	case FormatCSV:
		r := csv.NewReader(strings.NewReader(out))
		r.FieldsPerRecord = len(tb.Columns)
		recs, err := r.ReadAll()
		if err != nil {
			t.Fatalf("csv parse: %v", err)
		}
		if len(recs) != nrows+1 {
			t.Fatalf("%d records, want %d", len(recs), nrows+1)
		}
		for i, row := range tb.Rows {
			if i >= len(hostileStrings) {
				break
			}
			if tb.Columns[0].Name != "S" {
				break
			}
			if got, want := recs[i+1][0], csvSanitized(row[0].(string)); got != want {
				t.Errorf("row %d: %q want %q", i, got, want)
			}
		}
	case FormatJSON:
		var rows []map[string]any
		if err := json.Unmarshal([]byte(out), &rows); err != nil {
			t.Fatalf("json: %v", err)
		}
		if len(rows) != nrows {
			t.Fatalf("%d rows want %d", len(rows), nrows)
		}
		if tb.Columns[0].Name == "S" {
			for i, row := range tb.Rows {
				want := string([]rune(row[0].(string))) // invalid bytes -> U+FFFD each
				if got := rows[i]["s"]; got != want {
					t.Errorf("row %d: %q want %q", i, got, want)
				}
			}
		}
	case FormatNDJSON:
		lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
		if len(lines) != nrows {
			t.Fatalf("%d lines want %d", len(lines), nrows)
		}
		for i, l := range lines {
			if !json.Valid([]byte(l)) {
				t.Errorf("line %d invalid JSON: %.80q", i, l)
			}
		}
	case FormatMarkdown:
		lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
		if want := 2 + 2 + nrows; len(lines) != want { // title + blank + header + delimiter + rows
			t.Fatalf("%d lines want %d", len(lines), want)
		}
		for i, l := range lines[4:] {
			// Unescaped pipes in the row would add cells.
			if n := countUnescapedPipes(l); n != visibleCols+1 {
				t.Errorf("row %d: %d pipes want %d: %.100q", i, n, visibleCols+1, l)
			}
		}
		if hasRawTag(out) {
			t.Errorf("raw HTML in markdown")
		}
	case FormatHTML:
		assertSafeHTML(t, out)
		if got := strings.Count(out, "<tr>"); got != nrows+1 {
			t.Errorf("%d <tr> want %d", got, nrows+1)
		}
	}
}

// hasRawTag reports whether s has a '<' that is not backslash-escaped and not
// the <br> we emit for line breaks.
func hasRawTag(s string) bool {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '<':
			if !strings.HasPrefix(s[i:], "<br>") {
				return true
			}
			i += 3
		}
	}
	return false
}

func csvSanitized(s string) string {
	var b strings.Builder
	rs := []rune(s)
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		switch {
		case r == '\r':
			if i+1 < len(rs) && rs[i+1] == '\n' {
				continue
			}
			b.WriteByte('\n')
		case r == '\n' || r == '\t':
			b.WriteRune(r)
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0):
			b.WriteRune('\uFFFD')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func countUnescapedPipes(l string) int {
	n := 0
	for i := 0; i < len(l); i++ {
		switch l[i] {
		case '\\':
			i++
		case '|':
			n++
		}
	}
	return n
}

func TestCSVRoundTrip(t *testing.T) {
	cols := []Column{{Name: "a"}, {Name: "b"}, {Name: "n", Kind: Int}, {Name: "d", Kind: Duration}, {Name: "t", Kind: Time}, {Name: "f", Kind: Float}}
	var rows [][]any
	for i, h := range hostileStrings {
		rows = append(rows, []any{h, hostileStrings[(i+7)%len(hostileStrings)], i - 5, time.Duration(i) * 1234567 * time.Nanosecond, testStart.Add(time.Duration(i) * time.Hour), float64(i) / 7})
	}
	out := render(t, FormatCSV, Table{Columns: cols, Rows: rows}, Options{UTC: true})
	recs, err := csv.NewReader(strings.NewReader(out)).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != len(rows)+1 {
		t.Fatalf("%d records", len(recs))
	}
	if got, want := strings.Join(recs[0], ","), "a,b,n,d_ms,t,f"; got != want {
		t.Errorf("header %s", got)
	}
	for i, row := range rows {
		rec := recs[i+1]
		if rec[0] != csvSanitized(row[0].(string)) || rec[1] != csvSanitized(row[1].(string)) {
			t.Errorf("row %d: strings did not round trip: %q %q", i, rec[0], rec[1])
		}
		d, err := parseMillis(rec[3])
		if err != nil || d != row[3].(time.Duration) {
			t.Errorf("row %d: duration %q -> %v, %v want %v", i, rec[3], d, err, row[3])
		}
		tm, err := time.Parse(time.RFC3339Nano, rec[4])
		if err != nil || !tm.Equal(row[4].(time.Time)) {
			t.Errorf("row %d: time %q: %v", i, rec[4], err)
		}
		if rec[2] != strconv.Itoa(row[2].(int)) {
			t.Errorf("row %d: int %q", i, rec[2])
		}
	}
}

// parseMillis converts "12.345678" milliseconds to a Duration exactly.
func parseMillis(s string) (time.Duration, error) {
	neg := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	whole, frac, _ := strings.Cut(s, ".")
	frac = (frac + "000000")[:6]
	d, err := time.ParseDuration(whole + "ms")
	if err != nil {
		return 0, err
	}
	f, err := time.ParseDuration(frac + "ns")
	if err != nil {
		return 0, err
	}
	d += f
	if neg {
		d = -d
	}
	return d, nil
}

func TestJSONValidity(t *testing.T) {
	tb := mixedTable()
	tb.Rows = append(tb.Rows, []any{math.NaN(), math.Inf(-1), math.MaxFloat64, time.Duration(math.MinInt64), time.Unix(1<<40, 0), nil, "\xff"})
	out := render(t, FormatJSON, tb, Options{UTC: true})
	var rows []map[string]any
	dec := json.NewDecoder(strings.NewReader(out))
	dec.UseNumber()
	if err := dec.Decode(&rows); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if len(rows) != 4 {
		t.Fatalf("%d rows", len(rows))
	}
	if !reflect.DeepEqual(keysOf(rows[2]), []string{"call_id", "code", "ua"}) {
		t.Errorf("row 2 keys %v", keysOf(rows[2]))
	}
	if rows[0]["code"] != json.Number("200") || rows[0]["duration_ms"] != json.Number("90500") || rows[0]["media"] != true {
		t.Errorf("row 0 types: %#v", rows[0])
	}
	if rows[3]["ua"] != "\ufffd" {
		t.Errorf("row 3 ua: %#v", rows[3]["ua"])
	}
	// NDJSON decodes to the same objects.
	nd := render(t, FormatNDJSON, tb, Options{UTC: true})
	var fromND []map[string]any
	for _, l := range strings.Split(strings.TrimSuffix(nd, "\n"), "\n") {
		var m map[string]any
		d := json.NewDecoder(strings.NewReader(l))
		d.UseNumber()
		if err := d.Decode(&m); err != nil {
			t.Fatalf("ndjson line %q: %v", l, err)
		}
		fromND = append(fromND, m)
	}
	if !reflect.DeepEqual(rows, fromND) {
		t.Errorf("json and ndjson differ:\n%v\n%v", rows, fromND)
	}
}

func keysOf(m map[string]any) []string {
	var ks []string
	for _, k := range []string{"call_id", "code", "loss_pct", "duration_ms", "start", "media", "ua"} {
		if _, ok := m[k]; ok {
			ks = append(ks, k)
		}
	}
	return ks
}

func TestExtraColumns(t *testing.T) {
	tb := mixedTable()
	for _, f := range []Format{FormatTable, FormatMarkdown, FormatHTML} {
		off := render(t, f, tb, Options{UTC: true})
		on := render(t, f, tb, Options{UTC: true, Extra: true})
		if strings.Contains(off, "UA") || strings.Contains(off, "Asterisk") {
			t.Errorf("%s: extra column shown without Extra", f)
		}
		if !strings.Contains(on, "UA") || !strings.Contains(on, "Asterisk") {
			t.Errorf("%s: extra column missing with Extra", f)
		}
	}
	for _, f := range []Format{FormatCSV, FormatJSON, FormatNDJSON} {
		a, b := render(t, f, tb, Options{UTC: true}), render(t, f, tb, Options{UTC: true, Extra: true})
		if a != b || !strings.Contains(a, "Asterisk") {
			t.Errorf("%s: extra columns must always be present", f)
		}
	}
}

// failWriter fails after n bytes.
type failWriter struct{ n int }

var errBoom = errors.New("boom")

func (w *failWriter) Write(p []byte) (int, error) {
	if len(p) > w.n {
		return 0, errBoom
	}
	w.n -= len(p)
	return len(p), nil
}

func TestWriteErrors(t *testing.T) {
	tb := Table{Columns: []Column{{Name: "A"}}}
	for range 20000 {
		tb.Rows = append(tb.Rows, []any{"some cell text"})
	}
	for _, f := range []Format{FormatTable, FormatCSV, FormatJSON, FormatNDJSON, FormatMarkdown, FormatHTML} {
		if err := Write(&failWriter{n: 100}, f, tb, Options{}); !errors.Is(err, errBoom) {
			t.Errorf("%s: err = %v", f, err)
		}
	}
	if err := WriteHTML(&failWriter{n: 100}, Document{Title: "x"}); !errors.Is(err, errBoom) {
		t.Errorf("WriteHTML: err = %v", err)
	}
}

// TestNoQuadratic checks that allocations and output grow linearly with rows.
func TestNoQuadratic(t *testing.T) {
	mk := func(n int) Table { return benchTable(n, 12) }
	small, large := mk(500), mk(5000)
	for _, f := range []Format{FormatTable, FormatCSV, FormatJSON, FormatNDJSON, FormatMarkdown, FormatHTML} {
		run := func(tb Table) float64 {
			return testing.AllocsPerRun(1, func() {
				if err := Write(discard{}, f, tb, Options{UTC: true, Color: true}); err != nil {
					t.Fatal(err)
				}
			})
		}
		a, b := run(small), run(large)
		if b > 14*a+100 {
			t.Errorf("%s: allocs grew %.0f -> %.0f for 10x rows", f, a, b)
		}
	}
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }
