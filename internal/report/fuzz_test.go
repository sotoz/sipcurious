package report

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// FuzzWriters feeds arbitrary strings (as cells, titles, names, keys) and
// numbers through every writer and checks the structural invariants: no panic,
// valid UTF-8, JSON and CSV that parse, one line per row in table/ndjson,
// no ESC outside our own styling, HTML without tag injection.
func FuzzWriters(f *testing.F) {
	for _, s := range hostileStrings {
		f.Add(s, s, int64(len(s)), 1.5, int64(1500000))
	}
	f.Add("a\x00b", "k\"ey", int64(math.MinInt64), math.NaN(), int64(math.MinInt64))
	f.Add("\xff", "", int64(0), math.Inf(1), int64(math.MaxInt64))
	f.Fuzz(func(t *testing.T, cell, name string, n int64, fl float64, ns int64) {
		tb := Table{
			Title: name,
			Columns: []Column{
				{Name: name, Key: name},
				{Name: "n", Kind: Int},
				{Name: "f", Kind: Float},
				{Name: "d", Kind: Duration},
				{Name: "t", Kind: Time},
				{Name: "x", Kind: String, Extra: true},
			},
			Rows: [][]any{
				{cell, n, fl, time.Duration(ns), time.Unix(0, ns).UTC(), cell},
				{name, uint64(n), float32(fl), nil, nil},
				{},
			},
		}
		// Keys must be unique for JSON: give the fuzzed column a prefix no other key has.
		tb.Columns[0].Key = "k:" + name
		for _, o := range []Options{{UTC: true}, {Color: true, Extra: true, HeaderRule: true}} {
			for _, f := range []Format{FormatTable, FormatCSV, FormatJSON, FormatNDJSON, FormatMarkdown, FormatHTML} {
				var b bytes.Buffer
				if err := Write(&b, f, tb, o); err != nil {
					t.Fatalf("%s: %v", f, err)
				}
				out := b.String()
				if !utf8.ValidString(out) {
					t.Fatalf("%s: invalid UTF-8", f)
				}
				switch f {
				case FormatTable:
					rest := strings.NewReplacer("\x1b[1m", "", "\x1b[0m", "", "\x1b[32m", "", "\x1b[33m", "", "\x1b[31m", "", "\x1b[2m", "").Replace(out)
					if strings.ContainsAny(rest, "\x1b\x00\t\r\v\f") {
						t.Fatalf("control character in table: %q", out)
					}
					want := 1 + len(tb.Rows)
					if name != "" {
						want++ // title
					}
					if o.HeaderRule {
						want++
					}
					if got := strings.Count(out, "\n"); got != want {
						t.Fatalf("%d lines want %d: %q", got, want, out)
					}
				case FormatCSV:
					r := csv.NewReader(strings.NewReader(out))
					r.FieldsPerRecord = len(tb.Columns)
					if recs, err := r.ReadAll(); err != nil || len(recs) != len(tb.Rows)+1 {
						t.Fatalf("csv: %d records, err %v: %q", len(recs), err, out)
					}
				case FormatJSON:
					var v []map[string]any
					if err := json.Unmarshal(b.Bytes(), &v); err != nil || len(v) != len(tb.Rows) {
						t.Fatalf("json: %v: %q", err, out)
					}
				case FormatNDJSON:
					lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
					if len(lines) != len(tb.Rows) {
						t.Fatalf("ndjson: %d lines: %q", len(lines), out)
					}
					for _, l := range lines {
						if !json.Valid([]byte(l)) {
							t.Fatalf("ndjson line: %q", l)
						}
					}
				case FormatMarkdown:
					want := 2 + len(tb.Rows)
					if name != "" {
						want += 2 // title and blank line
					}
					if strings.Count(out, "\n") != want {
						t.Fatalf("markdown lines: %q", out)
					}
				case FormatHTML:
					assertSafeHTML(t, out)
				}
			}
		}
		// Document with every block type.
		var b bytes.Buffer
		doc := hostileDocument(cell, name)
		if err := WriteHTML(&b, doc); err != nil {
			t.Fatal(err)
		}
		assertSafeDocument(t, b.String())
	})
}
