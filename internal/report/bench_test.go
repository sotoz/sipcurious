package report

import (
	"fmt"
	"net/netip"
	"testing"
	"time"
)

// benchTable builds a SIP-call-like table of rows x cols cells. The columns
// cycle through all Kinds; every tenth cell is missing.
func benchTable(rows, cols int) Table {
	tb := Table{Title: "bench", Columns: make([]Column, cols)}
	for j := range tb.Columns {
		c := Column{Name: fmt.Sprintf("Column %d", j), Kind: Kind(j % 6)}
		if j%6 == 1 {
			c.Style = func(v any) Style {
				if n, ok := v.(int); ok {
					return StatusStyle(n)
				}
				return None
			}
		}
		tb.Columns[j] = c
	}
	base := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	addr := netip.MustParseAddr("10.1.2.3")
	_ = addr
	tb.Rows = make([][]any, rows)
	cells := make([]any, rows*cols)
	for i := range tb.Rows {
		row := cells[i*cols : (i+1)*cols : (i+1)*cols]
		for j := range row {
			if (i+j)%10 == 9 {
				continue
			}
			switch Kind(j % 6) {
			case String:
				row[j] = "call-" + fmt.Sprint(i) + "@pbx.example.com"
			case Int:
				row[j] = 100 + (i%6)*100 + j
			case Float:
				row[j] = float64(i%1000) / 7
			case Duration:
				row[j] = time.Duration(i%100000) * time.Millisecond
			case Time:
				row[j] = base.Add(time.Duration(i) * time.Millisecond)
			case Bool:
				row[j] = i%2 == 0
			}
		}
		tb.Rows[i] = row
	}
	return tb
}

// BenchmarkWriters renders 100k rows x 12 columns in every format.
func BenchmarkWriters(b *testing.B) {
	tb := benchTable(100_000, 12)
	for _, f := range []Format{FormatTable, FormatCSV, FormatJSON, FormatNDJSON, FormatMarkdown, FormatHTML} {
		b.Run(string(f), func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				if err := Write(discard{}, f, tb, Options{UTC: true}); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/float64(len(tb.Rows)), "ns/row")
		})
	}
	b.Run("table/color", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			if err := Write(discard{}, FormatTable, tb, Options{UTC: true, Color: true}); err != nil {
				b.Fatal(err)
			}
		}
		b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/float64(len(tb.Rows)), "ns/row")
	})
}

// BenchmarkScaling renders 10k, 100k and 1M rows of one format to show
// linear growth (ns/row stays flat).
func BenchmarkScaling(b *testing.B) {
	for _, f := range []Format{FormatTable, FormatJSON} {
		for _, n := range []int{10_000, 100_000, 400_000} {
			tb := benchTable(n, 12)
			b.Run(fmt.Sprintf("%s/%d", f, n), func(b *testing.B) {
				for range b.N {
					if err := Write(discard{}, f, tb, Options{UTC: true}); err != nil {
						b.Fatal(err)
					}
				}
				b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/float64(n), "ns/row")
			})
		}
	}
}

func BenchmarkFormatDuration(b *testing.B) {
	b.ReportAllocs()
	for i := range b.N {
		_ = FormatDuration(time.Duration(i) * 1234567)
	}
}

func BenchmarkSanitizeClean(b *testing.B) {
	s := "sip:alice@example.com;transport=udp"
	buf := make([]byte, 0, 256)
	b.ReportAllocs()
	for range b.N {
		buf = appendSanitized(buf[:0], s, modeText)
	}
}
