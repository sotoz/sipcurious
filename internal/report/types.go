package report

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// Kind is the semantic type of a column. It selects the machine key suffix
// (Duration columns are exported as <key>_ms), the alignment in text,
// Markdown and HTML (Int, Float and Duration are right aligned) and the sort
// mode of HTML tables. How a single cell is rendered depends on the cell's
// dynamic type, never on Kind.
type Kind int

// Column kinds.
const (
	String   Kind = iota // text, left aligned
	Int                  // integer, right aligned
	Float                // floating point, right aligned
	Duration             // time.Duration, right aligned; exported as milliseconds under "<key>_ms"
	Time                 // time.Time, left aligned
	Bool                 // true/false, left aligned
)

// numeric reports whether columns of this kind are right aligned.
func (k Kind) numeric() bool { return k == Int || k == Float || k == Duration }

// sortsNumerically reports whether HTML tables sort the column by value.
func (k Kind) sortsNumerically() bool { return k.numeric() || k == Time }

// Style is a presentation hint for a cell: ANSI color in the text table when
// Options.Color is set, a CSS class (sc-good, sc-warn, sc-bad, sc-dim) in HTML.
// Markdown, CSV and JSON ignore it.
type Style int

// Cell styles.
const (
	None Style = iota // no styling
	Good              // success (green)
	Warn              // needs attention (yellow)
	Bad               // failure (red)
	Dim               // de-emphasised (faint)
)

// Column describes one table column.
type Column struct {
	// Name is the human readable header used by table, Markdown and HTML.
	Name string
	// Key is the stable machine name used by CSV, JSON and NDJSON. If empty
	// it is derived from Name (lower case, runs of other characters become
	// one underscore). Duration columns get the suffix "_ms" appended unless
	// the key already ends in it.
	Key string
	// Kind is the semantic type, see Kind.
	Kind Kind
	// Extra columns are hidden in table, Markdown and HTML unless
	// Options.Extra is set. CSV, JSON and NDJSON always carry them.
	Extra bool
	// Style, if non-nil, maps a raw cell value (nil for a missing cell) to a
	// presentation hint. It is called once per cell for the text table when
	// Options.Color is set, and for every cell of an HTML table.
	Style func(v any) Style
}

// Table is a titled grid of cells. A cell is one of: string, []byte, any
// integer type, float32/float64, time.Duration, time.Time, bool, netip.Addr,
// netip.AddrPort, error, fmt.Stringer or nil. Values of other types are
// rendered with fmt.Sprint.
//
// Missing values: nil, a typed nil pointer, a zero time.Time, an invalid
// netip.Addr or AddrPort and a non-finite float (NaN, +/-Inf) all mean "no
// value": an empty cell in table, CSV, Markdown and HTML, and an omitted key
// in JSON and NDJSON. An empty string is a value: it stays "" in JSON.
//
// A row shorter than Columns is padded with missing values. A row longer
// than Columns is an error (the writer returns it before writing anything).
type Table struct {
	Title   string
	Columns []Column
	Rows    [][]any
}

// Options tune the output.
type Options struct {
	// Extra shows Extra columns in table, Markdown and HTML.
	Extra bool
	// UTC renders times in UTC. Otherwise they are rendered in Location, or
	// in time.Local if Location is nil.
	UTC bool
	// Location is the zone used when UTC is false. Nil means time.Local.
	Location *time.Location
	// Color enables ANSI color and bold in the text table. Nothing else is
	// affected, and input text can never inject escape sequences.
	Color bool
	// HeaderRule underlines the header of the text table with dashes.
	HeaderRule bool
}

// zone converts t to the zone selected by o.
func (o Options) zone(t time.Time) time.Time {
	switch {
	case o.UTC:
		return t.UTC()
	case o.Location != nil:
		return t.In(o.Location)
	}
	return t.Local()
}

// Format is an output format.
type Format string

// Output formats.
const (
	FormatTable    Format = "table"
	FormatCSV      Format = "csv"
	FormatJSON     Format = "json"
	FormatNDJSON   Format = "ndjson"
	FormatMarkdown Format = "markdown"
	FormatHTML     Format = "html"
)

// allFormats lists the valid formats in the order they are advertised.
var allFormats = [...]Format{FormatTable, FormatCSV, FormatJSON, FormatNDJSON, FormatMarkdown, FormatHTML}

// Formats returns the valid format names in advertised order.
func Formats() []string {
	names := make([]string, len(allFormats))
	for i, f := range allFormats {
		names[i] = string(f)
	}
	return names
}

// ParseFormat parses a format name, ignoring case and surrounding whitespace.
func ParseFormat(s string) (Format, error) {
	n := Format(strings.ToLower(strings.TrimSpace(s)))
	for _, f := range allFormats {
		if n == f {
			return f, nil
		}
	}
	return "", fmt.Errorf("unknown format %q (valid: %s)", s, strings.Join(Formats(), ", "))
}

func errFormat(f Format) error {
	return fmt.Errorf("unknown format %q (valid: %s)", string(f), strings.Join(Formats(), ", "))
}

// Write renders t in format f.
//
//   - table: space padded columns, no trailing whitespace, the title (if any)
//     on its own first line.
//   - csv: header of keys, then one record per row; all columns; "\n" line ends.
//   - json: indented array of objects keyed by Column.Key; all columns.
//   - ndjson: one compact object per line; all columns.
//   - markdown: GFM table preceded by a "### title" heading.
//   - html: a <table class="sc-table"> fragment with the title as caption.
//
// Nothing is written if the table is invalid (row longer than Columns, or
// duplicate keys in JSON/NDJSON) or f is unknown.
func Write(w io.Writer, f Format, t Table, o Options) error {
	if err := validate(f, t); err != nil {
		return err
	}
	s := newSink(w)
	switch f {
	case FormatTable:
		writeText(s, t, o)
	case FormatCSV:
		writeCSV(s, t, o)
	case FormatJSON:
		writeJSON(s, t, o, 0)
		s.buf = append(s.buf, '\n')
	case FormatNDJSON:
		writeNDJSON(s, t, o)
	case FormatMarkdown:
		writeMarkdown(s, t, o)
	case FormatHTML:
		writeHTMLTable(s, t, o, false)
	default:
		return errFormat(f)
	}
	return s.flush()
}

// Section is a named table in a multi-table document.
type Section struct {
	// Name is the section heading, and the JSON object key. If empty, the
	// table's Title is used instead.
	Name  string
	Table Table
}

func (s Section) name() string {
	if s.Name != "" {
		return s.Name
	}
	return s.Table.Title
}

// WriteSections renders several tables as one document.
//
//   - json: one object mapping each section name to its array of rows.
//   - table, markdown, html: a heading and a table per section, separated by
//     a blank line (html: <h2> plus fragment, no blank line).
//   - csv, ndjson: an error, they cannot express several tables.
func WriteSections(w io.Writer, f Format, secs []Section, o Options) error {
	switch f {
	case FormatCSV, FormatNDJSON:
		return fmt.Errorf("format %s cannot hold several tables", f)
	case FormatTable, FormatMarkdown, FormatHTML, FormatJSON:
	default:
		return errFormat(f)
	}
	seen := make(map[string]bool, len(secs))
	for i, sec := range secs {
		if err := validate(f, sec.Table); err != nil {
			return fmt.Errorf("section %d (%q): %w", i, sec.name(), err)
		}
		if f == FormatJSON {
			n := sec.name()
			if n == "" {
				return fmt.Errorf("section %d has no name", i)
			}
			if seen[n] {
				return fmt.Errorf("duplicate section name %q", n)
			}
			seen[n] = true
		}
	}
	s := newSink(w)
	if f == FormatJSON {
		writeJSONSections(s, secs, o)
		s.buf = append(s.buf, '\n')
		return s.flush()
	}
	for i, sec := range secs {
		t := sec.Table
		t.Title = sec.name()
		if i > 0 && f != FormatHTML {
			s.buf = append(s.buf, '\n')
		}
		switch f {
		case FormatTable:
			writeText(s, t, o)
		case FormatMarkdown:
			writeMarkdown(s, t, o)
		case FormatHTML:
			s.str("<section class=\"sc-section\">\n<h2 class=\"sc-h\">")
			s.buf = appendSanitized(s.buf, t.Title, modeHTML)
			s.str("</h2>\n")
			t.Title = ""
			writeHTMLTable(s, t, o, false)
			s.str("</section>\n")
		}
		s.maybeFlush()
	}
	return s.flush()
}

var errNoColumnsRow = errors.New("row has more cells than the table has columns")

// validate checks t before anything is written.
func validate(f Format, t Table) error {
	n := len(t.Columns)
	for i, row := range t.Rows {
		if len(row) > n {
			return fmt.Errorf("row %d has %d cells for %d columns: %w", i, len(row), n, errNoColumnsRow)
		}
	}
	if f == FormatJSON || f == FormatNDJSON {
		seen := make(map[string]bool, n)
		for _, c := range t.Columns {
			k := c.jsonKey()
			if seen[k] {
				return fmt.Errorf("duplicate key %q in columns", k)
			}
			seen[k] = true
		}
	}
	return nil
}

// key returns the machine key of c without the duration suffix.
func (c Column) baseKey() string {
	if c.Key != "" {
		return c.Key
	}
	var b strings.Builder
	under := false
	for _, r := range strings.ToLower(c.Name) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			if under && b.Len() > 0 {
				b.WriteByte('_')
			}
			under = false
			b.WriteRune(r)
		} else {
			under = true
		}
	}
	return b.String()
}

// jsonKey returns the machine key including the "_ms" suffix of Duration
// columns. It is also the CSV header.
func (c Column) jsonKey() string {
	k := c.baseKey()
	if c.Kind == Duration && !strings.HasSuffix(k, "_ms") {
		k += "_ms"
	}
	return k
}

// cell returns row[j], or nil if the row is shorter.
func cell(row []any, j int) any {
	if j < len(row) {
		return row[j]
	}
	return nil
}
