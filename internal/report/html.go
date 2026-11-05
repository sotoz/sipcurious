package report

import (
	"errors"
	"io"
	"strconv"
	"time"
)

// styleClass returns the CSS class of a cell style, or "".
func styleClass(st Style) string {
	switch st {
	case Good:
		return "sc-good"
	case Warn:
		return "sc-warn"
	case Bad:
		return "sc-bad"
	case Dim:
		return "sc-dim"
	}
	return ""
}

// appendClass appends a class attribute made of up to two class names.
func appendClass(dst []byte, a, b string) []byte {
	if a == "" && b == "" {
		return dst
	}
	dst = append(dst, ` class="`...)
	dst = append(dst, a...)
	if a != "" && b != "" {
		dst = append(dst, ' ')
	}
	dst = append(dst, b...)
	return append(dst, '"')
}

// writeHTMLTable writes t as an HTML table. The fragment is
//
//	<table class="sc-table"> [<caption class="sc-caption">] <thead>...</thead> <tbody>...</tbody> </table>
//
// With interactive set it is wrapped in a box carrying the filter input and
// the row counter that the document script wires up, and the headers become
// sortable (data-k="n" numeric/time columns, data-k="s" text columns).
// Numeric and time cells carry their sort key in data-v; missing values have
// none and sort last. Cells are styled with Column.Style classes.
func writeHTMLTable(s *sink, t Table, o Options, interactive bool) {
	cols := visible(t, o)
	if interactive {
		s.str("<div class=\"sc-tablebox\" data-sc-table>\n<div class=\"sc-tools\"><input type=\"search\" class=\"sc-filter\" placeholder=\"Filter rows\u2026\" aria-label=\"Filter rows\"><span class=\"sc-count\"></span></div>\n<div class=\"sc-scroll\">")
	}
	s.str("<table class=\"sc-table\">\n")
	if t.Title != "" {
		s.str("<caption class=\"sc-caption\">")
		s.buf = appendSanitized(s.buf, t.Title, modeHTMLInline)
		s.str("</caption>\n")
	}
	s.str("<thead><tr>")
	for _, j := range cols {
		c := t.Columns[j]
		s.str("<th")
		if c.Kind.numeric() {
			s.buf = appendClass(s.buf, "sc-num", "")
		}
		if interactive {
			if c.Kind.sortsNumerically() {
				s.str(` data-k="n"`)
			} else {
				s.str(` data-k="s"`)
			}
		}
		s.str(">")
		s.buf = appendSanitized(s.buf, c.Name, modeHTMLInline)
		s.str("</th>")
	}
	s.str("</tr></thead>\n<tbody>\n")
	for _, row := range t.Rows {
		s.str("<tr>")
		for _, j := range cols {
			c := t.Columns[j]
			raw := cell(row, j)
			v := normalize(raw)
			num := ""
			if c.Kind.numeric() {
				num = "sc-num"
			}
			st := ""
			if c.Style != nil {
				st = styleClass(c.Style(raw))
			}
			s.str("<td")
			s.buf = appendClass(s.buf, num, st)
			if interactive {
				s.buf = appendSortKey(s.buf, v)
			}
			s.str(">")
			s.buf = appendHuman(s.buf, v, o, modeHTML)
			s.str("</td>")
		}
		s.str("</tr>\n")
		s.maybeFlush()
	}
	s.str("</tbody>\n</table>\n")
	if interactive {
		s.str("</div>\n</div>\n")
	}
}

// appendSortKey appends a data-v attribute for numeric and time values.
func appendSortKey(dst []byte, v value) []byte {
	switch v.k {
	case vInt, vUint, vFloat:
		dst = append(dst, ` data-v="`...)
		dst = appendMachine(dst, v, Options{})
	case vDur:
		dst = append(dst, ` data-v="`...)
		dst = appendMillis(dst, time.Duration(v.n))
	case vTime:
		dst = append(dst, ` data-v="`...)
		dst = strconv.AppendInt(dst, v.t.UnixMilli(), 10)
	default:
		return dst
	}
	return append(dst, '"')
}

// Block is one element of a Document. The concrete types are Heading,
// Paragraph, KeyValues, TableBlock, Pre, Details, Badges, SVG and RawHTML;
// the interface is sealed, so output safety is decided in this package.
type Block interface {
	writeBlock(s *sink, depth int)
}

// maxNesting bounds Details recursion; deeper blocks are an error.
const maxNesting = 32

var errNesting = errors.New("blocks nested too deeply")

// Heading is a section heading. Level is clamped to 1..6 (h1..h6); the
// document title itself is an h1, so sections normally use 2 and up.
type Heading struct {
	Level int
	Text  string
}

func (b Heading) writeBlock(s *sink, _ int) {
	lv := min(max(b.Level, 1), 6)
	s.str("<h")
	s.buf = strconv.AppendInt(s.buf, int64(lv), 10)
	s.str(" class=\"sc-h sc-h")
	s.buf = strconv.AppendInt(s.buf, int64(lv), 10)
	s.str("\">")
	s.buf = appendSanitized(s.buf, b.Text, modeHTMLInline)
	s.str("</h")
	s.buf = strconv.AppendInt(s.buf, int64(lv), 10)
	s.str(">\n")
}

// Paragraph is a paragraph of plain text; newlines become line breaks.
type Paragraph struct{ Text string }

func (b Paragraph) writeBlock(s *sink, _ int) {
	s.str("<p class=\"sc-p\">")
	s.buf = appendSanitized(s.buf, b.Text, modeHTML)
	s.str("</p>\n")
}

// KeyValue is one summary card: a small label and a large value.
type KeyValue struct {
	Key, Value string
	Style      Style
}

// KeyValues renders summary cards in a responsive grid.
type KeyValues []KeyValue

func (b KeyValues) writeBlock(s *sink, _ int) {
	s.str("<dl class=\"sc-kv\">\n")
	for _, kv := range b {
		s.str("<div")
		s.buf = appendClass(s.buf, "sc-card", styleClass(kv.Style))
		s.str("><dt class=\"sc-k\">")
		s.buf = appendSanitized(s.buf, kv.Key, modeHTMLInline)
		s.str("</dt><dd class=\"sc-v\">")
		s.buf = appendSanitized(s.buf, kv.Value, modeHTML)
		s.str("</dd></div>\n")
	}
	s.str("</dl>\n")
}

// TableBlock is an interactive table: click a header to sort, type into the
// filter box to hide rows that do not contain every word typed. Both need the
// document's inline script. Options selects Extra columns and the time zone;
// Color and HeaderRule are ignored.
type TableBlock struct {
	Table   Table
	Options Options
}

func (b TableBlock) writeBlock(s *sink, _ int) {
	writeHTMLTable(s, b.Table, b.Options, true)
}

// Pre is preformatted monospace text (a raw SIP message, an SDP body). Tabs
// and line breaks are kept, control characters are replaced.
type Pre struct{ Text string }

func (b Pre) writeBlock(s *sink, _ int) {
	s.str("<pre class=\"sc-pre\">")
	s.buf = appendSanitized(s.buf, b.Text, modeHTMLPre)
	s.str("</pre>\n")
}

// Details is a collapsible group of blocks.
type Details struct {
	Summary string
	Open    bool
	Blocks  []Block
}

func (b Details) writeBlock(s *sink, depth int) {
	s.str("<details class=\"sc-details\"")
	if b.Open {
		s.str(" open")
	}
	s.str("><summary class=\"sc-summary\">")
	s.buf = appendSanitized(s.buf, b.Summary, modeHTMLInline)
	s.str("</summary>\n<div class=\"sc-body\">\n")
	for _, c := range b.Blocks {
		writeBlock(s, c, depth+1)
	}
	s.str("</div>\n</details>\n")
}

// Badge is a small colored label.
type Badge struct {
	Text  string
	Style Style
}

// SeverityBadge returns the badge for a finding severity name (see SeverityStyle).
func SeverityBadge(name string) Badge { return Badge{Text: name, Style: SeverityStyle(name)} }

// BadgeHTML returns the markup of one badge, for use in RawHTML or when
// assembling trusted markup by hand. Text is escaped.
func BadgeHTML(b Badge) string {
	buf := append([]byte(nil), "<span"...)
	buf = appendClass(buf, "sc-badge", styleClass(b.Style))
	buf = append(buf, '>')
	buf = appendSanitized(buf, b.Text, modeHTMLInline)
	return string(append(buf, "</span>"...))
}

// Badges renders a row of badges.
type Badges []Badge

func (b Badges) writeBlock(s *sink, _ int) {
	s.str("<p class=\"sc-badges\">")
	for i, x := range b {
		if i > 0 {
			s.buf = append(s.buf, ' ')
		}
		s.str(BadgeHTML(x))
	}
	s.str("</p>\n")
}

// SVG embeds a ready made SVG image inside a scrollable figure. The markup is
// TRUSTED and written verbatim: only pass output of this repository's
// diagram generator (which escapes all captured text itself), never text
// taken from a capture. Title is a plain-text caption.
type SVG struct {
	Title  string
	Markup string
}

func (b SVG) writeBlock(s *sink, _ int) {
	s.str("<figure class=\"sc-fig\"><div class=\"sc-scroll\">")
	s.str(b.Markup)
	s.str("</div>")
	if b.Title != "" {
		s.str("<figcaption class=\"sc-figcap\">")
		s.buf = appendSanitized(s.buf, b.Title, modeHTMLInline)
		s.str("</figcaption>")
	}
	s.str("</figure>\n")
}

// RawHTML is trusted markup written verbatim into the page, wrapped in
// <div class="sc-raw">. Never put captured text in it unescaped.
type RawHTML struct{ HTML string }

func (b RawHTML) writeBlock(s *sink, _ int) {
	s.str("<div class=\"sc-raw\">")
	s.str(b.HTML)
	s.str("</div>\n")
}

// writeBlock dispatches to c, guarding against nil blocks and runaway nesting.
func writeBlock(s *sink, c Block, depth int) {
	if c == nil {
		return
	}
	if depth > maxNesting {
		s.str("<p class=\"sc-p sc-bad\">\u2026</p>\n")
		return
	}
	c.writeBlock(s, depth)
	s.maybeFlush()
}

// Document is a complete, self-contained HTML page.
type Document struct {
	// Title is the page title and the h1. Subtitle is shown below it.
	Title, Subtitle string
	// Generated, if not zero, is shown as "Generated <RFC 3339 UTC>". It is
	// an input (not time.Now) so that output is reproducible.
	Generated time.Time
	Blocks    []Block
}

// WriteHTML writes d as one HTML5 file: inline CSS (light and dark through
// prefers-color-scheme, print friendly), one small inline script (table sort
// and filter, details opened for printing), no external assets, no network
// access. Every string of the document and of its blocks is escaped, except
// SVG.Markup and RawHTML.HTML which are trusted.
func WriteHTML(w io.Writer, d Document) error {
	if err := checkNesting(d.Blocks, 0); err != nil {
		return err
	}
	s := newSink(w)
	s.str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n")
	s.str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n")
	s.str("<meta name=\"color-scheme\" content=\"light dark\">\n<title>")
	s.buf = appendSanitized(s.buf, d.Title, modeHTMLInline)
	s.str("</title>\n<style>\n")
	s.str(htmlCSS)
	s.str("</style>\n</head>\n<body class=\"sc-doc\">\n<header class=\"sc-header\">\n<h1 class=\"sc-title\">")
	s.buf = appendSanitized(s.buf, d.Title, modeHTMLInline)
	s.str("</h1>\n")
	if d.Subtitle != "" {
		s.str("<p class=\"sc-subtitle\">")
		s.buf = appendSanitized(s.buf, d.Subtitle, modeHTMLInline)
		s.str("</p>\n")
	}
	if !d.Generated.IsZero() {
		s.str("<p class=\"sc-generated\">Generated ")
		s.buf = d.Generated.UTC().AppendFormat(s.buf, "2006-01-02T15:04:05Z")
		s.str("</p>\n")
	}
	s.str("</header>\n<main class=\"sc-main\">\n")
	for _, b := range d.Blocks {
		writeBlock(s, b, 0)
	}
	s.str("</main>\n<script>\n")
	s.str(htmlJS)
	s.str("</script>\n</body>\n</html>\n")
	return s.flush()
}

// checkNesting rejects documents nested deeper than maxNesting.
func checkNesting(bs []Block, depth int) error {
	if depth > maxNesting {
		return errNesting
	}
	for _, b := range bs {
		if d, ok := b.(Details); ok {
			if err := checkNesting(d.Blocks, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

const htmlJS = `(function () {
  function init(box) {
    var table = box.querySelector('table'), body = table.tBodies[0];
    var rows = Array.prototype.slice.call(body.rows), total = rows.length;
    var input = box.querySelector('.sc-filter'), count = box.querySelector('.sc-count');
    function filter() {
      var terms = input.value.toLowerCase().split(/\s+/).filter(Boolean), shown = 0;
      rows.forEach(function (r) {
        var text = r.textContent.toLowerCase();
        r.hidden = !terms.every(function (t) { return text.indexOf(t) >= 0; });
        if (!r.hidden) shown++;
      });
      count.textContent = (shown === total ? total : shown + ' / ' + total) + ' rows';
    }
    input.addEventListener('input', filter);
    var heads = table.tHead.rows[0].cells, last = -1, asc = true;
    Array.prototype.forEach.call(heads, function (th, i) {
      th.addEventListener('click', function () {
        asc = last === i ? !asc : true;
        last = i;
        var numeric = th.getAttribute('data-k') === 'n';
        rows.sort(function (a, b) {
          var x = a.cells[i], y = b.cells[i], xv = x.getAttribute('data-v'), yv = y.getAttribute('data-v'), c;
          if (numeric) {
            if (xv === null || yv === null) return xv === yv ? 0 : xv === null ? 1 : -1;
            c = parseFloat(xv) - parseFloat(yv);
          } else {
            c = x.textContent.localeCompare(y.textContent, undefined, { numeric: true });
          }
          return asc ? c : -c;
        });
        rows.forEach(function (r) { body.appendChild(r); });
        Array.prototype.forEach.call(heads, function (h) { h.removeAttribute('aria-sort'); });
        th.setAttribute('aria-sort', asc ? 'ascending' : 'descending');
      });
    });
    filter();
  }
  Array.prototype.forEach.call(document.querySelectorAll('[data-sc-table]'), init);
  window.addEventListener('beforeprint', function () {
    Array.prototype.forEach.call(document.querySelectorAll('details'), function (d) { d.open = true; });
  });
})();
`

const htmlCSS = `:root{--bg:#fff;--fg:#1d2330;--mut:#667085;--line:#d9dee7;--card:#f5f7fa;--hd:#eaeef4;--accent:#2457c5;--good:#0a7a3d;--warn:#9a6700;--bad:#c4262e;--goodbg:#e6f6ec;--warnbg:#fff4d6;--badbg:#fde8e9;--pre:#f6f8fa}
@media (prefers-color-scheme:dark){:root{--bg:#14171d;--fg:#e4e8ef;--mut:#98a2b3;--line:#2d3440;--card:#1c2028;--hd:#232934;--accent:#7aa2f7;--good:#4cc38a;--warn:#e3b341;--bad:#ff7b72;--goodbg:#12301f;--warnbg:#3a2f0e;--badbg:#3d1a1d;--pre:#0f1217}}
*{box-sizing:border-box}
body.sc-doc{margin:0;padding:1.5rem;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.sc-header{border-bottom:1px solid var(--line);margin-bottom:1rem}
.sc-title{margin:0 0 .25rem;font-size:1.6rem}
.sc-subtitle{margin:0;color:var(--mut)}
.sc-generated{margin:.25rem 0 .75rem;color:var(--mut);font-size:12px}
.sc-main{max-width:100%}
.sc-h{margin:1.5rem 0 .5rem;line-height:1.25}
.sc-p{margin:.5rem 0}
.sc-kv{display:grid;grid-template-columns:repeat(auto-fill,minmax(12rem,1fr));gap:.75rem;margin:.75rem 0}
.sc-card{background:var(--card);border:1px solid var(--line);border-radius:6px;padding:.5rem .75rem}
.sc-k{color:var(--mut);font-size:12px;text-transform:uppercase;letter-spacing:.04em}
.sc-v{margin:0;font-size:1.25rem;font-weight:600;overflow-wrap:anywhere}
.sc-card.sc-good{border-left:4px solid var(--good)}.sc-card.sc-warn{border-left:4px solid var(--warn)}.sc-card.sc-bad{border-left:4px solid var(--bad)}.sc-card.sc-dim{opacity:.7}
.sc-tablebox{margin:.75rem 0}
.sc-tools{display:flex;gap:.75rem;align-items:center;margin-bottom:.4rem}
.sc-filter{flex:0 1 22rem;padding:.3rem .5rem;border:1px solid var(--line);border-radius:4px;background:var(--bg);color:var(--fg);font:inherit}
.sc-count{color:var(--mut);font-size:12px}
.sc-scroll{overflow:auto;max-width:100%}
.sc-table{border-collapse:collapse;width:100%;font-variant-numeric:tabular-nums}
.sc-caption{caption-side:top;text-align:left;font-weight:600;padding:.25rem 0}
.sc-table th,.sc-table td{border:1px solid var(--line);padding:.25rem .5rem;text-align:left;vertical-align:top;overflow-wrap:anywhere}
.sc-table th{background:var(--hd);position:sticky;top:0;white-space:nowrap}
.sc-tablebox th[data-k]{cursor:pointer;user-select:none}
.sc-tablebox th[aria-sort=ascending]::after{content:" \25B2";font-size:10px}
.sc-tablebox th[aria-sort=descending]::after{content:" \25BC";font-size:10px}
.sc-table tbody tr:nth-child(even){background:var(--card)}
.sc-table .sc-num{text-align:right}
td.sc-good{color:var(--good);background:var(--goodbg)}td.sc-warn{color:var(--warn);background:var(--warnbg)}td.sc-bad{color:var(--bad);background:var(--badbg)}td.sc-dim{color:var(--mut)}
.sc-pre{margin:.5rem 0;padding:.75rem;background:var(--pre);border:1px solid var(--line);border-radius:6px;overflow:auto;font:12px/1.45 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;white-space:pre}
.sc-details{margin:.5rem 0;border:1px solid var(--line);border-radius:6px;padding:0 .75rem}
.sc-summary{cursor:pointer;padding:.4rem 0;font-weight:600}
.sc-body{padding-bottom:.5rem}
.sc-badges{margin:.5rem 0}
.sc-badge{display:inline-block;padding:0 .5rem;border-radius:999px;border:1px solid var(--line);background:var(--card);font-size:12px;font-weight:600}
.sc-badge.sc-good{color:var(--good);background:var(--goodbg)}.sc-badge.sc-warn{color:var(--warn);background:var(--warnbg)}.sc-badge.sc-bad{color:var(--bad);background:var(--badbg)}.sc-badge.sc-dim{color:var(--mut)}
.sc-fig{margin:.75rem 0}
.sc-figcap{color:var(--mut);font-size:12px;margin-top:.25rem}
.sc-fig svg{max-width:100%;height:auto}
@media print{body.sc-doc{padding:0;background:#fff;color:#000;font-size:11px}.sc-tools{display:none}.sc-pre{white-space:pre-wrap}.sc-table th{position:static}.sc-table,.sc-card,.sc-details{break-inside:auto}tr{break-inside:avoid}}
`
