package report

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// allowedTags and allowedAttrs are everything the writer (and the benign
// trusted markup used in tests) may emit. Anything else in output derived
// from hostile text is an injection.
var allowedTags = map[string]bool{
	"html": true, "head": true, "meta": true, "title": true, "style": true, "body": true, "header": true,
	"h1": true, "h2": true, "h3": true, "h4": true, "h5": true, "h6": true, "p": true, "main": true,
	"script": true, "dl": true, "div": true, "dt": true, "dd": true, "input": true, "span": true,
	"table": true, "caption": true, "thead": true, "tbody": true, "tr": true, "th": true, "td": true,
	"pre": true, "details": true, "summary": true, "section": true, "figure": true, "figcaption": true,
	"svg": true, "rect": true, "br": true,
}

var allowedAttrs = map[string]bool{
	"lang": true, "charset": true, "name": true, "content": true, "class": true, "data-k": true,
	"data-v": true, "data-sc-table": true, "type": true, "placeholder": true, "aria-label": true,
	"open": true, "x": true, "width": true, "height": true, "xmlns": true,
}

// assertSafeHTML checks a fragment: only whitelisted tags and attributes,
// attribute values without quotes or angle brackets, text without < or >, and
// every ampersand starting one of our five entities.
func assertSafeHTML(t *testing.T, s string) {
	t.Helper()
	for len(s) > 0 {
		lt := strings.IndexByte(s, '<')
		text := s
		if lt >= 0 {
			text = s[:lt]
		}
		assertSafeText(t, text)
		if lt < 0 {
			return
		}
		s = s[lt+1:]
		end := scanTag(t, s)
		if end < 0 {
			return
		}
		s = s[end:]
	}
}

func assertSafeText(t *testing.T, text string) {
	t.Helper()
	if strings.ContainsAny(text, "<>") {
		t.Errorf("angle bracket in text: %.80q", text)
	}
	for i := 0; i < len(text); i++ {
		if text[i] != '&' {
			continue
		}
		rest := text[i+1:]
		if !strings.HasPrefix(rest, "amp;") && !strings.HasPrefix(rest, "lt;") && !strings.HasPrefix(rest, "gt;") &&
			!strings.HasPrefix(rest, "quot;") && !strings.HasPrefix(rest, "#39;") {
			t.Errorf("bare ampersand: %.80q", text[i:])
			return
		}
	}
}

// scanTag consumes one tag (s starts after '<') and returns the index after
// its '>'. Doctype and closing tags are accepted. Script and style bodies are
// skipped here, the writer's own constants.
func scanTag(t *testing.T, s string) int {
	t.Helper()
	if strings.HasPrefix(s, "!DOCTYPE html>") {
		return len("!DOCTYPE html>")
	}
	i := 0
	closing := false
	if i < len(s) && s[i] == '/' {
		closing = true
		i++
	}
	start := i
	for i < len(s) && (s[i] >= 'a' && s[i] <= 'z' || s[i] >= '0' && s[i] <= '9') {
		i++
	}
	name := s[start:i]
	if !allowedTags[name] {
		t.Errorf("tag not allowed: <%.40q", s)
		return -1
	}
	for {
		for i < len(s) && s[i] == ' ' {
			i++
		}
		if i >= len(s) {
			t.Errorf("unterminated tag <%.40s", s)
			return -1
		}
		if s[i] == '>' {
			i++
			break
		}
		if s[i] == '/' && i+1 < len(s) && s[i+1] == '>' {
			i += 2
			break
		}
		if closing {
			t.Errorf("attributes on closing tag: %.40q", s)
			return -1
		}
		as := i
		for i < len(s) && (s[i] >= 'a' && s[i] <= 'z' || s[i] == '-') {
			i++
		}
		if !allowedAttrs[s[as:i]] {
			t.Errorf("attribute not allowed: %.60q", s[as:])
			return -1
		}
		if i < len(s) && s[i] == '=' {
			i++
			if i >= len(s) || s[i] != '"' {
				t.Errorf("unquoted attribute value: %.60q", s[as:])
				return -1
			}
			i++
			ve := strings.IndexByte(s[i:], '"')
			if ve < 0 {
				t.Errorf("unterminated attribute value: %.60q", s[as:])
				return -1
			}
			if v := s[i : i+ve]; strings.ContainsAny(v, "<>") {
				t.Errorf("angle bracket in attribute: %q", v)
			}
			i += ve + 1
		}
	}
	if !closing && (name == "script" || name == "style") {
		// raw text element: skip to its end tag
		end := strings.Index(s[i:], "</"+name+">")
		if end < 0 {
			t.Errorf("unterminated <%s>", name)
			return -1
		}
		i += end
	}
	return i
}

// assertSafeDocument checks a whole page: safe markup, exactly one script and
// one style, and no external references.
func assertSafeDocument(t *testing.T, s string) {
	t.Helper()
	assertSafeHTML(t, s)
	if n := strings.Count(s, "<script"); n != 1 {
		t.Errorf("%d <script> tags", n)
	}
	if n := strings.Count(s, "<style"); n != 1 {
		t.Errorf("%d <style> tags", n)
	}
	// src/href attributes cannot appear: the attribute whitelist rejects them.
	for _, bad := range []string{"http://", "https://", "@import", "url("} {
		// The only permitted URL is the SVG namespace in trusted test markup.
		if strings.Contains(strings.ReplaceAll(s, "xmlns=\"http://www.w3.org/2000/svg\"", ""), bad) {
			t.Errorf("document references external resource (%q)", bad)
		}
	}
}

// hostileDocument uses cell and name in every block type that takes text.
func hostileDocument(cell, name string) Document {
	tb := Table{Title: name, Columns: []Column{
		{Name: name, Key: "k"},
		{Name: "N", Kind: Int, Style: func(any) Style { return Bad }},
	}, Rows: [][]any{{cell, 1}, {name, nil}}}
	return Document{
		Title:     name,
		Subtitle:  cell,
		Generated: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		Blocks: []Block{
			Heading{Level: 2, Text: cell},
			Heading{Level: 99, Text: name},
			Heading{Level: -4, Text: name},
			Paragraph{Text: cell},
			KeyValues{{Key: name, Value: cell, Style: Warn}, {Key: cell, Value: name}},
			TableBlock{Table: tb, Options: Options{UTC: true, Extra: true}},
			Pre{Text: cell},
			Details{Summary: cell, Open: true, Blocks: []Block{
				Pre{Text: name},
				Details{Summary: name, Blocks: []Block{Paragraph{Text: cell}, nil}},
			}},
			Badges{{Text: cell, Style: Good}, SeverityBadge(name), {Text: name, Style: Style(99)}},
			SVG{Title: cell, Markup: `<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"><rect x="0"/></svg>`},
			RawHTML{HTML: `<p class="sc-p">trusted</p>`},
		},
	}
}

func TestHTMLXSS(t *testing.T) {
	payloads := append([]string{
		`<script>alert(1)</script>`,
		`"><img src=x onerror=alert(1)>`,
		`'><svg/onload=alert(1)>`,
		`</title><script>alert(1)</script>`,
		`</pre><script>alert(1)</script>`,
		`</td></tr></table><script>alert(1)</script>`,
		`</summary></details><script>alert(1)</script>`,
		`</style><script>alert(1)</script>`,
		`" onmouseover="alert(1)`,
		`javascript:alert(1)`,
		`&lt;script&gt;`,
		`&#60;script&#62;`,
		"<scr\x00ipt>alert(1)</scr\x00ipt>",
		"<a href=\"x\u2028\">",
		"<!--",
		"<![CDATA[",
	}, hostileStrings...)
	for _, p := range payloads {
		var b bytes.Buffer
		if err := WriteHTML(&b, hostileDocument(p, p)); err != nil {
			t.Fatalf("%q: %v", p, err)
		}
		assertSafeDocument(t, b.String())
		if strings.Contains(b.String(), "<!--") {
			t.Errorf("%q: comment injected", p)
		}
		// Table fragment and section forms.
		tb := Table{Title: p, Columns: []Column{{Name: p}}, Rows: [][]any{{p}}}
		frag := render(t, FormatHTML, tb, Options{})
		assertSafeHTML(t, frag)
		var sec bytes.Buffer
		if err := WriteSections(&sec, FormatHTML, []Section{{Name: p, Table: tb}}, Options{}); err != nil {
			t.Fatal(err)
		}
		assertSafeHTML(t, sec.String())
	}
}

func TestHTMLNoLiteralPayload(t *testing.T) {
	// Spot check on the raw bytes, independent of our tokenizer.
	p := `<script>alert(1)</script>"><img src=x onerror=alert(1)>`
	var b bytes.Buffer
	if err := WriteHTML(&b, hostileDocument(p, p)); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if strings.Contains(out, "<img") || strings.Contains(out, "alert(1)</script>") || strings.Contains(out, `"><`+"img") {
		t.Error("payload present unescaped")
	}
	if !strings.Contains(out, "&lt;script&gt;alert(1)&lt;/script&gt;&quot;&gt;&lt;img src=x onerror=alert(1)&gt;") {
		t.Error("escaped payload not found")
	}
	// Hidden BOM and ESC never make it through.
	if strings.ContainsAny(out, "\x1b\x00\ufeff") {
		t.Error("control characters in document")
	}
}

// bodyOf returns the markup between <body ...> and </main> of a document.
func bodyOf(t *testing.T, doc string) string {
	t.Helper()
	i := strings.Index(doc, "<body")
	j := strings.Index(doc, "</main>")
	if i < 0 || j < 0 {
		t.Fatalf("no body in %.200q", doc)
	}
	return doc[i : j+len("</main>")]
}

func TestHTMLGolden(t *testing.T) {
	d := Document{
		Title:     "Call a@host",
		Subtitle:  "capture.pcap",
		Generated: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		Blocks: []Block{
			Heading{Level: 2, Text: "Summary"},
			KeyValues{{Key: "Calls", Value: "3"}, {Key: "Failed", Value: "1", Style: Bad}},
			Paragraph{Text: "Two\nlines & <more>"},
			TableBlock{Table: Table{
				Title:   "Messages",
				Columns: []Column{{Name: "Method"}, {Name: "Code", Kind: Int, Style: func(v any) Style { return StatusStyle(v.(int)) }}, {Name: "At", Kind: Time}, {Name: "RTT", Kind: Duration}},
				Rows:    [][]any{{"INVITE", 200, testStart, 1500 * time.Millisecond}, {"BYE", 503, nil, nil}},
			}, Options: Options{UTC: true}},
			Pre{Text: "INVITE sip:bob@example.com SIP/2.0\r\nVia: SIP/2.0/UDP 10.0.0.1;branch=z9hG4bK1\r\n\r\n"},
			Details{Summary: "More", Blocks: []Block{Paragraph{Text: "inside"}}},
			Badges{{Text: "ok", Style: Good}, SeverityBadge("error")},
			SVG{Title: "Ladder", Markup: `<svg></svg>`},
			RawHTML{HTML: `<b>raw</b>`},
		},
	}
	var b bytes.Buffer
	if err := WriteHTML(&b, d); err != nil {
		t.Fatal(err)
	}
	const want = `<body class="sc-doc">
<header class="sc-header">
<h1 class="sc-title">Call a@host</h1>
<p class="sc-subtitle">capture.pcap</p>
<p class="sc-generated">Generated 2026-01-02T03:04:05Z</p>
</header>
<main class="sc-main">
<h2 class="sc-h sc-h2">Summary</h2>
<dl class="sc-kv">
<div class="sc-card"><dt class="sc-k">Calls</dt><dd class="sc-v">3</dd></div>
<div class="sc-card sc-bad"><dt class="sc-k">Failed</dt><dd class="sc-v">1</dd></div>
</dl>
<p class="sc-p">Two<br>lines &amp; &lt;more&gt;</p>
<div class="sc-tablebox" data-sc-table>
<div class="sc-tools"><input type="search" class="sc-filter" placeholder="Filter rows…" aria-label="Filter rows"><span class="sc-count"></span></div>
<div class="sc-scroll"><table class="sc-table">
<caption class="sc-caption">Messages</caption>
<thead><tr><th data-k="s">Method</th><th class="sc-num" data-k="n">Code</th><th data-k="n">At</th><th class="sc-num" data-k="n">RTT</th></tr></thead>
<tbody>
<tr><td>INVITE</td><td class="sc-num sc-good" data-v="200">200</td><td data-v="1767323045123">2026-01-02T03:04:05.123Z</td><td class="sc-num" data-v="1500">1.5s</td></tr>
<tr><td>BYE</td><td class="sc-num sc-bad" data-v="503">503</td><td></td><td class="sc-num"></td></tr>
</tbody>
</table>
</div>
</div>
<pre class="sc-pre">INVITE sip:bob@example.com SIP/2.0
Via: SIP/2.0/UDP 10.0.0.1;branch=z9hG4bK1

</pre>
<details class="sc-details"><summary class="sc-summary">More</summary>
<div class="sc-body">
<p class="sc-p">inside</p>
</div>
</details>
<p class="sc-badges"><span class="sc-badge sc-good">ok</span> <span class="sc-badge sc-bad">error</span></p>
<figure class="sc-fig"><div class="sc-scroll"><svg></svg></div><figcaption class="sc-figcap">Ladder</figcaption></figure>
<div class="sc-raw"><b>raw</b></div>
</main>`
	out := b.String()
	if got := bodyOf(t, out); got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
	if !strings.HasPrefix(out, "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">") ||
		!strings.Contains(out, "<title>Call a@host</title>") || !strings.HasSuffix(out, "</script>\n</body>\n</html>\n") {
		t.Errorf("document frame wrong: %.300q", out)
	}
	for _, need := range []string{"prefers-color-scheme:dark", "@media print"} {
		if !strings.Contains(out, need) {
			t.Errorf("missing %q", need)
		}
	}
}

func TestHTMLDeterministic(t *testing.T) {
	d := hostileDocument("x", "y")
	var a, b bytes.Buffer
	_ = WriteHTML(&a, d)
	_ = WriteHTML(&b, d)
	if a.String() != b.String() {
		t.Error("output differs between runs")
	}
	// No Generated: no timestamp paragraph (no time.Now).
	var c bytes.Buffer
	_ = WriteHTML(&c, Document{Title: "t"})
	if strings.Contains(c.String(), "Generated") {
		t.Error("timestamp without Generated")
	}
}

func TestHTMLNesting(t *testing.T) {
	var blk Block = Paragraph{Text: "x"}
	for range maxNesting + 5 {
		blk = Details{Summary: "s", Blocks: []Block{blk}}
	}
	if err := WriteHTML(&bytes.Buffer{}, Document{Blocks: []Block{blk}}); err == nil {
		t.Error("deep nesting accepted")
	}
	blk = Paragraph{Text: "x"}
	for range maxNesting {
		blk = Details{Summary: "s", Blocks: []Block{blk}}
	}
	var b bytes.Buffer
	if err := WriteHTML(&b, Document{Blocks: []Block{blk}}); err != nil {
		t.Errorf("max nesting rejected: %v", err)
	}
	assertSafeDocument(t, b.String())
}

func TestHTMLTableBlockRowLimits(t *testing.T) {
	// A ragged row inside a TableBlock must not panic; extra cells are cut off.
	tb := Table{Columns: []Column{{Name: "A"}}, Rows: [][]any{{"x", "extra", "more"}, {}}}
	var b bytes.Buffer
	if err := WriteHTML(&b, Document{Blocks: []Block{TableBlock{Table: tb}}}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "extra") {
		t.Error("extra cell leaked")
	}
}

func TestBadgeHTML(t *testing.T) {
	if got, want := BadgeHTML(Badge{Text: "<x>", Style: Warn}), `<span class="sc-badge sc-warn">&lt;x&gt;</span>`; got != want {
		t.Errorf("got %s want %s", got, want)
	}
	if got, want := BadgeHTML(Badge{Text: "a"}), `<span class="sc-badge">a</span>`; got != want {
		t.Errorf("got %s want %s", got, want)
	}
}
