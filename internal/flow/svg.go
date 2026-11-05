package flow

import (
	"strconv"
	"strings"

	"github.com/sotoz/sipcurious/internal/call"
	"github.com/sotoz/sipcurious/internal/report"
)

// SVG geometry in pixels. Text is monospace 12px, estimated at 7.5px per cell.
const (
	svgPad         = 12
	svgRow         = 32
	svgNoteExtra   = 14
	svgLineH       = 16
	svgMinLane     = 200
	svgHead        = 40 // participant box height
	svgMinWidth    = 480
	maxHeaderCells = 110 // header lines wider than this are ellipsised
)

// cw is the pixel width of n terminal cells.
func cw(n int) int { return (n*15 + 1) / 2 }

// svgCSS uses fixed mid-tone semantic colours that keep their contrast on
// light and dark backgrounds; ordinary text inherits the surrounding colour.
const svgCSS = `.fl{font:12px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}` +
	`.fl text{fill:currentColor}` +
	`.fl .fl-life{stroke:#8b93a1;stroke-width:1;stroke-dasharray:4 4}` +
	`.fl .fl-box{fill:none;stroke:#8b93a1;stroke-width:1.5}` +
	`.fl .fl-role{font-size:11px;opacity:.7}` +
	`.fl .fl-axis{stroke:#8b93a1;stroke-width:1;opacity:.5}` +
	`.fl .fl-req{stroke:#3b82f6;stroke-width:1.5;fill:none}` +
	`.fl .fl-res{stroke:#2da44e;stroke-width:1.5;fill:none;stroke-dasharray:6 3}` +
	`.fl .fl-fail{stroke:#e5484d;stroke-width:2;fill:none;stroke-dasharray:6 3}` +
	`.fl .fl-rtp{stroke:#8e66d9;stroke-width:3;fill:none}` +
	`.fl .fl-ah-req{fill:#3b82f6}.fl .fl-ah-res{fill:#2da44e}.fl .fl-ah-fail{fill:#e5484d}.fl .fl-ah-rtp{fill:#8e66d9}` +
	`.fl .fl-failbg{fill:#e5484d;opacity:.14}` +
	`.fl .fl-failtx{fill:#e5484d;font-weight:bold}` +
	`.fl .fl-retx{opacity:.65;font-style:italic}` +
	`.fl .fl-gap{fill:#d29922;font-weight:bold}` +
	`.fl .fl-note{font-size:11px;opacity:.75}` +
	`.fl .fl-time{font-size:11px;opacity:.8}` +
	`.fl .fl-h{font-weight:bold}`

// SVG renders c as a self-contained <svg> element for embedding in HTML
// reports (report.SVG): no scripts, foreignObject, external references or
// event attributes; all captured text is sanitised and XML-escaped. The width
// grows with the number of participants and the label lengths; the height
// with the number of messages. Request arrows are blue and solid, responses
// green and dashed, final responses >= 400 red on a tinted band, retransmitted
// messages faded and pauses above one second amber; time labels run down the
// left axis. The Call-ID and other long header values are ellipsised with the
// full text in a <title> tooltip. The error is always nil; it is reserved for
// future size limits.
func SVG(c call.Call, o Options) (string, error) {
	m := newModel(c, o)
	n := len(m.eps)

	// Time column.
	timeW := 0
	for _, r := range m.rows {
		timeW = max(timeW, cw(width(r.when(o))))
	}
	timeW += svgPad + 8
	if len(m.rows) == 0 {
		timeW = 0
	}

	// Lane geometry: gaps in pixels.
	hw := make([]int, n)
	for i, e := range m.eps {
		hw[i] = cw(max(width(e.label), width(e.role)+2)) + 24
	}
	minGap := make([]int, max(n-1, 0))
	for k := range minGap {
		minGap[k] = max(svgMinLane, (hw[k]+hw[k+1])/2+8)
	}
	spans := make([]span, 0, len(m.rows))
	for _, r := range m.rows {
		lw := cw(max(width(r.label), noteWidth(r.note))) + 28
		if r.src == r.dst {
			if r.src < n-1 {
				spans = append(spans, span{r.src, r.src + 1, 40 + lw})
			}
			continue
		}
		spans = append(spans, span{min(r.src, r.dst), max(r.src, r.dst), lw})
	}
	gaps := solveGaps(minGap, spans)
	lanes := make([]int, n)
	if n > 0 {
		lanes[0] = svgPad + timeW + hw[0]/2
		for k := 1; k < n; k++ {
			lanes[k] = lanes[k-1] + gaps[k-1]
		}
	}
	totalW := svgMinWidth
	if n > 0 {
		totalW = max(totalW, lanes[n-1]+hw[n-1]/2+svgPad)
		for _, r := range m.rows {
			if r.src == r.dst {
				totalW = max(totalW, lanes[r.src]+40+cw(max(width(r.label), noteWidth(r.note)))+svgPad)
			}
		}
	}
	headerW := 0
	for _, h := range m.header {
		headerW = max(headerW, cw(min(width(h), maxHeaderCells)))
	}
	totalW = max(totalW, headerW+2*svgPad)
	maxCells := (totalW - 2*svgPad) * 2 / 15

	// Vertical layout.
	var body strings.Builder
	y := svgPad
	for _, h := range m.header {
		short := report.Truncate(h, maxCells)
		body.WriteString(`<text x="` + itoa(svgPad) + `" y="` + itoa(y+12) + `"`)
		if short != h {
			body.WriteString(`>` + `<title>` + esc(h) + `</title>` + esc(short) + `</text>`)
		} else {
			body.WriteString(`>` + esc(h) + `</text>`)
		}
		body.WriteByte('\n')
		y += svgLineH
	}
	y += 8
	headTop := y
	laneTop := headTop + svgHead
	y = laneTop + 8

	type placed struct {
		r      row
		y      int // top of the row band
		height int
	}
	rows := make([]placed, len(m.rows))
	for i, r := range m.rows {
		h := svgRow
		if r.note != "" {
			h += svgNoteExtra
		}
		rows[i] = placed{r, y, h}
		y += h
	}
	laneBottom := y + 4
	y = laneBottom

	var rowsB strings.Builder
	for _, p := range rows {
		writeSVGRow(&rowsB, p.r, p.y, p.height, lanes, timeW, o)
	}

	var foot strings.Builder
	if o.Media {
		y += 12
		if len(m.streams) == 0 {
			foot.WriteString(`<text x="` + itoa(svgPad) + `" y="` + itoa(y+12) + `">` + esc(m.none) + "</text>\n")
			y += svgLineH
		} else {
			y = writeSVGTable(&foot, m, y, totalW)
		}
	}
	totalH := y + svgPad

	var b strings.Builder
	b.Grow(1024 + len(body.String()) + len(rowsB.String()) + len(foot.String()) + n*400)
	b.WriteString(`<svg xmlns="http://www.w3.org/2000/svg" class="fl" role="img" width="` + itoa(totalW) + `" height="` + itoa(totalH) +
		`" viewBox="0 0 ` + itoa(totalW) + ` ` + itoa(totalH) + `" aria-label="` + esc("SIP call flow "+text(c.CallID, 64)) + `">` + "\n")
	b.WriteString("<title>" + esc("SIP call flow "+text(c.CallID, 120)) + "</title>\n")
	b.WriteString("<style>" + svgCSS + "</style>\n")
	b.WriteString("<defs>")
	for _, k := range []string{"req", "res", "fail", "rtp"} {
		b.WriteString(`<marker id="fl-ah-` + k + `" viewBox="0 0 10 10" refX="9" refY="5" markerUnits="userSpaceOnUse" markerWidth="10" markerHeight="10" orient="auto">` +
			`<path class="fl-ah-` + k + `" d="M0,0 L10,5 L0,10 z"/></marker>`)
	}
	b.WriteString("</defs>\n")
	b.WriteString(body.String())
	for k, e := range m.eps {
		x := lanes[k]
		bw := hw[k]
		b.WriteString(`<line class="fl-life" x1="` + itoa(x) + `" y1="` + itoa(laneTop) + `" x2="` + itoa(x) + `" y2="` + itoa(laneBottom) + `"/>` + "\n")
		b.WriteString(`<rect class="fl-box" x="` + itoa(x-bw/2) + `" y="` + itoa(headTop) + `" width="` + itoa(bw) + `" height="` + itoa(svgHead) + `" rx="4"/>`)
		b.WriteString(`<text class="fl-h" x="` + itoa(x) + `" y="` + itoa(headTop+17) + `" text-anchor="middle">` + esc(e.label) + `</text>`)
		if e.role != "" {
			b.WriteString(`<text class="fl-role" x="` + itoa(x) + `" y="` + itoa(headTop+32) + `" text-anchor="middle">` + esc(e.role) + `</text>`)
		}
		b.WriteByte('\n')
	}
	if len(rows) > 0 {
		ax := svgPad + timeW - 6
		b.WriteString(`<line class="fl-axis" x1="` + itoa(ax) + `" y1="` + itoa(laneTop) + `" x2="` + itoa(ax) + `" y2="` + itoa(laneBottom) + `"/>` + "\n")
	}
	b.WriteString(rowsB.String())
	b.WriteString(foot.String())
	b.WriteString("</svg>\n")
	return b.String(), nil
}

// writeSVGRow draws one arrow row in the band [top, top+height).
func writeSVGRow(b *strings.Builder, r row, top, height int, lanes []int, timeW int, o Options) {
	cls, head := "req", "req"
	switch {
	case r.rtp:
		cls, head = "rtp", "rtp"
	case r.fail:
		cls, head = "fail", "fail"
	case r.response:
		cls, head = "res", "res"
	}
	lineY := top + 24
	b.WriteString("<g")
	if r.retrans {
		b.WriteString(` opacity=".6"`)
	}
	b.WriteString(">")
	if r.fail {
		b.WriteString(`<rect class="fl-failbg" x="0" y="` + itoa(top) + `" width="100%" height="` + itoa(height) + `"/>`)
	}
	// Time axis.
	b.WriteString(`<text class="fl-time" x="` + itoa(svgPad) + `" y="` + itoa(top+16) + `">` + esc(r.when(o)) + `</text>`)
	if r.gap > 0 {
		b.WriteString(`<text class="fl-gap fl-time" x="` + itoa(svgPad) + `" y="` + itoa(top+28) + `">` + esc("gap "+fmtDur(r.gap)) + `</text>`)
	}
	tcls := ""
	switch {
	case r.fail:
		tcls = ` class="fl-failtx"`
	case r.retrans:
		tcls = ` class="fl-retx"`
	}
	if r.src == r.dst {
		x := lanes[r.src]
		b.WriteString(`<path class="fl-` + cls + `" marker-end="url(#fl-ah-` + head + `)" d="M` + itoa(x) + `,` + itoa(lineY-8) +
			` h28 v16 h-26"/>`)
		b.WriteString(`<text` + tcls + ` x="` + itoa(x+36) + `" y="` + itoa(lineY+4) + `">` + esc(r.label) + `</text>`)
		if r.note != "" {
			b.WriteString(`<text class="fl-note" x="` + itoa(x+36) + `" y="` + itoa(lineY+4+svgNoteExtra) + `">` + esc(r.note) + `</text>`)
		}
	} else {
		x1, x2 := lanes[r.src], lanes[r.dst]
		pad := 2
		if x1 < x2 {
			x1 += pad
			x2 -= pad
		} else {
			x1 -= pad
			x2 += pad
		}
		b.WriteString(`<line class="fl-` + cls + `" marker-end="url(#fl-ah-` + head + `)" x1="` + itoa(x1) + `" y1="` + itoa(lineY) + `" x2="` + itoa(x2) + `" y2="` + itoa(lineY) + `"/>`)
		mid := (x1 + x2) / 2
		b.WriteString(`<text` + tcls + ` x="` + itoa(mid) + `" y="` + itoa(lineY-5) + `" text-anchor="middle">` + esc(r.label) + `</text>`)
		if r.note != "" {
			b.WriteString(`<text class="fl-note" x="` + itoa(mid) + `" y="` + itoa(lineY+svgNoteExtra) + `" text-anchor="middle">` + esc(r.note) + `</text>`)
		}
	}
	b.WriteString("</g>\n")
}

// writeSVGTable draws the RTP stream table starting at y and returns the y
// below it.
func writeSVGTable(b *strings.Builder, m *model, y, totalW int) int {
	head := []string{"Direction", "Codec", "Packets", "Loss", "Jitter", "MOS", "Flow"}
	cells := make([][]string, len(m.streams))
	widths := make([]int, len(head))
	for i, h := range head {
		widths[i] = len(h)
	}
	for i, s := range m.streams {
		cells[i] = []string{s.leg, s.codec, s.packets, s.loss, s.jitter, s.mos, s.flow}
		for k, c := range cells[i] {
			widths[k] = max(widths[k], width(c))
		}
	}
	b.WriteString(`<text class="fl-h" x="` + itoa(svgPad) + `" y="` + itoa(y+12) + `">RTP streams</text>` + "\n")
	y += svgLineH + 4
	line := func(row []string, cls string) {
		x := svgPad
		for k, c := range row {
			b.WriteString(`<text` + cls + ` x="` + itoa(x) + `" y="` + itoa(y+12) + `">` + esc(c) + `</text>`)
			x += cw(widths[k] + 2)
		}
		b.WriteByte('\n')
		y += svgLineH
	}
	line(head, ` class="fl-h"`)
	for _, r := range cells {
		line(r, "")
	}
	return y
}

func itoa(n int) string { return strconv.Itoa(n) }

// escaper makes text safe for XML element content and attribute values.
var escaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;")

// esc escapes already cleaned text for SVG.
func esc(s string) string { return escaper.Replace(s) }
