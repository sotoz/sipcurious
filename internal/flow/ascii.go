package flow

import (
	"io"
	"strings"
	"unicode/utf8"

	"github.com/sotoz/sipcurious/internal/call"
)

const (
	gutter     = 2  // columns left of the first lifeline: failure marker
	minLaneGap = 18 // narrowest distance between adjacent lifelines
	selfOffset = 6  // column, relative to the lifeline, where a self-addressed label starts
)

// WriteASCII renders one ASCII ladder diagram per call to w: a header block,
// the diagram (participants, one arrow per message with its time), and with
// o.Media the table of correlated RTP streams. Calls are separated by a blank
// line; calls without messages only get their header.
//
// Conventions: "-->" request, "<--" response, "==>" a final response >= 400
// (marked "!" in the left margin), "~~>" an RTP stream; a pause above one
// second shows as "(gap N.NNNs)" after the time; a repeated message ends in
// "(retrans)". An arrow between non-adjacent lifelines is drawn over the
// lifelines in between. Widths are counted in terminal cells with East Asian
// wide characters taking two.
func WriteASCII(w io.Writer, calls []call.Call, o Options) error {
	var b strings.Builder
	for i, c := range calls {
		if i > 0 {
			b.WriteByte('\n')
		}
		writeASCII(&b, newModel(c, o), o)
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// grid is a fixed-width row of terminal cells. A cell of -1 is the second half
// of a wide rune and prints nothing.
type grid []rune

func newGrid(n int) grid {
	g := make(grid, n)
	for i := range g {
		g[i] = ' '
	}
	return g
}

// put writes s starting at cell c, clipping at both ends.
func (g grid) put(c int, s string) {
	for _, r := range s {
		w := runeWidth(r)
		if c >= 0 && c+w <= len(g) {
			g[c] = r
			if w == 2 {
				g[c+1] = -1
			}
		}
		c += w
	}
}

func (g grid) String() string {
	var sb strings.Builder
	sb.Grow(len(g))
	for _, r := range g {
		if r >= 0 {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

func writeASCII(b *strings.Builder, m *model, o Options) {
	for _, h := range m.header {
		b.WriteString(h)
		b.WriteByte('\n')
	}
	if len(m.rows) > 0 {
		b.WriteByte('\n')
		writeLadder(b, m, o)
	}
	if o.Media {
		writeFooter(b, m)
	}
}

func writeLadder(b *strings.Builder, m *model, o Options) {
	n := len(m.eps)
	hw := make([]int, n)
	hasRole := false
	for i, e := range m.eps {
		hw[i] = width(e.label)
		if e.role != "" {
			hasRole = true
			hw[i] = max(hw[i], width(e.role)+2)
		}
	}

	minGap := make([]int, max(n-1, 0))
	for k := range minGap {
		minGap[k] = max(minLaneGap, (hw[k]+1)/2+hw[k+1]/2+2)
	}
	spans := make([]span, 0, len(m.rows))
	for _, r := range m.rows {
		lw := max(width(r.label), noteWidth(r.note)) // note counts too
		if r.src == r.dst {
			if r.src < n-1 {
				spans = append(spans, span{r.src, r.src + 1, selfOffset + lw + 1})
			}
			continue
		}
		a, z := min(r.src, r.dst), max(r.src, r.dst)
		spans = append(spans, span{a, z, lw + 6})
	}
	gaps := solveGaps(minGap, spans)
	lanes := make([]int, n)
	lanes[0] = gutter + (hw[0]+1)/2
	for k := 1; k < n; k++ {
		lanes[k] = lanes[k-1] + gaps[k-1]
	}

	w := lanes[n-1] + hw[n-1]/2 + 1
	for _, r := range m.rows {
		if r.src == r.dst {
			w = max(w, lanes[r.src]+selfOffset+max(width(r.label), noteWidth(r.note))+1)
		}
	}

	newRow := func() grid {
		g := newGrid(w)
		for _, l := range lanes {
			g[l] = '|'
		}
		return g
	}
	emit := func(g grid, suffix string) {
		s := g.String()
		if suffix != "" {
			s += "  " + suffix
		}
		b.WriteString(strings.TrimRight(s, " "))
		b.WriteByte('\n')
	}

	head := newGrid(w)
	for k, e := range m.eps {
		head.put(lanes[k]-width(e.label)/2, e.label)
	}
	emit(head, "")
	if hasRole {
		head = newGrid(w)
		for k, e := range m.eps {
			if e.role != "" {
				head.put(lanes[k]-(width(e.role)+2)/2, "("+e.role+")")
			}
		}
		emit(head, "")
	}
	emit(newRow(), "")

	for _, r := range m.rows {
		g := newRow()
		mark := " "
		if r.fail {
			mark = "!"
		}
		suffix := r.when(o)
		if r.gap > 0 {
			suffix += "  (gap " + fmtDur(r.gap) + ")"
		}
		if r.src == r.dst {
			c := lanes[r.src]
			head, tail := "|--+", "|<-+"
			if r.fail {
				head, tail = "|==+", "|<=+"
			}
			g.put(c, head)
			g.put(c+selfOffset, r.label)
			g.put(0, mark)
			emit(g, suffix)
			g = newRow()
			g.put(c, tail)
			if r.note != "" {
				g.put(c+selfOffset, "["+r.note+"]")
			}
			emit(g, "")
			continue
		}
		a, z := lanes[r.src], lanes[r.dst]
		if a > z {
			a, z = z, a
		}
		fill := "-"
		switch {
		case r.rtp:
			fill = "~"
		case r.fail:
			fill = "="
		}
		inner := z - a - 1
		body := " " + r.label + " "
		rest := inner - width(body) - 1 // minus the arrow head
		l := rest / 2
		fillL, fillR := strings.Repeat(fill, l), strings.Repeat(fill, rest-l)
		var arrow string
		if r.src < r.dst {
			arrow = fillL + body + fillR + ">"
		} else {
			arrow = "<" + fillL + body + fillR
		}
		g.put(a+1, arrow)
		g.put(0, mark)
		emit(g, suffix)
		if r.note != "" {
			g = newRow()
			note := "[" + r.note + "]"
			// Lifelines inside the span are overwritten, as for arrows.
			for k := a + 1; k < z; k++ {
				g[k] = ' '
			}
			g.put(a+1+(inner-width(note))/2, note)
			emit(g, "")
		}
	}
	emit(newRow(), "")
}

// noteWidth is the width of a note including its brackets, 0 if empty.
func noteWidth(n string) int {
	if n == "" {
		return 0
	}
	return width(n) + 2
}

// writeFooter appends the RTP stream table.
func writeFooter(b *strings.Builder, m *model) {
	b.WriteByte('\n')
	if len(m.streams) == 0 {
		b.WriteString(m.none)
		b.WriteByte('\n')
		return
	}
	b.WriteString("RTP streams:\n")
	head := []string{"Direction", "Codec", "Packets", "Loss", "Jitter", "MOS", "Flow"}
	rows := make([][]string, len(m.streams))
	widths := make([]int, len(head))
	for i, h := range head {
		widths[i] = utf8.RuneCountInString(h)
	}
	for i, s := range m.streams {
		rows[i] = []string{s.leg, s.codec, s.packets, s.loss, s.jitter, s.mos, s.flow}
		for k, c := range rows[i] {
			widths[k] = max(widths[k], width(c))
		}
	}
	line := func(cells []string) {
		var sb strings.Builder
		for k, c := range cells {
			if k > 0 {
				sb.WriteString("  ")
			}
			sb.WriteString(c)
			if k < len(cells)-1 {
				sb.WriteString(strings.Repeat(" ", widths[k]-width(c)))
			}
		}
		b.WriteString("  ")
		b.WriteString(strings.TrimRight(sb.String(), " "))
		b.WriteByte('\n')
	}
	line(head)
	for _, r := range rows {
		line(r)
	}
}
