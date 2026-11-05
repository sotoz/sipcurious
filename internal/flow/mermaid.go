package flow

import (
	"io"
	"strconv"
	"strings"

	"github.com/sotoz/sipcurious/internal/call"
)

// mermaidEscaper replaces the characters that would break Mermaid text with
// entity codes: ';' ends a statement, '#' starts an entity, '<' and '>' are
// markup and "%%" starts a comment that would cut the rest of the line.
var mermaidEscaper = strings.NewReplacer(
	"#", "#35;",
	"%", "#37;",
	";", "#59;",
	"<", "#lt;",
	">", "#gt;",
)

// mm escapes cleaned text for Mermaid.
func mm(s string) string { return mermaidEscaper.Replace(s) }

// WriteMermaid renders each call as a fenced Mermaid sequenceDiagram block.
// Participants get the safe ids P1, P2, ... and display their address, role
// and port. A note over all lifelines carries the header block. Requests are
// solid arrows, responses dashed; a final response >= 400 is wrapped in a red
// rect; RTP streams (o.Media) are open arrows. Calls without messages are
// skipped. Mermaid has no column for times, so each label ends in
// "(+offset)" (or the time of day with o.Absolute), followed by "[gap N]" for
// a pause above one second.
func WriteMermaid(w io.Writer, calls []call.Call, o Options) error {
	var b strings.Builder
	n := 0
	for _, c := range calls {
		if len(c.Messages) == 0 {
			continue
		}
		if n > 0 {
			b.WriteByte('\n')
		}
		n++
		writeMermaid(&b, newModel(c, o), o)
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func writeMermaid(b *strings.Builder, m *model, o Options) {
	id := func(k int) string { return "P" + strconv.Itoa(k+1) }
	over := func() string {
		if len(m.eps) > 1 {
			return id(0) + "," + id(len(m.eps)-1)
		}
		return id(0)
	}

	b.WriteString("```mermaid\nsequenceDiagram\n")
	for k, e := range m.eps {
		b.WriteString("    participant " + id(k) + " as " + mm(e.title()) + "\n")
	}
	b.WriteString("    Note over " + over() + ": " + joinEscaped(m.header, "<br/>") + "\n")
	for _, r := range m.rows {
		label := mm(r.label) + " (" + mm(r.when(o)) + ")"
		if r.gap > 0 {
			label += " [gap " + fmtDur(r.gap) + "]"
		}
		arrow := "->>"
		switch {
		case r.rtp:
			arrow = "-)"
		case r.response:
			arrow = "-->>"
		}
		if r.fail {
			b.WriteString("    rect rgba(229, 72, 77, 0.2)\n    ")
		}
		b.WriteString("    " + id(r.src) + arrow + id(r.dst) + ": " + label + "\n")
		if r.note != "" {
			b.WriteString("    ")
			if r.fail {
				b.WriteString("    ")
			}
			b.WriteString("Note over " + id(r.dst) + ": " + mm(r.note) + "\n")
		}
		if r.fail {
			b.WriteString("    end\n")
		}
	}
	if o.Media {
		lines := make([]string, 0, len(m.streams)+1)
		if len(m.streams) == 0 {
			lines = append(lines, m.none)
		}
		for _, s := range m.streams {
			lines = append(lines, "RTP "+s.leg+" "+s.codec+" "+s.packets+" pkts, loss "+s.loss+", jitter "+s.jitter+", MOS "+s.mos)
		}
		b.WriteString("    Note over " + over() + ": " + joinEscaped(lines, "<br/>") + "\n")
	}
	b.WriteString("```\n")
}

// joinEscaped escapes each line and joins them with sep, which is trusted
// markup and is not escaped.
func joinEscaped(lines []string, sep string) string {
	var b strings.Builder
	for i, l := range lines {
		if i > 0 {
			b.WriteString(sep)
		}
		b.WriteString(mm(l))
	}
	return b.String()
}
