package cli

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"html"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/sotoz/sipcurious/internal/analysis"
	"github.com/sotoz/sipcurious/internal/call"
	"github.com/sotoz/sipcurious/internal/engine"
	"github.com/sotoz/sipcurious/internal/flow"
	"github.com/sotoz/sipcurious/internal/report"
	"github.com/sotoz/sipcurious/internal/stats"
)

// maxRawMessages bounds the raw SIP shown for one call.
const maxRawMessages = 300

type reportOpts struct {
	title     string
	generated string
	maxCalls  int
	thresholds
}

func init() {
	Register(NewCommand(Command{
		Name:    "report",
		Group:   "Share",
		Summary: "write one self-contained troubleshooting report (HTML or Markdown): summary, findings, calls with ladders",
		Usage:   "report [flags] -o REPORT.html CAPTURE...",
		Formats: []string{"html", "markdown"},
	}, func(fs *flag.FlagSet, o *reportOpts) {
		fs.StringVar(&o.title, "title", "SIP troubleshooting report", "report `TITLE`")
		fs.StringVar(&o.generated, "generated", "", "generation time `RFC3339` shown in the report (default: $SIPCURIOUS_NOW, else now)")
		fs.IntVar(&o.maxCalls, "max-calls", 200, "describe at most `N` calls in detail; the rest is summarised (0 = no calls)")
		o.bindSIP(fs)
		o.bindMedia(fs)
	}, runReport))
}

func runReport(ctx context.Context, env *Env, c *Common, o *reportOpts) int {
	if o.maxCalls < 0 {
		return env.Fail(Usagef("--max-calls must not be negative"))
	}
	cfg, err := o.config()
	if err != nil {
		return env.Fail(err)
	}
	generated, err := o.generatedAt()
	if err != nil {
		return env.Fail(err)
	}
	q, err := c.Query()
	if err != nil {
		return env.Fail(err)
	}
	ds, err := c.Open(ctx, env)
	if err != nil {
		return env.Fail(err)
	}
	fs, err := analysis.Run(ds.AnalysisInput(cfg), analysis.RunOptions{})
	if err != nil {
		return env.Fail(err)
	}
	sel, err := selectCalls(ctx, ds, q)
	if err != nil {
		return env.Fail(err)
	}
	in := ds.StatsInput()
	if q != nil {
		fs = filterFindings(fs, ds, q, false)
		in = restrict(in, sel)
	}
	r := &reportData{
		ds: ds, c: c, o: o, cfg: cfg, generated: generated,
		findings: fs, summary: stats.Compute(in), calls: orderCalls(sel, fs), total: len(sel),
	}
	c.Infof(env, "report: %s, %s", plural(len(sel), "call"), analysis.Summary(fs))
	err = c.WriteWith(env, func(w io.Writer, f report.Format, opt report.Options) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		opt.UTC = true // a report is shared between people in different zones
		if f == report.FormatMarkdown {
			return r.markdown(w, opt)
		}
		return report.WriteHTML(w, r.document(opt))
	})
	return env.Fail(err)
}

// generatedAt resolves the "Generated" time: --generated, $SIPCURIOUS_NOW or
// the clock. It is the only place where the clock is read.
func (o *reportOpts) generatedAt() (time.Time, error) {
	src, name := o.generated, "--generated"
	if src == "" {
		src, name = os.Getenv("SIPCURIOUS_NOW"), "$SIPCURIOUS_NOW"
	}
	if src == "" {
		return time.Now(), nil
	}
	t, err := time.Parse(time.RFC3339, src)
	if err != nil {
		return time.Time{}, Usagef("%s: %q is not an RFC 3339 time (2026-03-04T10:00:00Z)", name, src)
	}
	return t, nil
}

type reportData struct {
	ds        *engine.Dataset
	c         *Common
	o         *reportOpts
	cfg       analysis.Config
	generated time.Time
	findings  []analysis.Finding
	summary   stats.Summary
	calls     []*call.Call // worst first, see orderCalls
	total     int
}

// orderCalls puts failed calls first, then calls with an error or warning
// finding, then the others; each group keeps capture order.
func orderCalls(sel []*call.Call, fs []analysis.Finding) []*call.Call {
	worst := map[string]analysis.Severity{}
	for _, f := range fs {
		if f.CallID != "" {
			if s, ok := worst[f.CallID]; !ok || f.Severity > s {
				worst[f.CallID] = f.Severity
			}
		}
	}
	rank := func(c *call.Call) int {
		switch s, has := worst[c.CallID]; {
		case c.State == call.StateFailed || c.State == call.StateNoResponse:
			return 0
		case has && s >= analysis.Warning:
			return 1
		}
		return 2
	}
	out := append([]*call.Call(nil), sel...)
	sort.SliceStable(out, func(i, j int) bool { return rank(out[i]) < rank(out[j]) })
	return out
}

// shown are the calls described in detail.
func (r *reportData) shown() []*call.Call {
	return r.calls[:min(len(r.calls), r.o.maxCalls)]
}

func (r *reportData) subtitle() string {
	s := r.summary
	parts := []string{plural(len(r.ds.Files), "file")}
	if !s.Start.IsZero() {
		parts = append(parts, report.FormatTime(s.Start, true)+" to "+report.FormatTime(s.End, true)+" (UTC)")
	}
	return strings.Join(parts, ", ") + ": " + strings.Join(r.ds.Files, ", ")
}

func (r *reportData) findingsOf(id string) []analysis.Finding {
	var out []analysis.Finding
	for _, f := range r.findings {
		if f.CallID == id {
			out = append(out, f)
		}
	}
	return out
}

func (r *reportData) streamsOf(c *call.Call) report.Table {
	t := StreamTable(c.Streams, r.cfg)
	t.Title = "RTP streams"
	return t
}

func callSummary(c *call.Call) string {
	s := fmt.Sprintf("%s: %s -> %s, %s", c.CallID, nonEmpty(c.FromUser, c.From), nonEmpty(c.ToUser, c.To), c.State)
	if c.Result != "" {
		s += " " + c.Result
	}
	return s
}

func callFacts(c *call.Call, utc bool) report.KeyValues {
	kv := report.KeyValues{
		{Key: "State", Value: string(c.State), Style: stateStyle(string(c.State))},
		{Key: "Start", Value: report.FormatTime(c.Start, utc)},
		{Key: "Duration", Value: report.FormatDuration(c.Duration())},
	}
	add := func(k, v string, st report.Style) {
		if v != "" {
			kv = append(kv, report.KeyValue{Key: k, Value: v, Style: st})
		}
	}
	dur := func(d time.Duration) string {
		if d == 0 {
			return ""
		}
		return report.FormatDuration(d)
	}
	add("Result", c.Result, report.None)
	add("PDD", dur(c.PDD), report.None)
	add("Setup", dur(c.SetupTime), report.None)
	add("Talk", dur(c.TalkTime), report.None)
	add("Codec", callCodec(c), report.None)
	if m := worstMOS(c); m > 0 {
		add("MOS", fmt.Sprintf("%.2f", m), mosStyle(m))
	}
	add("Ended by", c.EndedBy, report.None)
	add("Retransmissions", nonZero(c.Retransmissions), report.None)
	add("Endpoints", joinAddrPorts(c.Endpoints), report.None)
	add("User agents", strings.Join(c.UserAgents, "; "), report.None)
	return kv
}

func nonZero(n int) string {
	if n == 0 {
		return ""
	}
	return fmt.Sprint(n)
}

// rawSIP is the text of the call's messages, each after a one line header.
func rawSIP(c *call.Call, utc bool) string {
	var b strings.Builder
	msgs := c.Messages
	for i, m := range msgs {
		if i == maxRawMessages {
			fmt.Fprintf(&b, "... %d more messages not shown\n", len(msgs)-i)
			break
		}
		if i > 0 {
			b.WriteByte('\n')
		}
		fmt.Fprintf(&b, "#%d %s %s %s -> %s\n", m.Index, m.File, report.FormatTime(m.Time, utc),
			endpoint(m.Src, m.SrcPort), endpoint(m.Dst, m.DstPort))
		b.WriteString(strings.TrimRight(strings.ReplaceAll(m.Raw, "\r\n", "\n"), "\n"))
		b.WriteByte('\n')
	}
	return b.String()
}

func (r *reportData) document(opt report.Options) report.Document {
	opt.Color = false
	counts := analysis.Summary(r.findings)
	doc := report.Document{Title: r.o.title, Subtitle: r.subtitle(), Generated: r.generated}
	doc.Blocks = append(doc.Blocks, report.Heading{Level: 2, Text: "Summary"}, r.summary.KeyValues(),
		report.Badges{
			{Text: plural(counts.Errors, "error"), Style: styleIf(counts.Errors > 0, report.Bad)},
			{Text: plural(counts.Warnings, "warning"), Style: styleIf(counts.Warnings > 0, report.Warn)},
			{Text: fmt.Sprintf("%d info", counts.Infos), Style: report.Dim},
		})

	doc.Blocks = append(doc.Blocks, report.Heading{Level: 2, Text: "Findings"})
	if len(r.findings) == 0 {
		doc.Blocks = append(doc.Blocks, report.Paragraph{Text: "No findings: the diagnostic rules found nothing to report."})
	} else {
		doc.Blocks = append(doc.Blocks, report.TableBlock{Table: analysis.Table(r.findings), Options: withExtra(opt)})
	}

	doc.Blocks = append(doc.Blocks, report.Heading{Level: 2, Text: "Calls"})
	shown := r.shown()
	if len(shown) > 0 {
		doc.Blocks = append(doc.Blocks, report.TableBlock{Table: CallTable(shown), Options: opt})
	}
	if note := r.omitted(); note != "" {
		doc.Blocks = append(doc.Blocks, report.Paragraph{Text: note})
	}

	if len(shown) > 0 {
		doc.Blocks = append(doc.Blocks, report.Heading{Level: 2, Text: "Call details"})
	}
	fo := flow.Options{UTC: opt.UTC, SDP: true, Media: !r.c.NoRTP}
	for _, cl := range shown {
		d := report.Details{Summary: callSummary(cl)}
		d.Blocks = append(d.Blocks, callFacts(cl, opt.UTC))
		if svg, err := flow.SVG(*cl, fo); err == nil {
			d.Blocks = append(d.Blocks, report.SVG{Title: "Call flow", Markup: svg})
		}
		if fs := r.findingsOf(cl.CallID); len(fs) > 0 {
			d.Blocks = append(d.Blocks, report.TableBlock{Table: analysis.Table(fs), Options: withExtra(opt)})
		}
		if len(cl.Streams) > 0 {
			d.Blocks = append(d.Blocks, report.TableBlock{Table: r.streamsOf(cl), Options: opt})
		}
		d.Blocks = append(d.Blocks, report.Details{
			Summary: plural(len(cl.Messages), "SIP message") + " (raw)",
			Blocks:  []report.Block{report.Pre{Text: rawSIP(cl, opt.UTC)}},
		})
		doc.Blocks = append(doc.Blocks, d)
	}

	var secs []report.Block
	for _, s := range r.summary.Sections(opt) {
		name := nonEmpty(s.Name, s.Table.Title)
		secs = append(secs, report.Heading{Level: 3, Text: name}, report.TableBlock{Table: s.Table, Options: opt})
	}
	doc.Blocks = append(doc.Blocks, report.Heading{Level: 2, Text: "Statistics"},
		report.Details{Summary: "Full statistics", Blocks: secs})
	return doc
}

func noTitle(t report.Table) report.Table { t.Title = ""; return t }

func withExtra(o report.Options) report.Options { o.Extra = true; return o }

func styleIf(cond bool, s report.Style) report.Style {
	if cond {
		return s
	}
	return report.None
}

// omitted describes the calls beyond --max-calls by state.
func (r *reportData) omitted() string {
	rest := r.calls[len(r.shown()):]
	if len(rest) == 0 {
		return ""
	}
	byState := map[call.State]int{}
	for _, c := range rest {
		byState[c.State]++
	}
	var parts []string
	for st, n := range byState {
		parts = append(parts, fmt.Sprintf("%d %s", n, st))
	}
	sort.Strings(parts)
	return fmt.Sprintf("%s not shown (--max-calls %d): %s. Narrow the report with --where, or use 'sipcurious calls'.",
		plural(len(rest), "more call"), r.o.maxCalls, strings.Join(parts, ", "))
}

// fence returns a code fence longer than any run of backticks in text.
func fence(text string) string {
	longest, run := 2, 0
	for _, ch := range text {
		if ch == '`' {
			run++
			longest = max(longest, run)
		} else {
			run = 0
		}
	}
	return strings.Repeat("`", longest+1)
}

func codeBlock(w *bytes.Buffer, text string) {
	text = clean2(text)
	f := fence(text)
	fmt.Fprintf(w, "%stext\n%s\n%s\n\n", f, strings.TrimRight(text, "\n"), f)
}

// clean2 neutralises control characters except line breaks and tabs.
func clean2(s string) string {
	return strings.Map(func(r rune) rune {
		if (r < 0x20 && r != '\n' && r != '\t') || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return '\uFFFD'
		}
		return r
	}, strings.ToValidUTF8(strings.ReplaceAll(s, "\r\n", "\n"), "\uFFFD"))
}

func (r *reportData) markdown(w io.Writer, opt report.Options) error {
	opt.Color = false
	var b bytes.Buffer
	counts := analysis.Summary(r.findings)
	fmt.Fprintf(&b, "# %s\n\n%s\n\nGenerated %s\n\n", mdText(r.o.title), mdText(r.subtitle()), r.generated.UTC().Format(time.RFC3339))

	b.WriteString("## Summary\n\n")
	for _, kv := range r.summary.KeyValues() {
		fmt.Fprintf(&b, "- **%s**: %s\n", mdText(kv.Key), mdText(kv.Value))
	}
	fmt.Fprintf(&b, "\nFindings: %s.\n\n## Findings\n\n", counts)
	if len(r.findings) == 0 {
		b.WriteString("No findings.\n\n")
	} else if err := report.Write(&b, report.FormatMarkdown, noTitle(analysis.Table(r.findings)), opt); err != nil {
		return err
	} else {
		b.WriteByte('\n')
	}

	b.WriteString("## Calls\n\n")
	shown := r.shown()
	if len(shown) > 0 {
		if err := report.Write(&b, report.FormatMarkdown, noTitle(CallTable(shown)), opt); err != nil {
			return err
		}
		b.WriteByte('\n')
	}
	if note := r.omitted(); note != "" {
		b.WriteString(mdText(note) + "\n\n")
	}
	fo := flow.Options{UTC: opt.UTC, SDP: true, Media: !r.c.NoRTP}
	for _, cl := range shown {
		fmt.Fprintf(&b, "### %s\n\n", mdText(callSummary(cl)))
		for _, kv := range callFacts(cl, opt.UTC) {
			fmt.Fprintf(&b, "- **%s**: %s\n", mdText(kv.Key), mdText(kv.Value))
		}
		b.WriteByte('\n')
		var ladder bytes.Buffer
		if err := flow.WriteASCII(&ladder, []call.Call{*cl}, fo); err != nil {
			return err
		}
		codeBlock(&b, ladder.String())
		if fs := r.findingsOf(cl.CallID); len(fs) > 0 {
			b.WriteString("**Findings**\n\n")
			for _, f := range fs {
				fmt.Fprintf(&b, "- **%s** `%s`: %s\n", f.Severity, f.Rule, mdText(f.Title))
				if f.Detail != "" {
					fmt.Fprintf(&b, "  - %s\n", mdText(f.Detail))
				}
				if f.Hint != "" {
					fmt.Fprintf(&b, "  - Hint: %s\n", mdText(f.Hint))
				}
			}
			b.WriteByte('\n')
		}
		if len(cl.Streams) > 0 {
			if err := report.Write(&b, report.FormatMarkdown, noTitle(r.streamsOf(cl)), opt); err != nil {
				return err
			}
			b.WriteByte('\n')
		}
		fmt.Fprintf(&b, "<details>\n<summary>%s (raw)</summary>\n\n", html.EscapeString(plural(len(cl.Messages), "SIP message")))
		codeBlock(&b, rawSIP(cl, opt.UTC))
		b.WriteString("</details>\n\n")
	}

	b.WriteString("## Statistics\n\n")
	if err := report.WriteSections(&b, report.FormatMarkdown, r.summary.Sections(opt), opt); err != nil {
		return err
	}
	_, err := w.Write(b.Bytes())
	return err
}

// mdText makes captured text safe for inline Markdown: control characters
// become spaces and markup characters are escaped (including "<", so HTML
// cannot get through).
func mdText(s string) string {
	s = clean(s)
	var b strings.Builder
	for _, r := range s {
		if strings.ContainsRune("\\`*_{}[]<>()#+!|~&", r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}
