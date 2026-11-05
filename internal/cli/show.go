package cli

import (
	"context"
	"flag"
	"fmt"
	"strings"

	"github.com/sotoz/sipcurious/internal/engine"
	"github.com/sotoz/sipcurious/internal/report"
	"github.com/sotoz/sipcurious/internal/trace"
)

type showOpts struct {
	headersOnly bool
	sdpOnly     bool
}

func init() {
	Register(NewCommand(Command{
		Name:    "show",
		Group:   "Inspect",
		Formats: []string{"text"},
		Summary: "print the matching SIP messages as full text",
		Usage:   "show [flags] CAPTURE...",
	}, func(fs *flag.FlagSet, o *showOpts) {
		fs.BoolVar(&o.headersOnly, "headers-only", false, "omit the message bodies")
		fs.BoolVar(&o.sdpOnly, "sdp-only", false, "print only the SDP of messages that carry one")
	}, runShow))
}

func runShow(ctx context.Context, env *Env, c *Common, o *showOpts) int {
	if o.headersOnly && o.sdpOnly {
		return env.Fail(Usagef("--headers-only and --sdp-only exclude each other"))
	}
	q, err := c.Query()
	if err != nil {
		return env.Fail(err)
	}
	ds, err := c.Open(ctx, env, func(opt *engine.Options) { opt.RTP = opt.RTP && q.NeedsCalls() })
	if err != nil {
		return env.Fail(err)
	}
	idx, err := Select(ctx, ds, q, c.Limit)
	if err != nil {
		return env.Fail(err)
	}
	out, err := c.OpenOutput(env)
	if err != nil {
		return env.Fail(err)
	}
	werr := writeShow(out, ds.Messages, idx, o, out.Color, c.UTC)
	if cerr := out.Close(); werr == nil {
		werr = cerr
	}
	c.Infof(env, "%s shown", plural(len(idx), "message"))
	return env.Fail(werr)
}

func writeShow(w *Out, msgs []trace.Message, idx []int, o *showOpts, color, utc bool) error {
	var sb strings.Builder
	for n, i := range idx {
		m := &msgs[i]
		body := ""
		switch {
		case o.sdpOnly:
			body = m.SDP()
			if body == "" {
				continue
			}
		case o.headersOnly:
			body = m.Raw[:min(m.HeaderEnd, len(m.Raw))]
		default:
			body = m.Raw
		}
		sb.Reset()
		if n > 0 {
			sb.WriteByte('\n')
		}
		fmt.Fprintf(&sb, "#%d %s %s %s -> %s\n", m.Index, m.File, report.FormatTime(m.Time, utc),
			endpoint(m.Src, m.SrcPort), endpoint(m.Dst, m.DstPort))
		writeMessageText(&sb, body, !o.sdpOnly, color)
		if _, err := w.WriteString(sb.String()); err != nil {
			return err
		}
	}
	return nil
}

// writeMessageText appends text with CRLF folded to LF, a single trailing
// newline, and control characters other than tab neutralised so a capture can
// not inject terminal escapes. With color (and headers true) header names are
// bold.
func writeMessageText(sb *strings.Builder, text string, headers, color bool) {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.TrimRight(text, "\n")
	inHeaders := headers
	for n, line := range strings.Split(text, "\n") {
		line = sanitizeLine(line)
		if inHeaders && line == "" {
			inHeaders = false
		}
		if color && inHeaders && n > 0 {
			if name, rest, ok := strings.Cut(line, ":"); ok && !strings.ContainsAny(name, " \t") {
				sb.WriteString("\x1b[1m" + name + "\x1b[0m:" + rest + "\n")
				continue
			}
		}
		sb.WriteString(line)
		sb.WriteByte('\n')
	}
}

func sanitizeLine(s string) string {
	clean := true
	for i := 0; i < len(s); i++ {
		if (s[i] < 0x20 && s[i] != '\t') || s[i] == 0x7f {
			clean = false
			break
		}
	}
	if clean {
		return s
	}
	return strings.Map(func(r rune) rune {
		if (r < 0x20 && r != '\t') || r == 0x7f {
			return '\uFFFD'
		}
		return r
	}, s)
}
