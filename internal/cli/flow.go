package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/sotoz/sipcurious/internal/call"
	"github.com/sotoz/sipcurious/internal/flow"
)

type flowOpts struct {
	sdp, media, absolute bool
	maxLabel             int
	top                  int
	sort                 string
}

var flowFormats = []string{"ascii", "mermaid", "svg"}

func init() {
	Register(NewCommand(Command{
		Name:    "flow",
		Aliases: []string{"ladder"},
		Group:   "Inspect",
		Summary: "draw a ladder diagram (ASCII, Mermaid or SVG) of every matching call",
		Usage:   "flow [flags] CAPTURE...",
		Formats: flowFormats,
	}, func(fs *flag.FlagSet, o *flowOpts) {
		fs.BoolVar(&o.sdp, "sdp", false, "annotate messages with SDP codecs and media address")
		fs.BoolVar(&o.media, "media", true, "add the correlated RTP streams (needs RTP analysis, so not with --no-rtp)")
		fs.BoolVar(&o.absolute, "absolute", false, "label arrows with the time of day instead of the offset from the call start")
		fs.IntVar(&o.maxLabel, "max-label", 0, "cut arrow labels to `N` characters (0 = default 48)")
		fs.IntVar(&o.top, "top", 0, "draw only the first `N` calls after sorting")
		fs.StringVar(&o.sort, "sort", "start", "sort calls by `FIELD`: "+strings.Join(callSorts, ", "))
	}, runFlow))
}

func runFlow(ctx context.Context, env *Env, c *Common, o *flowOpts) int {
	switch {
	case !slices.Contains(callSorts, o.sort):
		return env.Fail(Usagef("--sort: %q is not one of %s", o.sort, strings.Join(callSorts, ", ")))
	case o.top < 0 || o.maxLabel < 0:
		return env.Fail(Usagef("--top and --max-label must not be negative"))
	}
	q, err := c.Query()
	if err != nil {
		return env.Fail(err)
	}
	ds, err := c.Open(ctx, env)
	if err != nil {
		return env.Fail(err)
	}
	sel, err := selectCalls(ctx, ds, q)
	if err != nil {
		return env.Fail(err)
	}
	sortCalls(sel, o.sort)
	if o.top > 0 && len(sel) > o.top {
		sel = sel[:o.top]
	}
	if c.Limit > 0 && len(sel) > c.Limit {
		sel = sel[:c.Limit]
	}
	calls := make([]call.Call, len(sel))
	for i, cl := range sel {
		calls[i] = *cl
	}
	c.Infof(env, "%s matched", plural(len(calls), "call"))
	fo := flow.Options{UTC: c.UTC, SDP: o.sdp, Media: o.media && !c.NoRTP, Absolute: o.absolute, MaxLabel: o.maxLabel}

	if c.Format == "svg" && isDirOutput(c.Output) {
		return env.Fail(writeSVGDir(c.Output, calls, fo, func(n int) { c.Infof(env, "wrote %s to %s", plural(n, "file"), c.Output) }))
	}
	out, err := c.OpenOutput(env)
	if err != nil {
		return env.Fail(err)
	}
	var werr error
	switch c.Format {
	case "ascii":
		werr = flow.WriteASCII(out, calls, fo)
	case "mermaid":
		werr = flow.WriteMermaid(out, calls, fo)
	default:
		for i := range calls {
			svg, serr := flow.SVG(calls[i], fo)
			if serr != nil {
				werr = serr
				break
			}
			if i > 0 {
				svg = "\n" + svg
			}
			if _, werr = out.WriteString(svg + "\n"); werr != nil {
				break
			}
		}
	}
	if cerr := out.Close(); werr == nil {
		werr = cerr
	}
	return env.Fail(werr)
}

// isDirOutput reports whether --output names a directory: a trailing path
// separator or an existing directory.
func isDirOutput(p string) bool {
	if p == "" {
		return false
	}
	if p[len(p)-1] == '/' || p[len(p)-1] == filepath.Separator {
		return true
	}
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

// writeSVGDir writes one <Call-ID>.svg per call into dir (created if needed).
func writeSVGDir(dir string, calls []call.Call, fo flow.Options, done func(int)) error {
	if err := os.MkdirAll(dir, 0o777); err != nil {
		return err
	}
	used := map[string]bool{}
	for i := range calls {
		svg, err := flow.SVG(calls[i], fo)
		if err != nil {
			return err
		}
		name := fileName(calls[i].CallID)
		for n := 2; used[name]; n++ {
			name = fmt.Sprintf("%s-%d", fileName(calls[i].CallID), n)
		}
		used[name] = true
		if err := os.WriteFile(filepath.Join(dir, name+".svg"), []byte(svg+"\n"), 0o666); err != nil {
			return err
		}
	}
	done(len(calls))
	return nil
}

// fileName turns a Call-ID into a safe file name: anything but letters,
// digits and "-_.@" becomes "_", dots do not lead, the length is bounded.
func fileName(id string) string {
	s := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '@', r == '.':
			return r
		}
		return '_'
	}, id)
	s = strings.TrimLeft(s, ".")
	if len(s) > 120 {
		s = s[:120]
	}
	if s == "" {
		s = "call"
	}
	return s
}
