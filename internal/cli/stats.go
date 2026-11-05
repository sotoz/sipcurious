package cli

import (
	"context"
	"flag"
	"io"

	"github.com/sotoz/sipcurious/internal/report"
	"github.com/sotoz/sipcurious/internal/stats"
)

type statsOpts struct{ top int }

func init() {
	Register(NewCommand(Command{
		Name:    "stats",
		Group:   "Analyze",
		Summary: "capture-wide statistics: ASR/ACD, timings, SIP methods and codes, failures, RTP quality",
		Usage:   "stats [flags] CAPTURE...",
		Formats: []string{"table", "json", "markdown", "html"},
	}, func(fs *flag.FlagSet, o *statsOpts) {
		fs.IntVar(&o.top, "top", 0, "keep at most `N` rows in every section (0 = the built-in ten)")
	}, runStats))
}

func runStats(ctx context.Context, env *Env, c *Common, o *statsOpts) int {
	if o.top < 0 {
		return env.Fail(Usagef("--top must not be negative"))
	}
	q, err := c.Query()
	if err != nil {
		return env.Fail(err)
	}
	ds, err := c.Open(ctx, env)
	if err != nil {
		return env.Fail(err)
	}
	in := ds.StatsInput()
	if q != nil {
		// Statistics of the matching calls: their messages, streams and
		// calls only; packet counters then describe the whole capture.
		sel, err := selectCalls(ctx, ds, q)
		if err != nil {
			return env.Fail(err)
		}
		in = restrict(in, sel)
		c.Infof(env, "statistics of %s", plural(len(sel), "matching call"))
	}
	err = c.WriteWith(env, func(w io.Writer, f report.Format, opt report.Options) error {
		secs := stats.Compute(in).Sections(opt)
		if o.top > 0 {
			for i := range secs {
				if i > 0 && len(secs[i].Table.Rows) > o.top { // the overview is not a ranking
					secs[i].Table.Rows = secs[i].Table.Rows[:o.top]
				}
			}
		}
		return report.WriteSections(w, f, secs, opt)
	})
	return env.Fail(err)
}
