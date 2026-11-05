package cli

import (
	"context"
	"flag"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/sotoz/sipcurious/internal/analysis"
	"github.com/sotoz/sipcurious/internal/call"
	"github.com/sotoz/sipcurious/internal/engine"
	"github.com/sotoz/sipcurious/internal/query"
	"github.com/sotoz/sipcurious/internal/rtp"
	"github.com/sotoz/sipcurious/internal/stats"
	"github.com/sotoz/sipcurious/internal/trace"
)

// selectCalls returns the calls of ds matching q (all when q is nil), in
// capture order. It returns early with ctx's error when cancelled.
func selectCalls(ctx context.Context, ds *engine.Dataset, q *query.Query) ([]*call.Call, error) {
	all := ds.Calls()
	out := make([]*call.Call, 0, len(all))
	for i := range all {
		if i&0xff == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		if q.MatchCall(&all[i]) {
			out = append(out, &all[i])
		}
	}
	return out, nil
}

// thresholds are the analysis limits shared by diagnose, rtp and report.
// Zero means "the analysis default"; the flags show the defaults.
type thresholds struct {
	slowPDD, slowSetup, maxJitter, maxGap, longCall time.Duration
	minMOS, maxLoss                                 float64
	minRetransmits                                  int
}

// bindMedia registers the RTP quality thresholds.
func (t *thresholds) bindMedia(fs *flag.FlagSet) {
	fs.Float64Var(&t.minMOS, "min-mos", analysis.DefaultMinMOS, "report streams with a MOS below `F`")
	fs.Float64Var(&t.maxLoss, "max-loss", analysis.DefaultMaxLossPct, "report streams with packet loss above `PCT` percent")
	fs.DurationVar(&t.maxJitter, "max-jitter", analysis.DefaultMaxJitter, "report streams with a mean jitter above `DUR`")
	fs.DurationVar(&t.maxGap, "max-gap", analysis.DefaultMaxMediaGap, "report streams with a gap between packets above `DUR`")
}

// bindSIP registers the signalling thresholds.
func (t *thresholds) bindSIP(fs *flag.FlagSet) {
	fs.DurationVar(&t.slowPDD, "slow-pdd", analysis.DefaultSlowPDD, "report a post-dial delay above `DUR`")
	fs.DurationVar(&t.slowSetup, "slow-setup", analysis.DefaultSlowSetup, "report a call setup (INVITE to 200 OK) above `DUR`")
	fs.DurationVar(&t.longCall, "long-call", 0, "report calls talking longer than `DUR` (0 = off)")
	fs.IntVar(&t.minRetransmits, "min-retransmits", analysis.DefaultMinRetransmits, "report requests retransmitted at least `N` times")
}

// config validates the thresholds and returns the analysis configuration.
func (t *thresholds) config() (analysis.Config, error) {
	switch {
	case t.slowPDD < 0 || t.slowSetup < 0 || t.maxJitter < 0 || t.maxGap < 0 || t.longCall < 0:
		return analysis.Config{}, Usagef("thresholds in durations must not be negative")
	case t.minMOS < 0 || t.maxLoss < 0 || t.minRetransmits < 0:
		return analysis.Config{}, Usagef("thresholds must not be negative")
	}
	return analysis.Config{
		SlowPDD: t.slowPDD, SlowSetup: t.slowSetup, MinRetransmits: t.minRetransmits,
		MinMOS: t.minMOS, MaxLossPct: t.maxLoss, MaxJitter: t.maxJitter, MaxMediaGap: t.maxGap,
		LongCall: t.longCall,
	}.WithDefaults(), nil
}

// splitList splits a comma separated flag value, dropping empty items.
func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// isTerminal reports whether f is a character device other than /dev/null.
func isTerminal(f *os.File) bool {
	st, err := f.Stat()
	if err != nil || st.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	null, err := os.Stat(os.DevNull)
	return err != nil || !os.SameFile(st, null)
}

// clean makes captured text safe for one line of plain text or Markdown code:
// control characters (newlines included) and bidi overrides become spaces.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0):
			return ' '
		case r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069, r == 0x200e, r == 0x200f:
			return ' '
		}
		return r
	}, strings.ToValidUTF8(s, "\uFFFD"))
}

// restrict narrows a statistics input to the selected calls: their messages
// (chronological), their calls and the RTP streams correlated to them.
// Packet counters and files keep describing the whole capture.
func restrict(in stats.Input, sel []*call.Call) stats.Input {
	out := stats.Input{Packets: in.Packets, Skipped: in.Skipped, Files: in.Files}
	out.Calls = make([]call.Call, len(sel))
	for i, c := range sel {
		out.Calls[i] = *c
		out.Messages = append(out.Messages, c.Messages...)
		out.Streams = append(out.Streams, c.Streams...)
	}
	slices.SortStableFunc(out.Messages, func(a, b trace.Message) int { return a.Time.Compare(b.Time) })
	slices.SortStableFunc(out.Streams, func(a, b rtp.Stream) int { return a.Start.Compare(b.Start) })
	return out
}
