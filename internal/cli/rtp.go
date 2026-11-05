package cli

import (
	"context"
	"flag"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/sotoz/sipcurious/internal/analysis"
	"github.com/sotoz/sipcurious/internal/engine"
	"github.com/sotoz/sipcurious/internal/report"
	"github.com/sotoz/sipcurious/internal/rtp"
)

type rtpOpts struct {
	minPackets   int
	bad          bool
	sort         string
	uncorrelated bool
	thresholds
}

var rtpSorts = []string{"start", "mos", "loss", "jitter"}

func init() {
	AddFlagChoices("sort", rtpSorts...)
	Register(NewCommand(Command{
		Name:    "rtp",
		Aliases: []string{"streams"},
		Group:   "Analyze",
		Summary: "list the RTP streams with codec, loss, jitter, gaps and MOS",
		Usage:   "rtp [flags] CAPTURE...",
	}, func(fs *flag.FlagSet, o *rtpOpts) {
		fs.IntVar(&o.minPackets, "min-packets", 0, "hide streams with fewer than `N` packets")
		fs.BoolVar(&o.bad, "bad", false, "only streams breaching the quality thresholds (--min-mos, --max-loss, --max-jitter, --max-gap)")
		fs.StringVar(&o.sort, "sort", "start", "sort by `FIELD`: "+strings.Join(rtpSorts, ", ")+" (mos worst first, loss and jitter highest first)")
		fs.BoolVar(&o.uncorrelated, "uncorrelated", false, "also list streams that belong to no call (when filtering by call with --where)")
		o.bindMedia(fs)
	}, runRTP))
}

func runRTP(ctx context.Context, env *Env, c *Common, o *rtpOpts) int {
	if !slices.Contains(rtpSorts, o.sort) {
		return env.Fail(Usagef("--sort: %q is not one of %s", o.sort, strings.Join(rtpSorts, ", ")))
	}
	if o.minPackets < 0 {
		return env.Fail(Usagef("--min-packets must not be negative"))
	}
	if c.NoRTP {
		return env.Fail(Usagef("--no-rtp contradicts the rtp command"))
	}
	cfg, err := o.config()
	if err != nil {
		return env.Fail(err)
	}
	if _, err := c.Query(); err != nil { // fail on bad flags before the expensive load
		return env.Fail(err)
	}
	ds, err := c.Open(ctx, env)
	if err != nil {
		return env.Fail(err)
	}
	streams, err := selectStreams(ctx, ds, c, o)
	if err != nil {
		return env.Fail(err)
	}
	if o.minPackets > 0 {
		streams = slices.DeleteFunc(streams, func(s rtp.Stream) bool { return s.Packets < uint64(o.minPackets) })
	}
	if o.bad {
		streams = slices.DeleteFunc(streams, func(s rtp.Stream) bool { return !breaches(s, cfg) })
	}
	sortStreams(streams, o.sort)
	c.Infof(env, "%s matched", plural(len(streams), "RTP stream"))
	return env.Fail(c.WriteTable(env, StreamTable(streams, cfg)))
}

// selectStreams applies the stream filters. The query selects calls (their
// correlated streams); with a query, --uncorrelated adds the streams of no
// call that pass the address and time filters. --src-ip, --dst-ip, --since
// and --until are applied to the streams themselves, never to calls, and
// --callid selects by the stream's Call-ID.
func selectStreams(ctx context.Context, ds *engine.Dataset, c *Common, o *rtpOpts) ([]rtp.Stream, error) {
	// The sugar flags on addresses/time/Call-ID are stream filters here;
	// everything else (--where, --from, ...) filters the calls.
	callFlags := *c
	callFlags.SrcIP, callFlags.DstIP, callFlags.Since, callFlags.Until, callFlags.CallID = "", "", "", "", ""
	cq, err := callFlags.Query()
	if err != nil {
		return nil, err
	}
	var src, dst netip.Prefix
	if c.SrcIP != "" {
		if src, err = parsePrefix(c.SrcIP); err != nil {
			return nil, Usagef("--src-ip: %v", err)
		}
	}
	if c.DstIP != "" {
		if dst, err = parsePrefix(c.DstIP); err != nil {
			return nil, Usagef("--dst-ip: %v", err)
		}
	}
	var since, until time.Time
	if c.Since != "" {
		if since, err = parseWhen(c.Since, ds); err != nil {
			return nil, Usagef("--since: %v", err)
		}
	}
	if c.Until != "" {
		if until, err = parseWhen(c.Until, ds); err != nil {
			return nil, Usagef("--until: %v", err)
		}
	}
	callID := strings.ToLower(c.CallID)
	if c.CaseSensitive {
		callID = c.CallID
	}
	var out []rtp.Stream
	for i, s := range correlatedStreams(ds) {
		if i&0xfff == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		switch {
		case src.IsValid() && !src.Contains(s.Src.Addr().Unmap()):
			continue
		case dst.IsValid() && !dst.Contains(s.Dst.Addr().Unmap()):
			continue
		case !since.IsZero() && s.End.Before(since):
			continue
		case !until.IsZero() && s.Start.After(until):
			continue
		}
		if c.CallID != "" {
			id := s.CallID
			if !c.CaseSensitive {
				id = strings.ToLower(id)
			}
			if id == "" || !strings.Contains(id, callID) {
				continue
			}
		}
		if cq != nil {
			cl := ds.CallOf(s.CallID)
			if (cl == nil && !o.uncorrelated) || (cl != nil && !cq.MatchCall(cl)) {
				continue
			}
		}
		out = append(out, s)
	}
	return out, nil
}

func parsePrefix(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%q is not an IP address or CIDR", s)
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// parseWhen parses the --since/--until formats: RFC 3339, "YYYY-MM-DD
// HH:MM:SS" (UTC) or a time of day, taken on the date of the first capture
// time.
func parseWhen(s string, ds *engine.Dataset) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, nil
	}
	if t, err := time.Parse("2006-01-02 15:04:05", s); err == nil {
		return t, nil
	}
	for _, layout := range []string{"15:04:05", "15:04"} {
		if t, err := time.Parse(layout, s); err == nil {
			day := time.Time{}
			switch {
			case len(ds.Streams) > 0:
				day = ds.Streams[0].Start
			case len(ds.Messages) > 0:
				day = ds.Messages[0].Time
			}
			day = day.UTC()
			return time.Date(day.Year(), day.Month(), day.Day(), t.Hour(), t.Minute(), t.Second(), 0, time.UTC), nil
		}
	}
	return time.Time{}, fmt.Errorf("%q is not RFC 3339, 'YYYY-MM-DD HH:MM:SS' or HH:MM[:SS]", s)
}

// breaches reports whether a stream is worse than any limit of cfg. Streams
// with fewer than 10 packets are too short for meaningful statistics.
func breaches(s rtp.Stream, cfg analysis.Config) bool {
	if s.Packets < 10 {
		return false
	}
	return (s.MOS > 0 && s.MOS < cfg.MinMOS) || s.LossPct > cfg.MaxLossPct ||
		s.JitterMean > cfg.MaxJitter || s.MaxGap > cfg.MaxMediaGap
}

func sortStreams(ss []rtp.Stream, by string) {
	switch by {
	case "mos":
		sort.SliceStable(ss, func(i, j int) bool {
			a, b := ss[i].MOS, ss[j].MOS
			if (a == 0) != (b == 0) {
				return b == 0
			}
			return a < b
		})
	case "loss":
		sort.SliceStable(ss, func(i, j int) bool { return ss[i].LossPct > ss[j].LossPct })
	case "jitter":
		sort.SliceStable(ss, func(i, j int) bool { return ss[i].JitterMean > ss[j].JitterMean })
	default:
		sort.SliceStable(ss, func(i, j int) bool { return ss[i].Start.Before(ss[j].Start) })
	}
}

// StreamTable renders one row per RTP stream: Start, Duration, Src, Dst,
// SSRC (hex), Codec, Packets, Lost, Loss %, Jitter mean and max, Max gap,
// MOS, DTMF, Call-ID and Leg, plus the extra columns R-factor, RTCP and File.
// Cells breaching cfg are styled.
func StreamTable(ss []rtp.Stream, cfg analysis.Config) report.Table {
	over := func(bad bool) report.Style {
		if bad {
			return report.Warn
		}
		return report.None
	}
	t := report.Table{
		Title: "RTP streams",
		Columns: []report.Column{
			{Name: "Start", Key: "start", Kind: report.Time},
			{Name: "Duration", Key: "duration", Kind: report.Duration},
			{Name: "Src", Key: "src", Kind: report.String},
			{Name: "Dst", Key: "dst", Kind: report.String},
			{Name: "SSRC", Key: "ssrc", Kind: report.String},
			{Name: "Codec", Key: "codec", Kind: report.String},
			{Name: "Packets", Key: "packets", Kind: report.Int},
			{Name: "Lost", Key: "lost", Kind: report.Int},
			{Name: "Loss%", Key: "loss_pct", Kind: report.Float, Style: func(v any) report.Style {
				f, _ := v.(float64)
				return over(f > cfg.MaxLossPct)
			}},
			{Name: "Jitter", Key: "jitter_mean", Kind: report.Duration, Style: func(v any) report.Style {
				d, _ := v.(time.Duration)
				return over(d > cfg.MaxJitter)
			}},
			{Name: "JitterMax", Key: "jitter_max", Kind: report.Duration},
			{Name: "MaxGap", Key: "max_gap", Kind: report.Duration, Style: func(v any) report.Style {
				d, _ := v.(time.Duration)
				return over(d > cfg.MaxMediaGap)
			}},
			{Name: "MOS", Key: "mos", Kind: report.Float, Style: mosStyle},
			{Name: "DTMF", Key: "dtmf", Kind: report.Int},
			{Name: "Call-ID", Key: "call_id", Kind: report.String},
			{Name: "Leg", Key: "leg", Kind: report.String},
			{Name: "R-factor", Key: "r_factor", Kind: report.Float, Extra: true},
			{Name: "RTCP", Key: "rtcp", Kind: report.String, Extra: true},
			{Name: "File", Key: "file", Kind: report.String, Extra: true},
		},
		Rows: make([][]any, 0, len(ss)),
	}
	round := func(f float64, scale float64) any {
		if f == 0 {
			return nil
		}
		return math.Round(f*scale) / scale
	}
	for _, s := range ss {
		var dtmf any
		if s.DTMFEvents > 0 {
			dtmf = s.DTMFEvents
		}
		t.Rows = append(t.Rows, []any{
			s.Start, s.Duration(), s.Src, s.Dst, ssrcHex(s.SSRC), s.Codec, s.Packets, s.Lost,
			math.Round(s.LossPct*100) / 100, s.JitterMean, s.JitterMax, s.MaxGap,
			round(s.MOS, 100), dtmf, s.CallID, s.Leg,
			round(s.RFactor, 10), rtcpSummary(s.RTCP), s.File,
		})
	}
	return t
}

func ssrcHex(v uint32) string { return fmt.Sprintf("0x%08X", v) }

func rtcpSummary(r rtp.RTCPSummary) string {
	if r.Reports == 0 {
		return ""
	}
	return fmt.Sprintf("%d reports, max loss %.1f%%, max jitter %s, %d lost", r.Reports, r.MaxFractionLost,
		report.FormatDuration(r.MaxJitter), r.PacketsLost)
}

// correlatedStreams returns ds.Streams with CallID and Leg filled for the
// streams that call.Attach correlated (it fills them only in Call.Streams).
func correlatedStreams(ds *engine.Dataset) []rtp.Stream {
	type id struct {
		key   rtp.Key
		file  string
		index int
	}
	byID := map[id]*rtp.Stream{}
	calls := ds.Calls()
	for i := range calls {
		for j := range calls[i].Streams {
			s := &calls[i].Streams[j]
			byID[id{s.Key, s.File, s.FirstIndex}] = s
		}
	}
	out := slices.Clone(ds.Streams)
	for i := range out {
		if cs := byID[id{out[i].Key, out[i].File, out[i].FirstIndex}]; cs != nil {
			out[i].CallID, out[i].Leg = cs.CallID, cs.Leg
		}
	}
	return out
}
