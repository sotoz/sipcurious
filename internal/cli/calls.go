package cli

import (
	"context"
	"flag"
	"math"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/sotoz/sipcurious/internal/call"
	"github.com/sotoz/sipcurious/internal/report"
)

type callsOpts struct {
	failed, answered bool
	kind, state      string
	sort             string
	top              int
}

var callSorts = []string{"start", "duration", "pdd", "setup", "mos"}

func init() {
	FlagChoices("sort", callSorts...)
	FlagChoices("kind", string(call.KindCall), string(call.KindRegistration), string(call.KindSubscription),
		string(call.KindMessage), string(call.KindOptions), string(call.KindOther))
	FlagChoices("state", string(call.StateInSetup), string(call.StateNoResponse), string(call.StateCancelled),
		string(call.StateRedirected), string(call.StateFailed), string(call.StateAnswered),
		string(call.StateCompleted), string(call.StateOK))
	Register(NewCommand(Command{
		Name:    "calls",
		Group:   "Inspect",
		Aliases: []string{"dialogs"},
		Summary: "list the calls (one row per Call-ID) with state, timings and media quality",
		Usage:   "calls [flags] CAPTURE...",
	}, func(fs *flag.FlagSet, o *callsOpts) {
		fs.BoolVar(&o.failed, "failed", false, "only calls that failed or got no response")
		fs.BoolVar(&o.answered, "answered", false, "only answered calls (answered or completed)")
		fs.StringVar(&o.kind, "kind", "", "only calls of this `KIND`: call, registration, subscription, message, options, other")
		fs.StringVar(&o.state, "state", "", "only calls in this `STATE`: in-setup, no-response, cancelled, redirected, failed, answered, completed, ok")
		fs.StringVar(&o.sort, "sort", "start", "sort by `FIELD`: "+strings.Join(callSorts, ", ")+" (duration, pdd and setup longest first, mos worst first)")
		fs.IntVar(&o.top, "top", 0, "keep only the first `N` calls after sorting")
	}, runCalls))
}

func runCalls(ctx context.Context, env *Env, c *Common, o *callsOpts) int {
	if !slices.Contains(callSorts, o.sort) {
		return env.Fail(Usagef("--sort: %q is not one of %s", o.sort, strings.Join(callSorts, ", ")))
	}
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
	all := ds.Calls()
	var sel []*call.Call
	for i := range all {
		cl := &all[i]
		if i&0xff == 0 && ctx.Err() != nil {
			return env.Fail(ctx.Err())
		}
		switch {
		case o.failed && cl.State != call.StateFailed && cl.State != call.StateNoResponse:
		case o.answered && cl.State != call.StateAnswered && cl.State != call.StateCompleted:
		case o.kind != "" && !strings.EqualFold(string(cl.Kind), o.kind):
		case o.state != "" && !strings.EqualFold(string(cl.State), o.state):
		case !q.MatchCall(cl):
		default:
			sel = append(sel, cl)
		}
	}
	sortCalls(sel, o.sort)
	if o.top > 0 && len(sel) > o.top {
		sel = sel[:o.top]
	}
	c.Infof(env, "%s matched", plural(len(sel), "call"))
	return env.Fail(c.WriteTable(env, CallTable(sel)))
}

func sortCalls(cs []*call.Call, by string) {
	key := func(c *call.Call) time.Duration {
		switch by {
		case "duration":
			return -c.Duration()
		case "pdd":
			return -c.PDD
		case "setup":
			return -c.SetupTime
		}
		return 0
	}
	switch by {
	case "start":
		return // Calls() is ordered by start
	case "mos":
		// Worst first; calls without a MOS go last.
		sort.SliceStable(cs, func(i, j int) bool {
			a, b := worstMOS(cs[i]), worstMOS(cs[j])
			if (a == 0) != (b == 0) {
				return b == 0
			}
			return a < b
		})
	default:
		sort.SliceStable(cs, func(i, j int) bool { return key(cs[i]) < key(cs[j]) })
	}
}

// worstMOS is the lowest MOS of the call's streams, 0 when none was computed.
func worstMOS(c *call.Call) float64 {
	var w float64
	for _, s := range c.Streams {
		if s.MOS > 0 && (w == 0 || s.MOS < w) {
			w = s.MOS
		}
	}
	return w
}

// callCodec is the codec of the call's media: the first voice codec of the
// negotiated description, else the codec of the first correlated stream.
func callCodec(c *call.Call) string {
	for i := len(c.Media) - 1; i >= 0; i-- {
		m := c.Media[i]
		if m.Disabled {
			continue
		}
		for _, name := range m.Codecs {
			if !strings.EqualFold(name, "telephone-event") && !strings.EqualFold(name, "CN") {
				return name
			}
		}
	}
	for _, s := range c.Streams {
		if s.Codec != "" {
			return s.Codec
		}
	}
	return ""
}

func nonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func joinAddrPorts(aps []netip.AddrPort) string {
	parts := make([]string, 0, len(aps))
	for _, a := range aps {
		if a.IsValid() {
			parts = append(parts, a.String())
		}
	}
	return strings.Join(parts, " ")
}

func mediaEndpoints(c *call.Call) string {
	var parts []string
	seen := map[netip.AddrPort]bool{}
	for _, m := range c.Media {
		for _, a := range []netip.AddrPort{m.Caller, m.Callee} {
			if a.IsValid() && !seen[a] {
				seen[a] = true
				parts = append(parts, a.String())
			}
		}
	}
	return strings.Join(parts, " ")
}

// orNil returns nil for a zero duration so that "not captured" is an empty cell.
func orNil(d time.Duration) any {
	if d == 0 {
		return nil
	}
	return d
}

// CallTable renders one row per call: Start, Duration, Kind, State, Result,
// From, To (user parts), PDD, Setup, Talk, Codec, MOS (worst stream) and
// Call-ID, plus the extra columns UAs, Endpoints, Retransmissions, Media and
// Reason and EndedBy.
func CallTable(cs []*call.Call) report.Table {
	t := report.Table{
		Title: "Calls",
		Columns: []report.Column{
			{Name: "Start", Key: "start", Kind: report.Time},
			{Name: "Duration", Key: "duration", Kind: report.Duration},
			{Name: "Kind", Key: "kind", Kind: report.String},
			{Name: "State", Key: "state", Kind: report.String, Style: stateStyle},
			{Name: "Result", Key: "result", Kind: report.String, Style: infoStyle},
			{Name: "From", Key: "from", Kind: report.String},
			{Name: "To", Key: "to", Kind: report.String},
			{Name: "PDD", Key: "pdd", Kind: report.Duration},
			{Name: "Setup", Key: "setup", Kind: report.Duration},
			{Name: "Talk", Key: "talk", Kind: report.Duration},
			{Name: "Codec", Key: "codec", Kind: report.String},
			{Name: "MOS", Key: "mos", Kind: report.Float, Style: mosStyle},
			{Name: "Call-ID", Key: "call_id", Kind: report.String},
			{Name: "UAs", Key: "user_agents", Kind: report.String, Extra: true},
			{Name: "Endpoints", Key: "endpoints", Kind: report.String, Extra: true},
			{Name: "Retransmissions", Key: "retransmissions", Kind: report.Int, Extra: true},
			{Name: "Media", Key: "media", Kind: report.String, Extra: true},
			{Name: "Reason", Key: "reason", Kind: report.String, Extra: true},
			{Name: "EndedBy", Key: "ended_by", Kind: report.String, Extra: true},
		},
		Rows: make([][]any, 0, len(cs)),
	}
	for _, c := range cs {
		var mos any
		if m := worstMOS(c); m > 0 {
			mos = math.Round(m*100) / 100
		}
		t.Rows = append(t.Rows, []any{
			c.Start, c.Duration(), string(c.Kind), string(c.State), c.Result,
			nonEmpty(c.FromUser, c.From), nonEmpty(c.ToUser, c.To),
			orNil(c.PDD), orNil(c.SetupTime), orNil(c.TalkTime), callCodec(c), mos, c.CallID,
			strings.Join(c.UserAgents, "; "), joinAddrPorts(c.Endpoints), c.Retransmissions, mediaEndpoints(c),
			c.Reason, c.EndedBy,
		})
	}
	return t
}

func stateStyle(v any) report.Style {
	s, _ := v.(string)
	switch call.State(s) {
	case call.StateCompleted, call.StateAnswered, call.StateOK:
		return report.Good
	case call.StateFailed:
		return report.Bad
	case call.StateNoResponse, call.StateCancelled:
		return report.Warn
	case call.StateInSetup:
		return report.Dim
	}
	return report.None
}

func mosStyle(v any) report.Style {
	f, ok := v.(float64)
	switch {
	case !ok || f == 0:
		return report.None
	case f < 3.1:
		return report.Bad
	case f < 3.6:
		return report.Warn
	}
	return report.Good
}
