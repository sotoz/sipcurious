package analysis

import (
	"fmt"
	"strings"

	"github.com/sotoz/sipcurious/internal/trace"
)

func init() {
	Register(rule{
		id:    "slow-setup",
		title: "Post-dial delay (INVITE to first ringing or final response) is above the threshold",
		doc: "Post-dial delay (PDD) is the time from the first INVITE to the first 180/183 (or to the final response when nothing " +
			"rang first). The rule reports INVITE calls whose PDD is above `SlowPDD` (default 3 s). The finding shows the " +
			"timeline of the first INVITE, the first provisional response and, where visible, which hop was slow: the time to the " +
			"first `100 Trying` is the latency of the first hop, the rest is spent downstream.\n\n" +
			"Typical causes: slow DNS/ENUM lookups, a slow or overloaded downstream carrier, number translation or LCR " +
			"database delays, retransmissions caused by packet loss, an authentication round trip, or a callee that is being paged " +
			"(mobile push). Severity: **warning**.",
		check: checkSlowSetup,
	})
	Register(rule{
		id:    "slow-answer",
		title: "INVITE to 200 OK took longer than the threshold",
		doc: "Reports answered INVITE calls whose time from the first INVITE to the first 2xx (`SetupTime`) is above " +
			"`SlowSetup` (default 10 s). A long ring time is normal for people, so the finding separates PDD from ring " +
			"time: a long ring time with a normal PDD is just an unanswered phone, a long PDD points at the network.\n\n" +
			"Severity: **info** when the delay is mostly ring time (the callee took its time to pick up), **warning** when " +
			"post-dial delay is a large part of it.",
		check: checkSlowAnswer,
	})
}

func checkSlowSetup(in *Input) []Finding {
	limit := in.Config.WithDefaults().SlowPDD
	var out []Finding
	for i := range in.Calls {
		c := &in.Calls[i]
		if !isInviteCall(c) || c.PDD <= limit {
			continue
		}
		inv := initialInvite(c)
		if inv == nil {
			continue
		}
		var refs refSet
		refs.add(inv)
		var trying, prov *trace.Message
		for j := range c.Messages {
			m := &c.Messages[j]
			if m.IsRequest || !strings.EqualFold(m.Method, "INVITE") || m.Time.Before(inv.Time) {
				continue
			}
			switch {
			case m.StatusCode == 100 && trying == nil:
				trying = m
			case m.StatusCode > 100 && prov == nil && !m.Time.After(inv.Time.Add(c.PDD)):
				prov = m
			}
		}
		var b strings.Builder
		fmt.Fprintf(&b, "%s: INVITE at %s", parties(c), inv.Time.UTC().Format("15:04:05.000"))
		if trying != nil {
			fmt.Fprintf(&b, ", 100 Trying after %s", dur(trying.Time.Sub(inv.Time)))
			refs.add(trying)
		} else {
			b.WriteString(", no 100 Trying")
		}
		if prov != nil {
			fmt.Fprintf(&b, ", %s after %s (PDD)", prov.Info(), dur(prov.Time.Sub(inv.Time)))
			refs.add(prov)
		} else if fr := finalResponse(c); fr != nil {
			fmt.Fprintf(&b, ", final %s after %s (PDD)", fr.Info(), dur(fr.Time.Sub(inv.Time)))
			refs.add(fr)
		}
		if c.Retransmissions > 0 {
			fmt.Fprintf(&b, "; %s seen", plur(c.Retransmissions, "retransmission", "retransmissions"))
		}
		b.WriteString(".")
		hint := "Find which hop is slow: a late 100 Trying means the first hop (or the network to it), a 100 Trying followed by a long silence means a downstream hop or carrier. Check DNS/ENUM lookups, routing/number translation databases and retransmissions."
		if trying != nil && trying.Time.Sub(inv.Time) > limit/2 {
			hint = "The first hop itself answered slowly (100 Trying took " + dur(trying.Time.Sub(inv.Time)) + "): check its load, DNS lookups, and the network path to it."
		}
		out = append(out, Finding{
			Rule: "slow-setup", Severity: Warning, CallID: c.CallID, Time: c.Start,
			Title:   fmt.Sprintf("Post-dial delay %s for %s (threshold %s)", dur(c.PDD), parties(c), dur(limit)),
			Detail:  b.String(),
			Hint:    hint,
			Packets: refs.result(),
		})
	}
	return out
}

func checkSlowAnswer(in *Input) []Finding {
	limit := in.Config.WithDefaults().SlowSetup
	var out []Finding
	for i := range in.Calls {
		c := &in.Calls[i]
		if !isInviteCall(c) || c.SetupTime <= limit || c.Answered.IsZero() {
			continue
		}
		inv := initialInvite(c)
		if inv == nil {
			continue
		}
		var refs refSet
		refs.add(inv)
		for j := range c.Messages {
			m := &c.Messages[j]
			if !m.IsRequest && m.StatusCode >= 200 && m.StatusCode < 300 && m.Time.Equal(c.Answered) && strings.EqualFold(m.Method, "INVITE") {
				refs.add(m)
				break
			}
		}
		sev := Info
		hint := "Mostly ring time: the callee took long to answer, which is normal for a person. If it is not (auto-answer, IVR), check the callee's registration and call handling."
		if c.PDD > limit/3 {
			sev = Warning
			hint = "Much of the time passed before the callee started ringing: check routing, DNS lookups and downstream hops (see slow-setup)."
		}
		out = append(out, Finding{
			Rule: "slow-answer", Severity: sev, CallID: c.CallID, Time: c.Start,
			Title:   fmt.Sprintf("Call %s answered after %s (threshold %s)", parties(c), dur(c.SetupTime), dur(limit)),
			Detail:  fmt.Sprintf("INVITE to 200 OK: %s, of which post-dial delay %s and ringing %s.", dur(c.SetupTime), dur(c.PDD), dur(c.RingTime)),
			Hint:    hint,
			Packets: refs.result(),
		})
	}
	return out
}
