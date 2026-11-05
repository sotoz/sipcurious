package analysis

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/sotoz/sipcurious/internal/call"
)

// stuckMediaStop is how long before the end of the capture media must have
// stopped for an unterminated call to count as stuck.
const stuckMediaStop = 30 * time.Second

func init() {
	Register(rule{
		id:    "stuck-call",
		title: "The call was answered, media stopped, but no BYE ever ended it",
		doc: "Reports INVITE calls that were answered, still have no BYE at the end of the capture, and whose RTP streams all " +
			"stopped more than 30 seconds before the last packet of the capture. The dialog is still open in the " +
			"endpoints' or the proxy's state although nobody is talking: a hung call that keeps a channel or licence busy.\n\n" +
			"Typical causes: a lost BYE, a party that crashed or lost connectivity without session timers (RFC 4028), a PBX " +
			"or SBC that does not watch media timeouts, a NAT binding that expired. Calls without any captured media are " +
			"not reported (silence cannot be told from an uncaptured media path). Severity: **warning**.",
		check: checkStuckCall,
	})
	Register(rule{
		id:    "long-call",
		title: "The call lasted longer than the configured limit",
		doc: "Only active when `Config.LongCall` is set (the default 0 turns it off). Reports answered INVITE calls whose talk time " +
			"(200 OK to BYE, or to the end of the capture for calls still up) exceeds the limit. Useful to find hung calls, " +
			"toll fraud and forgotten conference legs. Severity: **info**.",
		check: checkLongCall,
	})
	Register(rule{
		id:    "orphan-messages",
		title: "Responses, BYE or ACK without the request that started them (capture began mid-call)",
		doc: "Calls whose first captured message is a response, a BYE, an ACK or an in-dialog request (no initial INVITE) were " +
			"started before the capture began. One capture-wide finding gives the counts; nothing is reported per call because " +
			"nothing can be said about how these calls were set up.\n\n" +
			"Typical causes: the capture was started while calls were up, the capture rotated or was truncated, or asymmetric routing " +
			"means only one direction of the signalling is visible here (then the request path is missing for *every* call, which " +
			"points at the capture point rather than at the calls). Severity: **info**.",
		check: checkOrphans,
	})
	Register(rule{
		id:    "no-provisional",
		title: "INVITE answered after more than 1 s without any 100 Trying or 180 Ringing",
		doc: "The INVITE was answered with 200 OK more than one second after it was sent and no provisional response (100, 180, " +
			"183) was ever seen. Without a 100 Trying the caller keeps retransmitting the INVITE, and ringing feedback is missing. " +
			"Typical causes: a UA or B2BUA that does not send 100 Trying (RFC 3261 requires proxies to), provisional responses dropped or filtered, " +
			"or asymmetric routing that hides them from this capture point. Severity: **info**.",
		check: checkNoProvisional,
	})
	Register(rule{
		id:    "loop-or-hops",
		title: "Routing loop or Max-Forwards exhausted (482, 483, Max-Forwards <= 1)",
		doc: "Reports calls with a `482 Loop Detected` or `483 Too Many Hops` response (**error**), and requests that travel with " +
			"`Max-Forwards` of 1 or 0 (**warning**: one more hop and the request dies with 483). The finding lists the Via chain " +
			"of the message, where a repeated address shows the loop.\n\n" +
			"Typical causes: two proxies or a PBX and a trunk routing the same number to each other, a wrong dial-plan " +
			"rule that sends to itself, a forwarding loop, or a deliberately low Max-Forwards from a test tool.",
		check: checkLoop,
	})
	Register(rule{
		id:    "register-flapping",
		title: "The same address of record registers far too often (interval below 30 s)",
		doc: "Groups REGISTER transactions (authentication retries of the same attempt excluded) by address of record (the To URI) and " +
			"reports AoRs with five or more consecutive registrations less than 30 seconds apart. Normal refreshes are " +
			"minutes apart. The finding shows the count, the median interval and the Expires values and sources seen.\n\n" +
			"Typical causes: a device that reboots or loses its connection in a loop, two devices (or a device and a trunk) " +
			"registering the same account and kicking each other out, a registrar that grants a tiny Expires, or a NAT " +
			"binding that dies and forces re-registration. Severity: **warning**.",
		check: checkFlapping,
	})
	Register(rule{
		id:    "hold-resume",
		title: "The call was put on hold and resumed",
		doc: "Reports calls where a re-INVITE or UPDATE put the audio on hold (`sendonly`, `inactive` or a 0.0.0.0 connection address, RFC 6337) " +
			"and, if seen, when it was resumed, with the hold duration. Severity: **info**.\n\n" +
			"Hold explains silent periods and RTP gaps in the media statistics, and a hold that is never released explains one-way or " +
			"no media after a transfer.",
		check: checkHold,
	})
	Register(rule{
		id:    "forking",
		title: "The INVITE was forked to several destinations",
		doc: "Reports calls where several different To tags appeared in the provisional and final responses of the INVITE: the proxy " +
			"sent it to several devices at once. The finding names every fork with its source address and best response, and which " +
			"fork won (answered first). Severity: **info**.\n\n" +
			"Forking explains several 180s from different addresses, 487s for the losing legs after the winner answers and " +
			"media that starts on another address than the first ringing device.",
		check: checkForking,
	})
}

func checkStuckCall(in *Input) []Finding {
	_, end := captureBounds(in)
	var out []Finding
	for i := range in.Calls {
		c := &in.Calls[i]
		if !isInviteCall(c) || c.State != call.StateAnswered || len(c.Streams) == 0 {
			continue
		}
		var last time.Time
		for j := range c.Streams {
			if c.Streams[j].End.After(last) {
				last = c.Streams[j].End
			}
		}
		if end.Sub(last) <= stuckMediaStop {
			continue
		}
		var refs refSet
		for j := range c.Messages {
			m := &c.Messages[j]
			if !m.IsRequest && m.StatusCode >= 200 && m.StatusCode < 300 && m.Time.Equal(c.Answered) {
				refs.add(m)
			}
		}
		for j := range c.Streams {
			refs.refs = append(refs.refs, Ref{File: c.Streams[j].File, Index: c.Streams[j].FirstIndex})
		}
		out = append(out, Finding{
			Rule: "stuck-call", Severity: Warning, CallID: c.CallID, Time: last,
			Title: fmt.Sprintf("Call %s still open but media stopped %s before the capture ended", parties(c), dur(end.Sub(last))),
			Detail: fmt.Sprintf("Answered at %s; the last RTP packet was at %s and the capture ends at %s; no BYE was seen.",
				c.Answered.UTC().Format("15:04:05.000"), last.UTC().Format("15:04:05.000"), end.UTC().Format("15:04:05.000")),
			Hint:    "A BYE was lost or one side vanished: check session timers (Session-Expires/UPDATE refreshes), whether the call was torn down on a path this capture does not see, and media timeouts on the PBX/SBC.",
			Packets: refs.result(),
		})
	}
	return out
}

func checkLongCall(in *Input) []Finding {
	limit := in.Config.LongCall
	if limit <= 0 {
		return nil
	}
	_, end := captureBounds(in)
	var out []Finding
	for i := range in.Calls {
		c := &in.Calls[i]
		if !isInviteCall(c) || c.Answered.IsZero() {
			continue
		}
		talk := c.TalkTime
		if c.State == call.StateAnswered {
			talk = end.Sub(c.Answered)
		}
		if talk <= limit {
			continue
		}
		suffix := ""
		if c.State == call.StateAnswered {
			suffix = " and still up at the end of the capture"
		}
		out = append(out, Finding{
			Rule: "long-call", Severity: Info, CallID: c.CallID, Time: c.Answered,
			Title:   fmt.Sprintf("Call %s lasted %s (limit %s)%s", parties(c), dur(talk), dur(limit), suffix),
			Detail:  fmt.Sprintf("Answered at %s, talk time %s.", c.Answered.UTC().Format("15:04:05.000"), dur(talk)),
			Hint:    "Check that the call is wanted: forgotten conference legs, hung calls without session timers and toll fraud all look like this.",
			Packets: ackRefs(c),
		})
	}
	return out
}

func checkOrphans(in *Input) []Finding {
	var calls, msgs int
	var refs refSet
	var first time.Time
	kinds := map[string]int{}
	for i := range in.Calls {
		c := &in.Calls[i]
		if len(c.Messages) == 0 {
			continue
		}
		orphan := false
		switch {
		case c.Method == "": // responses only
			orphan = true
		case c.Kind == call.KindCall && initialInvite(c) == nil:
			orphan = true
		}
		if !orphan {
			continue
		}
		calls++
		msgs += len(c.Messages)
		m := &c.Messages[0]
		kinds[m.Info()]++
		refs.add(m)
		if first.IsZero() || m.Time.Before(first) {
			first = m.Time
		}
	}
	if calls == 0 {
		return nil
	}
	var parts []string
	for k, n := range kinds {
		parts = append(parts, fmt.Sprintf("%dx %s", n, k))
	}
	slices.Sort(parts)
	return []Finding{{
		Rule: "orphan-messages", Severity: Info, Time: first,
		Title: fmt.Sprintf("%s without the request that started them (capture began mid-call?)", plur(calls, "Call-ID", "Call-IDs")),
		Detail: fmt.Sprintf("%s (%s) have no initial request in the capture; first messages seen: %s.",
			plur(calls, "Call-ID", "Call-IDs"), plur(msgs, "message", "messages"), joinMax(parts, 8)),
		Hint:    "Normal when the capture started while calls were up. If it affects every call, only one direction of the signalling passes the capture point: capture where both directions are visible.",
		Packets: refs.result(),
	}}
}

func checkNoProvisional(in *Input) []Finding {
	var out []Finding
	for i := range in.Calls {
		c := &in.Calls[i]
		if !isInviteCall(c) || c.SetupTime <= time.Second || c.Answered.IsZero() {
			continue
		}
		inv := initialInvite(c)
		if inv == nil {
			continue
		}
		prov := false
		var refs refSet
		refs.add(inv)
		for j := range c.Messages {
			m := &c.Messages[j]
			if m.IsRequest || !strings.EqualFold(m.Method, "INVITE") {
				continue
			}
			if m.IsProvisional() {
				prov = true
				break
			}
			if m.StatusCode >= 200 && m.StatusCode < 300 && m.Time.Equal(c.Answered) {
				refs.add(m)
			}
		}
		if prov {
			continue
		}
		out = append(out, Finding{
			Rule: "no-provisional", Severity: Info, CallID: c.CallID, Time: c.Start,
			Title:   fmt.Sprintf("INVITE %s -> answered after %s with no 100 Trying or ringing", parties(c), dur(c.SetupTime)),
			Detail:  fmt.Sprintf("%d INVITE retransmission(s) or repeats seen; the first response of any kind was the 200 OK, %s after the INVITE.", c.Retransmissions, dur(c.SetupTime)),
			Hint:    "The callee/B2BUA sends no 100 Trying (the caller then retransmits the INVITE) and no 180: enable provisional responses on the answering side, or check that they are not filtered on their way back.",
			Packets: refs.result(),
		})
	}
	return out
}

func checkLoop(in *Input) []Finding {
	var out []Finding
	for i := range in.Calls {
		c := &in.Calls[i]
		var refs refSet
		var why []string
		sev := Warning
		var chain string
		for j := range c.Messages {
			m := &c.Messages[j]
			if !m.IsRequest && (m.StatusCode == 482 || m.StatusCode == 483) {
				why = append(why, fmt.Sprintf("%s from %s", m.Info(), m.SrcAddr()))
				refs.add(m)
				sev = Error
				if chain == "" {
					chain = viaChain(m)
				}
				continue
			}
			if m.IsRequest {
				if mf, ok := atoiSafe(hdr(m, "Max-Forwards")); ok && mf <= 1 && m.Method != "ACK" {
					why = append(why, fmt.Sprintf("%s with Max-Forwards: %d from %s", m.Method, mf, m.SrcAddr()))
					refs.add(m)
					if chain == "" {
						chain = viaChain(m)
					}
				}
			}
		}
		if len(why) == 0 {
			continue
		}
		title := fmt.Sprintf("Routing loop or hop limit reached for %s", parties(c))
		if sev == Warning {
			title = fmt.Sprintf("Max-Forwards nearly exhausted for %s", parties(c))
		}
		detail := joinMax(dedupe(why), 5) + "."
		if chain != "" {
			detail += " Via chain: " + chain + "."
		}
		out = append(out, Finding{
			Rule: "loop-or-hops", Severity: sev, CallID: c.CallID, Time: c.Start,
			Title:   title,
			Detail:  detail,
			Hint:    "Look for an address that appears twice in the Via/Record-Route chain: two servers route this number to each other (dial-plan or trunk rule loop). A very low Max-Forwards from the first hop is a misconfigured UA or test tool.",
			Packets: refs.result(),
		})
	}
	return out
}

func dedupe(s []string) []string {
	var out []string
	for _, x := range s {
		if !slices.Contains(out, x) {
			out = append(out, x)
		}
	}
	return out
}
