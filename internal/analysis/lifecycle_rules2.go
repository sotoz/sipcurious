package analysis

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/sotoz/sipcurious/internal/call"
	"github.com/sotoz/sipcurious/internal/trace"
)

// viaChain renders the sent-by hosts of all Via headers of m, topmost first.
func viaChain(m *trace.Message) string {
	var hops []string
	for _, h := range m.Headers("Via") {
		for _, part := range strings.Split(h, ",") {
			if v := viaHostPort(part); v != "" {
				hops = append(hops, v)
			}
		}
	}
	return strings.Join(hops, " > ")
}

// viaHostPort returns host[:port] of one Via value ("SIP/2.0/UDP host:port;branch=...").
func viaHostPort(v string) string {
	f := strings.Fields(v)
	if len(f) < 2 {
		return ""
	}
	h := f[1]
	if i := strings.IndexByte(h, ';'); i >= 0 {
		h = h[:i]
	}
	return h
}

const (
	flapInterval = 30 * time.Second
	flapMinRegs  = 5
)

type regEvent struct {
	at   time.Time
	m    *trace.Message
	call *call.Call
}

func checkFlapping(in *Input) []Finding {
	byAoR := map[string][]regEvent{}
	var order []string
	for i := range in.Calls {
		c := &in.Calls[i]
		if c.Kind != call.KindRegistration {
			continue
		}
		key := uriCore(c.To)
		lastCSeq := -1
		challenged := false
		for j := range c.Messages {
			m := &c.Messages[j]
			if m.IsRequest {
				if m.Method != "REGISTER" {
					continue
				}
				n := m.CSeqNumber()
				if n == lastCSeq {
					continue // retransmission
				}
				lastCSeq = n
				if challenged {
					challenged = false
					continue // retry with credentials after a challenge
				}
				if _, ok := byAoR[key]; !ok {
					order = append(order, key)
				}
				byAoR[key] = append(byAoR[key], regEvent{m.Time, m, c})
				continue
			}
			if m.Method == "REGISTER" && (m.StatusCode == 401 || m.StatusCode == 407 || m.StatusCode == 423) {
				challenged = true
			}
		}
	}
	var out []Finding
	for _, key := range order {
		ev := byAoR[key]
		slices.SortStableFunc(ev, func(a, b regEvent) int { return a.at.Compare(b.at) })
		// longest run of registrations with every gap below the interval
		bestFrom, bestLen := 0, 0
		for from := 0; from < len(ev); {
			to := from + 1
			for to < len(ev) && ev[to].at.Sub(ev[to-1].at) < flapInterval {
				to++
			}
			if to-from > bestLen {
				bestFrom, bestLen = from, to-from
			}
			from = to
		}
		if bestLen < flapMinRegs {
			continue
		}
		run := ev[bestFrom : bestFrom+bestLen]
		gaps := make([]time.Duration, 0, len(run)-1)
		for i := 1; i < len(run); i++ {
			gaps = append(gaps, run[i].at.Sub(run[i-1].at))
		}
		slices.Sort(gaps)
		median := gaps[len(gaps)/2]
		var refs refSet
		srcs := map[string]bool{}
		var srcList, expires []string
		for _, e := range run {
			refs.add(e.m)
			if s := e.m.Src.String(); !srcs[s] {
				srcs[s] = true
				srcList = append(srcList, s)
			}
			if x := hdr(e.m, "Expires"); x != "" && !slices.Contains(expires, x) {
				expires = append(expires, x)
			}
		}
		hint := "A device that re-registers this often is rebooting or losing its connection, or a registrar grants a tiny Expires. Check the device's logs and the Expires/Min-Expires values."
		if len(srcList) > 1 {
			hint = "Registrations come from " + plur(len(srcList), "address", "addresses") + ": two devices (or a device and a trunk) share this account and overwrite each other's binding. Give each device its own account."
		}
		detail := fmt.Sprintf("%s: %d registrations within %s, median interval %s (limit %s); sources: %s",
			key, len(run), dur(run[len(run)-1].at.Sub(run[0].at)), dur(median), dur(flapInterval), joinMax(srcList, 4))
		if len(expires) > 0 {
			detail += "; Expires: " + joinMax(expires, 4)
		}
		out = append(out, Finding{
			Rule: "register-flapping", Severity: Warning, CallID: run[0].call.CallID, Time: run[0].at,
			Title:   fmt.Sprintf("%s registered %d times, median %s apart", key, len(run), dur(median)),
			Detail:  detail + ".",
			Hint:    hint,
			Packets: refs.result(),
		})
	}
	return out
}

func checkHold(in *Input) []Finding {
	var out []Finding
	for i := range in.Calls {
		c := &in.Calls[i]
		if !isInviteCall(c) {
			continue
		}
		type span struct{ from, to time.Time }
		var spans []span
		var refs refSet
		open := false
		for k := range c.Media {
			m := &c.Media[k]
			if m.Type != "audio" || m.Early {
				continue
			}
			switch {
			case m.Hold && !open:
				open = true
				spans = append(spans, span{from: m.Time})
				refs.addAt(c, m.Time)
			case !m.Hold && open && !m.Disabled:
				open = false
				spans[len(spans)-1].to = m.Time
				refs.addAt(c, m.Time)
			}
		}
		if len(spans) == 0 {
			continue
		}
		parts := make([]string, len(spans))
		for k, s := range spans {
			if s.to.IsZero() {
				parts[k] = fmt.Sprintf("hold at %s, never resumed", s.from.UTC().Format("15:04:05.000"))
			} else {
				parts[k] = fmt.Sprintf("hold at %s, resumed after %s", s.from.UTC().Format("15:04:05.000"), dur(s.to.Sub(s.from)))
			}
		}
		title := fmt.Sprintf("Call %s put on hold and resumed (%s)", parties(c), plur(len(spans), "time", "times"))
		hint := "Silence and RTP gaps in this window are expected. Hold with music-on-hold shows as media from the holder."
		if spans[len(spans)-1].to.IsZero() {
			title = fmt.Sprintf("Call %s put on hold (%s)", parties(c), plur(len(spans), "time", "times"))
			hint = "The last hold was never released in the capture: if the call is meant to be live, the resume re-INVITE is missing or was rejected."
		}
		out = append(out, Finding{
			Rule: "hold-resume", Severity: Info, CallID: c.CallID, Time: spans[0].from,
			Title: title, Detail: strings.Join(parts, "; ") + ".", Hint: hint, Packets: refs.result(),
		})
	}
	return out
}

func checkForking(in *Input) []Finding {
	var out []Finding
	for i := range in.Calls {
		c := &in.Calls[i]
		if !isInviteCall(c) || c.Forks <= 1 {
			continue
		}
		type fork struct {
			tag  string
			src  string
			code int
		}
		var forks []fork
		var refs refSet
		winner := ""
		for j := range c.Messages {
			m := &c.Messages[j]
			if m.IsRequest || m.StatusCode <= 100 || m.StatusCode >= 300 || !strings.EqualFold(m.Method, "INVITE") {
				continue
			}
			tag := m.ToTag()
			if tag == "" {
				continue
			}
			k := slices.IndexFunc(forks, func(f fork) bool { return f.tag == tag })
			if k < 0 {
				forks = append(forks, fork{tag, m.SrcAddr().String(), m.StatusCode})
				refs.add(m)
			} else if m.StatusCode > forks[k].code {
				forks[k].code = m.StatusCode
				refs.add(m)
			}
			if m.StatusCode >= 200 && winner == "" {
				winner = tag
			}
		}
		parts := make([]string, len(forks))
		for k, f := range forks {
			parts[k] = fmt.Sprintf("%s (to-tag %s) best response %d", f.src, f.tag, f.code)
			if f.tag == winner {
				parts[k] += " [winner]"
			}
		}
		title := fmt.Sprintf("Call %s forked to %d destinations", parties(c), len(forks))
		hint := "Several devices were ringing; the others receive CANCEL (487) when one answers. Media must be taken from the winning leg."
		if winner == "" {
			hint = "No fork answered in the capture."
		} else if k := slices.IndexFunc(forks, func(f fork) bool { return f.tag == winner }); k >= 0 {
			title += ", answered by " + forks[k].src
		}
		out = append(out, Finding{
			Rule: "forking", Severity: Info, CallID: c.CallID, Time: c.Start,
			Title: title, Detail: strings.Join(parts, "; ") + ".", Hint: hint, Packets: refs.result(),
		})
	}
	return out
}
