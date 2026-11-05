package analysis

import (
	"fmt"
	"strings"
	"time"

	"github.com/sotoz/sipcurious/internal/call"
	"github.com/sotoz/sipcurious/internal/rtp"
)

func init() {
	Register(rule{
		id:    "no-media",
		title: "The call was answered with audio but no RTP was captured",
		doc: "Reports INVITE calls that were answered (2xx), negotiated an active audio stream (not disabled, not on hold, " +
			"`sendrecv`) and lasted at least one second after the answer, but have no RTP stream correlated to them. " +
			"Severity: **error**.\n\n" +
			"If the capture contains no RTP at all, it is probably a SIP-only capture (media taken on another interface or " +
			"not captured): one **info** finding says so instead of one error per call.\n\n" +
			"Typical causes: media is blocked by a firewall or NAT (private address in the SDP), the media path goes through a " +
			"different interface than the capture point, SRTP/DTLS on an unusual port, or the endpoints send media to an address " +
			"that differs from the SDP (symmetric RTP/latching).",
		check: checkNoMedia,
	})
	Register(rule{
		id:    "one-way-media",
		title: "RTP flows in one direction only",
		doc: "Reports answered INVITE calls with an active `sendrecv` audio stream where RTP was captured in one direction only. " +
			"The finding names the missing direction, the SDP endpoints that should have exchanged media and what the " +
			"existing stream did. Severity: **error**.\n\n" +
			"Capture-point limit: a capture taken on one side of an SBC, NAT or media gateway only sees the legs that cross that " +
			"point, and silence suppression without comfort noise can look like a missing direction on short streams. Verify with a capture on the other " +
			"side before blaming the network.\n\n" +
			"Typical causes: NAT/firewall dropping the inbound media, private IPs in the SDP, wrong or unreachable RTP ports, an endpoint " +
			"that sends to the SIP signalling address instead of the SDP address, and a muted or crashed media process.",
		check: checkOneWayMedia,
	})
	Register(rule{
		id:    "media-quality",
		title: "An RTP stream has poor quality (MOS, packet loss, jitter or gaps)",
		doc: "Checks every RTP stream, including streams that no call claimed, against the thresholds `MinMOS` (3.6), " +
			"`MaxLossPct` (1 %), `MaxJitter` (30 ms, tested against the mean RFC 3550 jitter) and `MaxMediaGap` (1 s). " +
			"Streams with fewer than 10 packets are ignored: the statistics are meaningless. One finding per stream lists the numbers per " +
			"direction (RTCP receiver report values are added when present).\n\n" +
			"Severity: **warning**; **error** when the MOS is below 3.1, the loss is at least five times the threshold, the " +
			"jitter at least three times, or a gap at least five times the threshold.\n\n" +
			"Statistics describe the path up to the capture point. Loss seen at the receiver's side is not necessarily loss on the path before " +
			"an SBC. Typical causes: congested or lossy links, Wi-Fi, missing QoS (DSCP EF), CPU starvation on the sender, " +
			"silence suppression without comfort noise (gaps), and transcoding.",
		check: checkMediaQuality,
	})
}

// talkWindow reports how long the call was up after the answer in the capture.
func talkWindow(c *call.Call) time.Duration {
	if c.Answered.IsZero() {
		return 0
	}
	return c.End.Sub(c.Answered)
}

func checkNoMedia(in *Input) []Finding {
	var out []Finding
	var candidates []*call.Call
	for i := range in.Calls {
		c := &in.Calls[i]
		if !isInviteCall(c) || !answered(c) || len(c.Streams) > 0 || talkWindow(c) < time.Second {
			continue
		}
		if _, ok := activeAudio(c); !ok {
			continue
		}
		candidates = append(candidates, c)
	}
	if len(candidates) == 0 {
		return nil
	}
	if len(in.Streams) == 0 {
		first := candidates[0]
		return []Finding{{
			Rule: "no-media", Severity: Info, Time: first.Answered,
			Title:   fmt.Sprintf("No RTP in the capture: %s answered with audio but media was not captured", plur(len(candidates), "call was", "calls were")),
			Detail:  "The capture holds no RTP at all, so it was probably taken where only signalling passes (or media was filtered out). Media rules cannot say anything about these calls.",
			Hint:    "Capture on the media path (or without a port filter such as 'port 5060') to analyse audio.",
			Packets: ackRefs(first),
		}}
	}
	for _, c := range candidates {
		m, _ := activeAudio(c)
		var refs refSet
		refs.addAt(c, m.Time)
		if inv := initialInvite(c); inv != nil {
			refs.add(inv)
		}
		out = append(out, Finding{
			Rule: "no-media", Severity: Error, CallID: c.CallID, Time: c.Answered,
			Title: fmt.Sprintf("Call %s answered but no RTP was captured (%s)", parties(c), strings.Join(firstN(m.Codecs, 2), ", ")),
			Detail: fmt.Sprintf("Negotiated audio %s: caller %s, callee %s, up for %s after the 200 OK, but none of the %d RTP streams in the capture matches these endpoints.%s",
				strings.Join(m.Codecs, ","), ep(m.Caller), ep(m.Callee), dur(talkWindow(c)), len(in.Streams), privateNote(m)),
			Hint: "Check that the endpoints can reach each other's SDP address (private IP behind NAT? firewall ports?), whether media passes " +
				"through a different interface than the one captured, and capture on the endpoints to see whether RTP is sent at all.",
			Packets: refs.result(),
		})
	}
	return out
}

func ackRefs(c *call.Call) []Ref {
	var refs refSet
	for i := range c.Messages {
		m := &c.Messages[i]
		if !m.IsRequest && m.StatusCode >= 200 && m.StatusCode < 300 && m.Time.Equal(c.Answered) {
			refs.add(m)
			break
		}
	}
	return refs.result()
}

func firstN(s []string, n int) []string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// privateNote warns about private addresses in the negotiated media endpoints.
func privateNote(m call.Media) string {
	var side []string
	if m.Caller.IsValid() && isLocal(m.Caller.Addr()) {
		side = append(side, "caller "+m.Caller.Addr().String())
	}
	if m.Callee.IsValid() && isLocal(m.Callee.Addr()) {
		side = append(side, "callee "+m.Callee.Addr().String())
	}
	if len(side) == 0 {
		return ""
	}
	return " The SDP announces private addresses (" + strings.Join(side, ", ") + "): media from the other side cannot reach them without NAT traversal."
}

func checkOneWayMedia(in *Input) []Finding {
	var out []Finding
	for i := range in.Calls {
		c := &in.Calls[i]
		if !isInviteCall(c) || !answered(c) || len(c.Streams) == 0 || talkWindow(c) < time.Second {
			continue
		}
		m, ok := activeAudio(c)
		if !ok {
			continue
		}
		var fwd, rev []*rtp.Stream
		for j := range c.Streams {
			s := &c.Streams[j]
			switch s.Leg {
			case "caller->callee":
				fwd = append(fwd, s)
			case "callee->caller":
				rev = append(rev, s)
			}
		}
		if (len(fwd) == 0) == (len(rev) == 0) {
			continue
		}
		have, missing := fwd, "callee->caller"
		from, to := m.Caller, m.Callee
		missFrom, missTo := m.Callee, m.Caller
		if len(fwd) == 0 {
			have, missing = rev, "caller->callee"
			from, to = m.Callee, m.Caller
			missFrom, missTo = m.Caller, m.Callee
		}
		var pk uint64
		var refs refSet
		for _, s := range have {
			pk += s.Packets
			refs.refs = append(refs.refs, Ref{File: s.File, Index: s.FirstIndex})
		}
		refs.addAt(c, m.Time)
		side, heard := "callee", "caller"
		if missing == "caller->callee" {
			side, heard = "caller", "callee"
		}
		out = append(out, Finding{
			Rule: "one-way-media", Severity: Error, CallID: c.CallID, Time: have[0].Start,
			Title: fmt.Sprintf("One-way audio: only %s RTP captured, nothing %s", have[0].Leg, missing),
			Detail: fmt.Sprintf("%d packets flowed %s (%s -> %s) but no RTP %s was captured although the SDP says %s (%s) should send to %s (%s). "+
				"The %s hears nothing from the %s.%s Captured at one point only: if media takes a path that does not cross the capture point, it is invisible here.",
				pk, have[0].Leg, ep(from), ep(to), missing, side, ep(missFrom), heard, ep(missTo), heard, side, privateNote(m)),
			Hint: fmt.Sprintf("Check what the %s endpoint does with the media it receives and sends: NAT/firewall blocking %s -> %s, wrong or private address in the %s's SDP, "+
				"a muted or crashed media process, or RTP going to a different address (symmetric RTP). Capture on the %s side.",
				side, ep(missFrom), ep(missTo), side, side),
			Packets: refs.result(),
		})
	}
	return out
}

func checkMediaQuality(in *Input) []Finding {
	cfg := in.Config.WithDefaults()
	var out []Finding
	seen := map[rtp.Key]bool{}
	for i := range in.Calls {
		c := &in.Calls[i]
		for j := range c.Streams {
			s := &c.Streams[j]
			seen[s.Key] = true
			if f, ok := streamFinding(c, s, cfg); ok {
				out = append(out, f)
			}
		}
	}
	for i := range in.Streams {
		s := &in.Streams[i]
		if seen[s.Key] {
			continue
		}
		if f, ok := streamFinding(nil, s, cfg); ok {
			out = append(out, f)
		}
	}
	return out
}

// gapExplainedByHold reports whether the call was on hold (re-INVITE with
// sendonly/inactive or a 0.0.0.0 address) for a period that covers a media gap
// of the given length, give or take slack: RTP stops during hold by design.
func gapExplainedByHold(c *call.Call, gap, slack time.Duration) bool {
	if c == nil {
		return false
	}
	var from time.Time
	var longest time.Duration
	for i := range c.Media {
		m := &c.Media[i]
		if m.Type != "audio" || m.Early {
			continue
		}
		switch {
		case m.Hold && from.IsZero():
			from = m.Time
		case !m.Hold && !from.IsZero() && !m.Disabled:
			longest = max(longest, m.Time.Sub(from))
			from = time.Time{}
		}
	}
	if !from.IsZero() { // never resumed: on hold until the end of the call
		longest = max(longest, c.End.Sub(from))
	}
	return longest > 0 && gap <= longest+slack
}

func streamFinding(c *call.Call, s *rtp.Stream, cfg Config) (Finding, bool) {
	if s.Packets < 10 {
		return Finding{}, false
	}
	var issues, hints []string
	sev := Warning
	bump := func(hard bool) {
		if hard {
			sev = Error
		}
	}
	if s.MOS > 0 && s.MOS < cfg.MinMOS {
		issues = append(issues, fmt.Sprintf("MOS %.1f", s.MOS))
		bump(s.MOS < 3.1)
		hints = append(hints, "low estimated MOS: look at loss and jitter below and at the codec (G.729 and narrowband codecs score lower)")
	}
	if s.LossPct > cfg.MaxLossPct {
		issues = append(issues, fmt.Sprintf("loss %.1f%%", s.LossPct))
		bump(s.LossPct >= 5*cfg.MaxLossPct)
		hints = append(hints, "packet loss: congested or lossy link, Wi-Fi, or a policer; compare captures on both sides of the path to see where it is lost and check DSCP/QoS")
	}
	if s.JitterMean > cfg.MaxJitter {
		issues = append(issues, "jitter "+dur(s.JitterMean))
		bump(s.JitterMean >= 3*cfg.MaxJitter)
		hints = append(hints, "high jitter: queueing on the path, Wi-Fi, CPU starvation on the sender or a transcoder; check QoS and the endpoint's load")
	}
	if s.MaxGap > cfg.MaxMediaGap && !gapExplainedByHold(c, s.MaxGap, cfg.MaxMediaGap) {
		issues = append(issues, "gap "+dur(s.MaxGap))
		bump(s.MaxGap >= 5*cfg.MaxMediaGap)
		hints = append(hints, "media gap: silence suppression without comfort noise, a stalled media process, a hold/resume or a network outage")
	}
	if len(issues) == 0 {
		return Finding{}, false
	}
	leg := s.Leg
	if leg == "" {
		leg = "uncorrelated"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s -> %s SSRC %#x (%s): %d packets", leg, s.Src, s.Dst, s.SSRC, codecName(s), s.Packets)
	fmt.Fprintf(&b, ", loss %.1f%% (%d lost)", s.LossPct, max(s.Lost, 0))
	fmt.Fprintf(&b, ", jitter mean %s max %s, max gap %s", dur(s.JitterMean), dur(s.JitterMax), dur(s.MaxGap))
	if s.MOS > 0 {
		fmt.Fprintf(&b, ", MOS %.1f (R %.0f)", s.MOS, s.RFactor)
	}
	if s.Reordered > 0 || s.Duplicates > 0 {
		fmt.Fprintf(&b, ", %d reordered, %d duplicates", s.Reordered, s.Duplicates)
	}
	if s.RTCP.Reports > 0 {
		fmt.Fprintf(&b, "; RTCP reports (%d): up to %.1f%% lost, jitter up to %s", s.RTCP.Reports, s.RTCP.MaxFractionLost, dur(s.RTCP.MaxJitter))
	}
	b.WriteString(". Measured at the capture point only.")

	var refs refSet
	refs.refs = append(refs.refs, Ref{File: s.File, Index: s.FirstIndex})
	f := Finding{
		Rule: "media-quality", Severity: sev, Time: s.Start,
		Title:   fmt.Sprintf("Poor media quality %s: %s", leg, strings.Join(issues, ", ")),
		Detail:  b.String(),
		Hint:    strings.Join(hints, "; ") + ".",
		Packets: refs.result(),
	}
	if c != nil {
		f.CallID = c.CallID
		if inv := initialInvite(c); inv != nil {
			refs.add(inv)
			f.Packets = refs.result()
		}
	}
	return f, true
}

func codecName(s *rtp.Stream) string {
	if s.Codec != "" {
		return s.Codec
	}
	return fmt.Sprintf("PT%d", s.PayloadType)
}
