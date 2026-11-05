package analysis

import (
	"fmt"
	"strings"

	"github.com/sotoz/sipcurious/internal/call"
	"github.com/sotoz/sipcurious/internal/sdp"
)

func init() {
	Register(rule{
		id:    "sdp-mismatch",
		title: "Offer and answer do not fit: 488/606, no common codec or every media line rejected",
		doc: "Reports three situations in INVITE calls, each with the offered codecs next to the answered or acceptable ones:\n\n" +
			"- the INVITE was rejected with **488 Not Acceptable Here** or **606 Not Acceptable** (the response's own SDP and Warning " +
			"header, which often name the acceptable parameters, are shown);\n" +
			"- the call was answered but the answer contains **no codec from the offer** (telephone-event and comfort noise do not count), so " +
			"the endpoints cannot understand each other's audio;\n" +
			"- the call was answered but **every media line was rejected** with port 0.\n\n" +
			"Severity: **error**. Typical causes: mismatched codec lists (a trunk that only takes G.729 or only G.711), SRTP offered " +
			"to a plain-RTP peer or the other way round (`RTP/SAVP` against `RTP/AVP`), unsupported ptime, or a B2BUA that stripped codecs.",
		check: checkSDPMismatch,
	})
	Register(rule{
		id:    "codec-change",
		title: "The negotiated audio codec changed during the call",
		doc: "Reports calls where the first negotiated codec of the audio stream differs between two successive negotiations: " +
			"early media (183) that used another codec than the final answer, or a re-INVITE/UPDATE that switched codec (fax/T.38 fallback " +
			"aside, which shows as a media type change and is ignored). Severity: **info**.\n\n" +
			"A codec change mid-call is legal but a frequent cause of clipped audio, transcoding load and one-way audio when one " +
			"side does not switch its encoder. Check that both sides really switched when the audio sounds wrong.",
		check: checkCodecChange,
	})
}

// realCodecs removes telephone-event and comfort noise.
func realCodecs(names []string) []string {
	var out []string
	for _, n := range names {
		l := strings.ToLower(n)
		if l == "telephone-event" || l == "cn" || strings.HasPrefix(l, "telephone-event") {
			continue
		}
		out = append(out, l)
	}
	return out
}

func overlaps(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			if x == y {
				return true
			}
		}
	}
	return false
}

func checkSDPMismatch(in *Input) []Finding {
	var out []Finding
	for i := range in.Calls {
		c := &in.Calls[i]
		if !isInviteCall(c) {
			continue
		}
		switch {
		case c.State == call.StateFailed && (c.FinalCode == 488 || c.FinalCode == 606):
			out = append(out, rejectedSDP(c))
		case answered(c):
			if f, ok := answeredMismatch(c); ok {
				out = append(out, f)
			}
		}
	}
	return out
}

func rejectedSDP(c *call.Call) Finding {
	var refs refSet
	inv := initialInvite(c)
	fr := finalResponse(c)
	var offered []string
	var offerProto string
	if inv != nil {
		refs.add(inv)
		if s, err := sdp.Parse(inv.SDP()); err == nil {
			for _, m := range s.Media {
				if m.Type == "audio" {
					offered = m.Codecs()
					offerProto = m.Proto
					break
				}
			}
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s: INVITE offered", c.Result)
	if len(offered) > 0 {
		fmt.Fprintf(&b, " audio %s [%s]", offerProto, strings.Join(offered, ", "))
	} else {
		b.WriteString(" no audio SDP that could be parsed (delayed offer or no SDP)")
	}
	hint := "Compare the offered codecs, media profile (RTP/AVP vs RTP/SAVP) and ptime with what the callee supports."
	if fr != nil {
		refs.add(fr)
		fmt.Fprintf(&b, "; the %d came from %s", fr.StatusCode, fr.SrcAddr())
		if w := hdr(fr, "Warning"); w != "" {
			fmt.Fprintf(&b, " with Warning: %s", w)
		}
		if s, err := sdp.Parse(fr.SDP()); err == nil && len(s.Media) > 0 {
			fmt.Fprintf(&b, "; acceptable per its SDP: %s %s [%s]", s.Media[0].Type, s.Media[0].Proto, strings.Join(s.Media[0].Codecs(), ", "))
			hint = "The rejection lists what the callee accepts: offer one of those codecs."
		}
	}
	b.WriteString(".")
	return Finding{
		Rule: "sdp-mismatch", Severity: Error, CallID: c.CallID, Time: c.Start,
		Title:   fmt.Sprintf("Call %s rejected for its media description: %s", parties(c), c.Result),
		Detail:  b.String(),
		Hint:    hint,
		Packets: refs.result(),
	}
}

func answeredMismatch(c *call.Call) (Finding, bool) {
	if len(c.Media) == 0 {
		return Finding{}, false
	}
	allOff := true
	for _, m := range c.Media {
		if !m.Disabled {
			allOff = false
		}
	}
	var refs refSet
	if inv := initialInvite(c); inv != nil {
		refs.add(inv)
	}
	if allOff {
		for _, m := range c.Media {
			refs.addAt(c, m.Time)
		}
		return Finding{
			Rule: "sdp-mismatch", Severity: Error, CallID: c.CallID, Time: c.Answered,
			Title:   fmt.Sprintf("Call %s answered but every media line was rejected (port 0)", parties(c)),
			Detail:  fmt.Sprintf("%s: the 200 OK carries %s, all with port 0, so no media can flow. Offered: [%s].", parties(c), plur(len(c.Media), "media line", "media lines"), strings.Join(c.Media[0].Offered, ", ")),
			Hint:    "The callee refused all media: check supported codecs and media types (video-only offer to an audio device?) and the SRTP/RTP profile.",
			Packets: refs.result(),
		}, true
	}
	for _, m := range c.Media {
		if m.Type != "audio" || m.Disabled || m.Early {
			continue
		}
		offered, got := realCodecs(m.Offered), realCodecs(m.Codecs)
		if len(offered) == 0 || overlaps(offered, got) {
			continue
		}
		refs.addAt(c, m.Time)
		return Finding{
			Rule: "sdp-mismatch", Severity: Error, CallID: c.CallID, Time: m.Time,
			Title: fmt.Sprintf("Call %s answered with a codec that was not offered", parties(c)),
			Detail: fmt.Sprintf("Offered audio [%s], answered [%s]: no codec in common. The endpoints will exchange audio the other side cannot decode.",
				strings.Join(m.Offered, ", "), strings.Join(m.Codecs, ", ")),
			Hint:    "The callee answered with a codec outside the offer: a broken media stack or a B2BUA that rewrote the SDP; check the answering device's codec configuration.",
			Packets: refs.result(),
		}, true
	}
	return Finding{}, false
}

func checkCodecChange(in *Input) []Finding {
	var out []Finding
	for i := range in.Calls {
		c := &in.Calls[i]
		if !isInviteCall(c) {
			continue
		}
		var prev *call.Media
		var changes []string
		var refs refSet
		var at = c.Start
		for k := range c.Media {
			m := &c.Media[k]
			if m.Type != "audio" || m.Disabled || len(realCodecs(m.Codecs)) == 0 {
				continue
			}
			if prev != nil {
				if a, b := realCodecs(prev.Codecs)[0], realCodecs(m.Codecs)[0]; a != b {
					if len(changes) == 0 {
						at = m.Time
					}
					changes = append(changes, fmt.Sprintf("%s -> %s at %s", realCodecs(prev.Codecs)[0], realCodecs(m.Codecs)[0], m.Time.UTC().Format("15:04:05.000")))
					refs.addAt(c, prev.Time)
					refs.addAt(c, m.Time)
				}
			}
			prev = m
		}
		if len(changes) == 0 {
			continue
		}
		out = append(out, Finding{
			Rule: "codec-change", Severity: Info, CallID: c.CallID, Time: at,
			Title:   fmt.Sprintf("Audio codec changed during call %s: %s", parties(c), changes[0]),
			Detail:  fmt.Sprintf("Codec changes: %s.", strings.Join(changes, "; ")),
			Hint:    "If the audio sounds wrong after the change, check that both endpoints switched encoder and decoder; unexpected changes come from re-INVITEs of an SBC or PBX (transcoding) or from early media on another codec.",
			Packets: refs.result(),
		})
	}
	return out
}
