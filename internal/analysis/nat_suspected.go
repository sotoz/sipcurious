package analysis

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/sotoz/sipcurious/internal/sdp"
)

func init() {
	Register(rule{
		id:    "nat-suspected",
		title: "NAT symptoms: private addresses announced by a public source, or media from another address",
		doc: "One finding per call that shows any of these symptoms:\n\n" +
			"- a **Contact** header with a private (RFC 1918, CGNAT, ULA), loopback or link-local host in a message whose packet " +
			"source is a public address;\n" +
			"- a request whose **Via** sent-by is private while the packet source is public, or a response going to a public address " +
			"whose Via is private and carries no `received` parameter, so the server did not correct it;\n" +
			"- **SDP** `c=` with a private address in a message whose packet source is public;\n" +
			"- RTP that reached a private announced endpoint but came from a different, public address (the NAT mapping), or " +
			"media announced as private by one side.\n\n" +
			"Severity: **warning** when signalling or SDP carries unusable private addresses (media or in-dialog requests probably " +
			"cannot reach the sender), **info** when only the media mapping shows NAT that was apparently handled (symmetric RTP).\n\n" +
			"Typical causes: no SIP ALG/SBC rewriting, missing `rport`, `received` ignored, no STUN/ICE, or a B2BUA that " +
			"copies the inside Contact/SDP to the outside. Fix with an SBC doing topology hiding and media latching, `rport`, " +
			"or NAT keep-alives and a correct external address configured in the UA.",
		check: checkNAT,
	})
}

func checkNAT(in *Input) []Finding {
	var out []Finding
	for i := range in.Calls {
		c := &in.Calls[i]
		var refs refSet
		var strong, weak []string
		seen := map[string]bool{}
		note := func(list *[]string, s string) {
			if !seen[s] {
				seen[s] = true
				*list = append(*list, s)
			}
		}
		for j := range c.Messages {
			m := &c.Messages[j]
			if !isPublic(m.Src) {
				continue
			}
			if m.Contact != "" && m.Method != "" {
				if a, err := netip.ParseAddr(uriHost(m.Contact)); err == nil && isLocal(a) {
					note(&strong, fmt.Sprintf("Contact %s in %s from public %s", strings.TrimSpace(m.Contact), m.Info(), m.Src))
					refs.add(m)
				}
			}
			if m.IsRequest {
				if a, err := netip.ParseAddr(viaHost(m.Via)); err == nil && isLocal(a) {
					note(&strong, fmt.Sprintf("Via %s in %s from public %s", a, m.Info(), m.Src))
					refs.add(m)
				}
			}
			if m.HeaderEnd > 0 && m.HeaderEnd < len(m.Raw) {
				if s, err := sdp.Parse(m.SDP()); err == nil {
					for _, md := range s.Media {
						if md.Port != 0 && isLocal(md.Addr) {
							note(&strong, fmt.Sprintf("SDP %s %s/%d in %s from public %s", md.Type, md.Addr, md.Port, m.Info(), m.Src))
							refs.add(m)
							break
						}
					}
				}
			}
		}
		for j := range c.Messages {
			m := &c.Messages[j]
			if m.IsRequest || !isPublic(m.Dst) {
				continue
			}
			if a, err := netip.ParseAddr(viaHost(m.Via)); err == nil && isLocal(a) {
				if _, ok := viaParam(m.Via, "received"); !ok {
					note(&strong, fmt.Sprintf("response %s goes to public %s but its Via %s has no received parameter", m.Info(), m.Dst, a))
					refs.add(m)
				}
			}
		}
		for k := range c.Streams {
			s := &c.Streams[k]
			for _, md := range c.Media {
				ann := md.Caller
				if s.Leg == "callee->caller" {
					ann = md.Callee
				}
				if ann.IsValid() && isLocal(ann.Addr()) && s.Src != ann && isPublic(s.Src.Addr()) {
					note(&weak, fmt.Sprintf("RTP %s comes from public %s although the SDP announced private %s (NAT mapping)", s.Leg, s.Src, ann))
					refs.refs = append(refs.refs, Ref{File: s.File, Index: s.FirstIndex})
					break
				}
			}
		}
		if len(strong) == 0 && len(weak) == 0 {
			continue
		}
		f := Finding{Rule: "nat-suspected", CallID: c.CallID, Time: c.Start, Packets: refs.result()}
		all := append(append([]string{}, strong...), weak...)
		f.Detail = joinMax(all, 6) + "."
		if len(strong) > 0 {
			f.Severity = Warning
			f.Title = fmt.Sprintf("NAT suspected for %s: %s", parties(c), shortNAT(strong[0]))
			f.Hint = "Private addresses leak to the public side, so in-dialog requests and media will go to unreachable addresses: enable rport/received handling, " +
				"NAT keep-alives and SIP ALG-free NAT traversal, or put an SBC with topology hiding and media latching in front of the device."
		} else {
			f.Severity = Info
			f.Title = fmt.Sprintf("NAT in the media path for %s: %s", parties(c), shortNAT(weak[0]))
			f.Hint = "Media still flows from the mapped address (symmetric RTP/latching works). If audio fails in one direction, check that the far side sends to the address RTP arrives from, not the private SDP address."
		}
		out = append(out, f)
	}
	return out
}

func shortNAT(s string) string {
	if i := strings.Index(s, " goes to "); i > 0 {
		return s[:i]
	}
	if i := strings.Index(s, " from public"); i > 0 {
		return s[:i] + " from a public source"
	}
	return s
}
