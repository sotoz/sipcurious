package analysis

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/sotoz/sipcurious/internal/call"
	"github.com/sotoz/sipcurious/internal/trace"
)

func init() {
	Register(rule{
		id:    "sip-retransmissions",
		title: "A SIP message was retransmitted repeatedly (packet loss, wrong next hop, peer down)",
		doc: "SIP over UDP retransmits a request until a response arrives (RFC 3261 timers T1 = 500 ms, doubling up to T2 = 4 s) " +
			"and retransmits a final response until the request sender confirms it. The rule groups messages that repeat the " +
			"same method or status, CSeq, topmost Via branch, source and destination, and reports every group retransmitted at " +
			"least `MinRetransmits` times (default 2).\n\n" +
			"- **error**: a request that never got any response, not even `100 Trying`.\n" +
			"- **warning**: a request answered only after retransmissions, or a response that had to be retransmitted.\n\n" +
			"2xx responses to INVITE are handled by `missing-ack`. Typical causes: packet loss, a wrong next hop or port, a " +
			"firewall dropping the traffic, the peer being down, or a message too large for the path MTU.",
		check: checkRetransmissions,
	})
}

// txKey identifies the repeats of one message.
type txKey struct {
	resp     bool
	method   string
	code     int
	cseq     int
	branch   string
	toTag    string
	src, dst netip.AddrPort
}

type txGroup struct {
	key  txKey
	msgs []*trace.Message
}

func checkRetransmissions(in *Input) []Finding {
	min := in.Config.WithDefaults().MinRetransmits
	var out []Finding
	for i := range in.Calls {
		c := &in.Calls[i]
		if c.Retransmissions < min {
			continue
		}
		var groups []*txGroup
		idx := map[txKey]*txGroup{}
		for j := range c.Messages {
			m := &c.Messages[j]
			if m.Method == "ACK" && m.IsRequest {
				continue
			}
			if !m.IsRequest && m.StatusCode >= 200 && m.StatusCode < 300 && strings.EqualFold(m.Method, "INVITE") {
				continue // missing-ack
			}
			k := txKey{resp: !m.IsRequest, method: strings.ToUpper(m.Method), cseq: m.CSeqNumber(), branch: m.Branch(), src: m.SrcAddr(), dst: m.DstAddr()}
			if !m.IsRequest {
				k.code, k.toTag = m.StatusCode, m.ToTag()
			}
			g := idx[k]
			if g == nil {
				g = &txGroup{key: k}
				idx[k] = g
				groups = append(groups, g)
			}
			g.msgs = append(g.msgs, m)
		}
		for _, g := range groups {
			if n := len(g.msgs) - 1; n >= min {
				out = append(out, retransFinding(c, g, n))
			}
		}
	}
	return out
}

func retransFinding(c *call.Call, g *txGroup, n int) Finding {
	first := g.msgs[0]
	var refs refSet
	for _, m := range g.msgs {
		refs.add(m)
	}
	f := Finding{Rule: "sip-retransmissions", CallID: c.CallID, Time: first.Time}

	delays := make([]string, 0, n)
	for i := 1; i < len(g.msgs); i++ {
		delays = append(delays, dur(g.msgs[i].Time.Sub(g.msgs[i-1].Time)))
	}
	detail := fmt.Sprintf("%s -> %s; gaps between transmissions: %s.", first.SrcAddr(), first.DstAddr(), joinMax(delays, 8))

	if g.key.resp {
		f.Severity = Warning
		f.Title = fmt.Sprintf("%s to %s retransmitted %s", first.Info(), first.Method, plur(n, "time", "times"))
		f.Detail = detail + " The sender kept repeating the response, so it never saw the request retransmission stop or the ACK arrive."
		f.Hint = "The response probably did not reach the requester (loss, wrong destination, firewall) or its ACK was lost. " +
			"Compare Via received/rport with the address the response was sent to, and capture on the requester's side."
		f.Packets = refs.result()
		return f
	}

	var answer *trace.Message
	for j := range c.Messages {
		m := &c.Messages[j]
		if !m.IsRequest && m.CSeqNumber() == g.key.cseq && strings.EqualFold(m.Method, g.key.method) && !m.Time.Before(first.Time) {
			answer = m
			break
		}
	}
	if answer == nil {
		f.Severity = Error
		f.Title = fmt.Sprintf("%s retransmitted %s without any response", g.key.method, plur(n, "time", "times"))
		f.Detail = fmt.Sprintf("%s Retransmitted for %s and never answered, not even with 100 Trying.", detail, dur(g.msgs[len(g.msgs)-1].Time.Sub(first.Time)))
		f.Hint = fmt.Sprintf("The peer did not answer: check packet loss on the path, whether %s is the intended next hop and port, a firewall/NAT dropping the packets, or the peer being down.", first.DstAddr())
	} else {
		f.Severity = Warning
		f.Title = fmt.Sprintf("%s retransmitted %s before the first response", g.key.method, plur(n, "time", "times"))
		f.Detail = fmt.Sprintf("%s First response (%s) came %s after the request, from %s.", detail, answer.Info(), dur(answer.Time.Sub(first.Time)), answer.SrcAddr())
		f.Hint = "One direction lost packets or the peer was slow: check packet loss and latency on the path"
		if answer.Src != first.Dst {
			f.Hint += ", and why the response came from a different address than the request went to (asymmetric routing, NAT)"
		}
		f.Hint += "."
		refs.add(answer)
		f.Packets = refs.result()
	}
	if f.Packets == nil {
		f.Packets = refs.result()
	}
	if len(first.Raw) > 1300 {
		f.Hint += fmt.Sprintf(" The message is %d bytes: a UDP datagram that large may be dropped by the path MTU, consider TCP.", len(first.Raw))
	}
	return f
}
