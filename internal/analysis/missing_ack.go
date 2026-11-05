package analysis

import (
	"fmt"
	"net/netip"
	"strings"
)

func init() {
	Register(rule{
		id:    "missing-ack",
		title: "The 200 OK to an INVITE was not acknowledged (retransmitted 2xx, no ACK)",
		doc: "After a 2xx to INVITE the caller must send an ACK; until it arrives the callee retransmits the 200 OK (RFC 3261 " +
			"13.3.1.4) and finally tears the dialog down. The rule reports calls where the 2xx was retransmitted and no ACK for " +
			"it was captured. Typical causes: the ACK is sent to the wrong address (Contact or Record-Route ignored, NAT: the " +
			"Contact holds a private address), a firewall drops it, or the caller is gone.\n\n" +
			"Severity: **error**.",
		check: checkMissingACK,
	})
}

func checkMissingACK(in *Input) []Finding {
	var out []Finding
	for i := range in.Calls {
		c := &in.Calls[i]
		if !c.MissingACK {
			continue
		}
		var refs refSet
		n := 0
		var contact string
		var first, last = c.Answered, c.Answered
		for j := range c.Messages {
			m := &c.Messages[j]
			if !m.IsRequest && m.StatusCode >= 200 && m.StatusCode < 300 && strings.EqualFold(m.Method, "INVITE") {
				n++
				refs.add(m)
				if contact == "" {
					contact = m.Contact
				}
				last = m.Time
			}
		}
		hint := "The caller's ACK never showed up at this capture point: check that ACK follows the 200 OK's Contact and Record-Route (is the Contact address reachable from the caller?), NAT and firewall rules, and capture on the caller side to see whether the ACK was sent."
		if contact != "" {
			if h := uriHost(contact); h != "" {
				if a, err := netip.ParseAddr(h); err == nil && isLocal(a) {
					hint = "The 200 OK Contact (" + contact + ") holds a private address, so the ACK probably goes astray: fix Contact rewriting (SBC/NAT traversal). " + hint
				}
			}
		}
		out = append(out, Finding{
			Rule: "missing-ack", Severity: Error, CallID: c.CallID, Time: c.Answered,
			Title:   fmt.Sprintf("200 OK for %s sent %s without an ACK", parties(c), plur(n, "time", "times")),
			Detail:  fmt.Sprintf("The 200 OK to the INVITE was transmitted %d times over %s and no matching ACK was captured, so the call is not confirmed and will be torn down by the callee.", n, dur(last.Sub(first))),
			Hint:    hint,
			Packets: refs.result(),
		})
	}
	return out
}
