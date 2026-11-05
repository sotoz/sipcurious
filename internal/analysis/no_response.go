package analysis

import (
	"fmt"

	"github.com/sotoz/sipcurious/internal/call"
)

func init() {
	Register(rule{
		id:    "no-response",
		title: "A request never received any response",
		doc: "Reports every Call-ID (INVITE call, registration, OPTIONS, SUBSCRIBE...) whose state is `no-response`: " +
			"the request, with all its retransmissions, got no response at all. The finding names the number of attempts, " +
			"the destination the request was sent to and the time covered by the attempts.\n\n" +
			"Severity: **error** for INVITE and REGISTER (the service is down for that user), **warning** for the rest " +
			"(a missing OPTIONS answer usually means the peer is considered down by the sender).",
		check: checkNoResponse,
	})
}

func checkNoResponse(in *Input) []Finding {
	var out []Finding
	for i := range in.Calls {
		c := &in.Calls[i]
		if c.State != call.StateNoResponse {
			continue
		}
		var refs refSet
		reqs, last := 0, c.Start
		var dst string
		for j := range c.Messages {
			m := &c.Messages[j]
			if !m.IsRequest || m.Method == "ACK" {
				continue
			}
			if m.Method != c.Method {
				continue
			}
			if reqs == 0 {
				dst = m.DstAddr().String()
			}
			reqs++
			last = m.Time
			refs.add(m)
		}
		method := c.Method
		if method == "" {
			method = "request"
		}
		sev := Warning
		if c.Kind == call.KindCall || c.Kind == call.KindRegistration {
			sev = Error
		}
		attempts := c.Attempts
		if attempts == 0 {
			attempts = reqs
		}
		f := Finding{
			Rule: "no-response", Severity: sev, CallID: c.CallID, Time: c.Start,
			Title: fmt.Sprintf("%s to %s got no response (%s)", method, dst, plur(reqs, "transmission", "transmissions")),
			Detail: fmt.Sprintf("%s: %s sent %s over %s (%s, %s) and received nothing back.",
				parties(c), method, plur(reqs, "time", "times"), dur(last.Sub(c.Start)), plur(attempts, "attempt", "attempts"), ep(c.Callee)),
			Hint: fmt.Sprintf("Check that %s is the right destination and port, that the peer is up and listening on that transport, "+
				"and whether a firewall or ACL drops the packets. Capture on the peer to see whether the request arrives.", dst),
			Packets: refs.result(),
		}
		out = append(out, f)
	}
	return out
}
