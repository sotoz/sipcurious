package analysis

import (
	"fmt"
	"strings"

	"github.com/sotoz/sipcurious/internal/call"
	"github.com/sotoz/sipcurious/internal/trace"
)

func init() {
	Register(rule{
		id:    "call-failed",
		title: "An INVITE was rejected with a 4xx, 5xx or 6xx final response",
		doc: "Reports every INVITE call whose state is `failed`, with the meaning of the status code, its typical causes and " +
			"what to check, taken from a built-in table covering 400-606. When the response (or the CANCEL/BYE) carries a Reason " +
			"header (RFC 3326) its cause is shown, and Q.850 causes 1, 16, 17, 18, 19, 21, 27, 28, 31, 34, 38, 41, 42 and 102 " +
			"are translated.\n\n" +
			"Severity: **warning** for failures that usually reflect a user or routing decision (404, 410, 480, 484, 486, 487 without CANCEL, 600, 603, 604); " +
			"**error** for everything else (5xx, 403, 488, 606...). A `487` that follows a CANCEL is a normal call abandon and reported as **info**.\n\n" +
			"A 401/407 challenge that was answered is not a failure; unanswered challenges are reported by `auth-failures`.",
		check: checkCallFailed,
	})
}

// userDecided are failure codes that normally reflect a user or routing decision rather than a fault.
var userDecided = map[int]bool{480: true, 486: true, 487: true, 600: true, 603: true, 410: true, 404: true, 484: true, 604: true}

func checkCallFailed(in *Input) []Finding {
	var out []Finding
	for i := range in.Calls {
		c := &in.Calls[i]
		if !isInviteCall(c) {
			continue
		}
		code := c.FinalCode
		cancelled := c.State == call.StateCancelled
		if !(c.State == call.StateFailed && code >= 400) && !(cancelled && code == 487) {
			continue
		}
		if c.State == call.StateFailed && (code == 401 || code == 407) {
			continue // auth-failures
		}
		info := Status(code)
		sev := Error
		switch {
		case cancelled:
			sev = Info
		case userDecided[code]:
			sev = Warning
		}
		var refs refSet
		for _, m := range []*trace.Message{initialInvite(c), finalResponse(c)} {
			if m != nil {
				refs.add(m)
			}
		}
		for j := range c.Messages {
			if m := &c.Messages[j]; m.IsRequest && m.Method == "CANCEL" {
				refs.add(m)
				break
			}
		}

		f := Finding{Rule: "call-failed", Severity: sev, CallID: c.CallID, Time: c.Start, Packets: refs.result()}
		if cancelled {
			f.Title = fmt.Sprintf("Call %s cancelled by the caller before answer (487)", parties(c))
			f.Detail = fmt.Sprintf("The caller sent CANCEL after %s of ringing/setup; the INVITE ended with 487 Request Terminated.", dur(c.Ended.Sub(c.Start)))
			f.Hint = "Normal when the caller hangs up. If callers cancel quickly, look at post-dial delay and ringing time (slow-setup)."
		} else {
			f.Title = fmt.Sprintf("Call %s failed: %d %s", parties(c), code, c.FinalReason)
			var b strings.Builder
			fmt.Fprintf(&b, "%s: %s.", c.Result, info.Meaning)
			if info.Causes != "" {
				b.WriteString(" Typical causes: " + info.Causes)
			}
			if src := c.Callee; src.IsValid() {
				fmt.Fprintf(&b, " The INVITE went to %s", src)
				if fr := finalResponse(c); fr != nil {
					fmt.Fprintf(&b, " and the rejection came from %s", fr.SrcAddr())
				}
				b.WriteString(".")
			}
			f.Detail = b.String()
			f.Hint = info.Check
		}
		if c.Reason != "" {
			f.Detail += " Reason: " + c.Reason + "."
			if proto, cause, text, ok := reasonCause(c.Reason); ok {
				if strings.EqualFold(proto, "Q.850") {
					if meaning := Q850(cause); meaning != "" {
						f.Detail += fmt.Sprintf(" Q.850 cause %d: %s.", cause, meaning)
					} else if text != "" {
						f.Detail += fmt.Sprintf(" Q.850 cause %d (%s).", cause, text)
					}
				}
			}
		}
		out = append(out, f)
	}
	return out
}
