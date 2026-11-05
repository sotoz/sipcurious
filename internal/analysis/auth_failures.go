package analysis

import (
	"fmt"
	"strings"

	"github.com/sotoz/sipcurious/internal/call"
	"github.com/sotoz/sipcurious/internal/trace"
)

func init() {
	Register(rule{
		id:    "auth-failures",
		title: "Authentication keeps failing (repeated 401/407/403, stale nonce loop, REGISTER never accepted)",
		doc: "A single 401/407 is the normal digest challenge. The rule reports:\n\n" +
			"- a Call-ID that was refused with 401, 407 or 403 **three or more times** (the client retries with credentials " +
			"that are rejected, or does not answer the challenge at all);\n" +
			"- a **stale nonce loop**: two or more challenges with `stale=true`, the client keeps using an expired nonce;\n" +
			"- a user (AoR) whose REGISTERs were refused three or more times over several Call-IDs and never got a 200.\n\n" +
			"Severity is **error** unless the request was finally accepted (then **warning**). Typical causes: wrong password or " +
			"realm, wrong auth user name versus From user, clock or nonce handling bugs, an IP-based ACL answering 403, " +
			"or a proxy that challenges every request because it cannot match the nonce (load-balanced servers without shared nonce state).",
		check: checkAuth,
	})
}

func isAuthCode(c int) bool { return c == 401 || c == 403 || c == 407 }

type authStats struct {
	challenges  []*trace.Message // 401/403/407 final responses
	stale       []*trace.Message
	credentials int // requests carrying Authorization/Proxy-Authorization
	accepted    bool
}

func scanAuth(c *call.Call) authStats {
	var st authStats
	for j := range c.Messages {
		m := &c.Messages[j]
		if m.IsRequest {
			if m.Method != "ACK" && (hdr(m, "Authorization") != "" || hdr(m, "Proxy-Authorization") != "") {
				st.credentials++
			}
			continue
		}
		switch {
		case isAuthCode(m.StatusCode):
			st.challenges = append(st.challenges, m)
			ch := hdr(m, "WWW-Authenticate")
			if ch == "" {
				ch = hdr(m, "Proxy-Authenticate")
			}
			if v, ok := authParam(ch, "stale"); ok && strings.EqualFold(v, "true") {
				st.stale = append(st.stale, m)
			}
		case m.StatusCode >= 200 && m.StatusCode < 300 && m.Method != "BYE" && m.Method != "CANCEL":
			st.accepted = true
		}
	}
	return st
}

// authParam finds name=value in a digest challenge.
func authParam(h, name string) (string, bool) {
	l := asciiLower(h) // strings.ToLower may change the length of invalid UTF-8
	for from := 0; ; {
		i := strings.Index(l[from:], name)
		if i < 0 {
			return "", false
		}
		i += from
		from = i + len(name)
		if i > 0 && (l[i-1] != ' ' && l[i-1] != ',') || from >= len(l) || l[from] != '=' {
			continue
		}
		v := h[from+1:]
		if j := strings.IndexByte(v, ','); j >= 0 {
			v = v[:j]
		}
		return strings.Trim(strings.TrimSpace(v), `"`), true
	}
}

func checkAuth(in *Input) []Finding {
	var out []Finding
	type aorStat struct {
		first      *call.Call
		calls      int
		challenges int
		ok         bool
		refs       refSet
		single     bool // one Call-ID alone was already reported
	}
	aors := map[string]*aorStat{}
	var order []string

	for i := range in.Calls {
		c := &in.Calls[i]
		st := scanAuth(c)
		reported := false
		n := len(st.challenges)

		if c.Kind == call.KindRegistration {
			key := uriCore(c.To)
			a := aors[key]
			if a == nil {
				a = &aorStat{first: c}
				aors[key] = a
				order = append(order, key)
			}
			a.calls++
			a.challenges += n
			a.ok = a.ok || st.accepted
			for _, m := range st.challenges {
				a.refs.add(m)
			}
		}

		if n >= 3 || len(st.stale) >= 2 {
			reported = true
			f := Finding{Rule: "auth-failures", Severity: Error, CallID: c.CallID, Time: st.challenges[0].Time}
			var refs refSet
			for _, m := range st.challenges {
				refs.add(m)
			}
			codes := make([]string, len(st.challenges))
			for k, m := range st.challenges {
				codes[k] = fmt.Sprint(m.StatusCode)
			}
			who := c.FromUser
			if c.Kind == call.KindRegistration {
				who = c.ToUser
			}
			switch {
			case len(st.stale) >= 2:
				f.Title = fmt.Sprintf("Stale nonce loop for %s: %d challenges with stale=true", who, len(st.stale))
				f.Hint = "The client does not use the fresh nonce from the challenge: check its digest implementation, and on the server side that every node of a cluster accepts nonces issued by the others."
			case st.credentials == 0:
				f.Title = fmt.Sprintf("%s refused %d times, the client never sent credentials", who, n)
				f.Hint = "The client does not answer the challenge: check that it has credentials configured for this realm and supports digest authentication."
			default:
				f.Title = fmt.Sprintf("Authentication for %s refused %d times (%s)", who, n, strings.Join(codes, ", "))
				f.Hint = "The credentials are rejected: check password, realm and auth user name (it may differ from the From user), and on a 403 the server's IP ACL and account state."
			}
			f.Detail = fmt.Sprintf("%s %s: %s challenged/refused with %s; the client sent credentials %s; %s.",
				c.Method, c.CallID, plur(n, "response", "responses"), strings.Join(codes, ", "), plur(st.credentials, "time", "times"), outcome(c, st))
			if st.accepted {
				f.Severity = Warning
			}
			f.Packets = refs.result()
			out = append(out, f)
		}
		if reported {
			if a := aors[uriCore(c.To)]; a != nil && c.Kind == call.KindRegistration {
				a.single = true
			}
		}
	}
	for _, key := range order {
		a := aors[key]
		if a.single || a.ok || a.calls < 2 || a.challenges < 3 {
			continue
		}
		c := a.first
		out = append(out, Finding{
			Rule: "auth-failures", Severity: Error, CallID: c.CallID, Time: c.Start,
			Title:   fmt.Sprintf("REGISTER for %s refused %d times over %d Call-IDs, never accepted", c.ToUser, a.challenges, a.calls),
			Detail:  fmt.Sprintf("%s: %d challenge/refusal responses (401/403/407) across %d REGISTER Call-IDs and no 200 OK.", key, a.challenges, a.calls),
			Hint:    "The device re-registers from scratch each time and fails: check its password, realm and auth user, and on a 403 the server-side IP ACL and account state.",
			Packets: a.refs.result(),
		})
	}
	return out
}

func outcome(c *call.Call, st authStats) string {
	if st.accepted {
		return "eventually accepted"
	}
	if c.FinalCode != 0 {
		return "final result " + c.Result
	}
	return "never accepted"
}

// asciiLower lower-cases ASCII letters only, keeping every byte offset.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}
