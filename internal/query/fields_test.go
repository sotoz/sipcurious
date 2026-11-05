package query

import (
	"strings"
	"testing"
	"time"

	"github.com/sotoz/sipcurious/internal/call"
	"github.com/sotoz/sipcurious/internal/rtp"
	"github.com/sotoz/sipcurious/internal/trace"
)

func mustParse(t testing.TB, src string, cs bool) *Query {
	t.Helper()
	q, err := Parse(src, Options{CaseSensitive: cs})
	if err != nil {
		t.Fatalf("Parse(%q): %v", src, err)
	}
	return q
}

type matchCase struct {
	src  string
	want bool
}

func runMsgCases(t *testing.T, m trace.Message, c *call.Call, cases []matchCase) {
	t.Helper()
	for _, tc := range cases {
		q := mustParse(t, tc.src, false)
		if got := q.MatchMessage(m, c); got != tc.want {
			t.Errorf("MatchMessage(%q) = %v, want %v (normal form %s)", tc.src, got, tc.want, q)
		}
		// Message-only queries agree through MatchCall on a one-message call.
		if !q.NeedsCalls() {
			cc := &call.Call{Messages: []trace.Message{m}, Start: m.Time}
			if got := q.MatchCall(cc); got != tc.want {
				t.Errorf("MatchCall(%q) = %v, want %v", tc.src, got, tc.want)
			}
		}
	}
}

// Every message field, on a request and a response.
func TestMessageFields(t *testing.T) {
	req := sm{at: 90 * time.Minute, method: "INVITE", src: "10.1.2.3:5070", dst: "[2001:db8::7]:5061", transp: "TCP",
		from: "alice", to: "+4930123", fromTag: "ftag99", branch: "z9hG4bKabc", callID: "cid-42@pbx",
		ua: "Yealink SIP-T46 1.2", sdp: sdpPCMA, extra: []string{"Subject: Urgent Call", "X-Account: 4711", "P-Asserted-Identity: <sip:alice@x>"}}.msg(17)
	rsp := sm{at: time.Second, method: "", code: 486, reason: "Busy Here", cseqM: "INVITE", src: "10.0.0.2:5060", dst: "10.0.0.1:5060",
		toTag: "tt77", server: "FreeSWITCH"}.msg(3)

	t.Run("request", func(t *testing.T) {
		runMsgCases(t, req, nil, []matchCase{
			{"method = INVITE", true}, {"method = invite", true}, {"method = BYE", false}, {"method in (BYE, INVITE)", true},
			{"method != INVITE", false}, {"method ~ INV", true},
			{"status = 200", false}, {"status != 200", true}, {"status >= 0", false}, {"status = 4xx", false}, {"status != 4xx", true},
			{"code < 1000", false},
			{"uri = sip:+4930123@example.com", true}, {"uri ~ +4930", true}, {"ruri ~ nothing", false},
			{"callid = cid-42@pbx", true}, {"call_id ~ CID-42", true}, {"callid = cid-42", false}, {"callid ~ 42@", true},
			{"from ~ alice", true}, {"from ~ ALICE", true}, {"from = alice", false}, {"to ~ 4930", true},
			{"from_user = alice", true}, {"from_user = ALICE", true}, {"from_user ~ lic", true}, {"to_user = +4930123", true}, {"to_user = 4930123", false},
			{"from_tag = ftag99", true}, {"from_tag ~ tag", true}, {"to_tag = ''", true}, {"to_tag ~ x", false}, {"to_tag != ''", false},
			{"contact ~ 10.1.2.3", true}, {"contact ~ sip:alice@", true},
			{"cseq = '1 INVITE'", true}, {"cseq ~ invite", true},
			{"via ~ 10.1.2.3:5070", true}, {"via ~ tcp", true}, {"branch = z9hG4bKabc", true}, {"branch ~ ABC", true}, {"branch = other", false},
			{"src = 10.1.2.3", true}, {"src = 10.1.2.4", false}, {"src = 10.0.0.0/8", true}, {"src in 10.1.2.0/24", true},
			{"src in (192.168.0.0/16, 10.1.0.0/16)", true}, {"src in (192.168.0.0/16, 172.16.0.0/12)", false}, {"src not in 10.0.0.0/8", false},
			{"src != 10.1.2.3", false}, {"src != 10.0.0.0/8", false}, {"src = 2001:db8::/32", false}, {"src_ip = 10.1.2.3", true},
			{"dst = 2001:db8::7", true}, {"dst = 2001:db8::/32", true}, {"dst in (2001:db8:1::/48, 10.0.0.0/8)", false}, {"dst = 2001:DB8:0:0:0:0:0:7", true},
			{"dst = 10.0.0.0/8", false}, {"dst_ip = ::1", false}, {"dst != 2001:db8::/32", false},
			{"sport = 5070", true}, {"sport > 5070", false}, {"sport >= 5070", true}, {"src_port in 5060..5070", true}, {"sport = 5060", false},
			{"dport = 5061", true}, {"dport in (5060, 5061)", true}, {"dst_port < 5061", false},
			{"transport = tcp", true}, {"transport = TCP", true}, {"transport = udp", false}, {"transport in (udp, tcp)", true}, {"transport != udp", true},
			{"time > 2026-03-01T13:00:00Z", true}, {"time > 2026-03-01T13:30:00Z", false}, {"time >= 2026-03-01T13:30:00Z", true},
			{"time = 2026-03-01T13:30:00Z", true}, {"time < 2026-03-01 13:30:01", true}, {"time = 2026-03-01", true}, {"time = 2026-03-02", false},
			{"time = 2026-03-01 13:30", true}, {"time = 2026-03-01 13:31", false}, {"time = 2026-03-01T14:30:00+01:00", true},
			{"time >= 13:30", true}, {"time > 13:30", false}, {"time = 13:30", true}, {"time = 13:30:00", true}, {"time = 13:30:01", false},
			{"time in 13:00..14:00", true}, {"time in 14:00..15:00", false}, {"time < 14:00", true},
			{"ua ~ yealink", true}, {"ua ~ freeswitch", false}, {"ua = 'Yealink SIP-T46 1.2'", true},
			{"is_request", true}, {"is_response", false}, {"is_request = false", false}, {"not is_response", true}, {"is_request = true and is_response = false", true},
			{"has_sdp", true}, {"has_sdp = false", false}, {"not has_sdp", false},
			{"file = t.pcap", true}, {"file ~ PCAP", true}, {"file ~ other", false},
			{"index = 17", true}, {"index > 16", true}, {"index in 10..20", true}, {"index in (1, 2, 3)", false}, {"index < 17", false},
			{"raw ~ 'a=sendonly'", true}, {"raw ~ sendrecv", false}, {"body ~ a=sendonly", true}, {"body ~ 'INVITE sip'", false}, {"raw ~ 'INVITE sip'", true},
			{`"a=sendonly"`, true}, {"sendrecv", false}, {"'Call-ID: cid-42@pbx'", true}, {"urgent", true},
			{"header.Subject ~ urgent", true}, {"h.subject = 'Urgent Call'", true}, {"h.SUBJECT ~ call", true}, {"header.Subject", true},
			{"header.X-Account = 4711", true}, {"h.x-account in (4711, 4712)", true}, {"h.X-Missing", false}, {"h.X-Missing = ''", true}, {"h.X-Missing != x", true}, {"h.X-Missing ~ x", false},
			{"h.i = cid-42@pbx", true}, {"h.f ~ alice", true}, {"h.t ~ 4930", true}, {"header.Call-ID = cid-42@pbx", true}, {"h.v ~ TCP", true}, {"h.c = application/sdp", true},
			{"h.p-asserted-identity ~ alice", true}, {"h.user-agent ~ yealink", true},
		})
	})
	t.Run("response", func(t *testing.T) {
		runMsgCases(t, rsp, nil, []matchCase{
			{"is_response", true}, {"is_request", false}, {"has_sdp", false},
			{"status = 486", true}, {"status = 4xx", true}, {"status = 4XX", true}, {"status = 5xx", false}, {"status != 4xx", false},
			{"status in (404, 4xx)", true}, {"status in (500..599)", false}, {"status in 400..499", true}, {"status >= 400 and status < 500", true},
			{"code = 486", true}, {"status > 486", false}, {"status < 487", true},
			{"method = INVITE", true}, // taken from CSeq
			{"uri = ''", true}, {"uri ~ sip", false},
			{"to_tag = tt77", true}, {"to_tag ~ 77", true},
			{"ua ~ freeswitch", true}, {"ua = FreeSWITCH", true}, {"ua ~ yealink", false},
			{"time = 12:00:01", true}, {"time >= 12:00", true},
			{"raw ~ 'Busy Here'", true}, {"'SIP/2.0 486'", true},
			{"src = 10.0.0.2", true}, {"dst = 10.0.0.1", true},
		})
	})
}

func TestNullSemantics(t *testing.T) {
	// A null Value matches no comparison; negated comparisons are true for it.
	var invalid trace.Message
	invalid.IsRequest = true
	runMsgCases(t, invalid, nil, []matchCase{
		{"time > 2000-01-01", false}, {"time < 2100-01-01", false}, {"time != 2000-01-01", true}, {"time not in 10:00..11:00", true}, {"time >= 00:00", false},
		{"src = 10.0.0.0/8", false}, {"src != 10.0.0.0/8", true}, {"src not in (10.0.0.0/8)", true}, {"dst in ::/0", false},
		{"status = 200", false}, {"status != 200", true}, {"status not in (1, 2)", true}, {"status < 1000", false},
		{"method = ''", true}, {"callid = ''", true},
	})
}

func TestStatusClassShorthand(t *testing.T) {
	for _, tc := range []struct {
		code int
		src  string
		want bool
	}{
		{199, "status = 1xx", true}, {100, "status = 1xx", true}, {200, "status = 1xx", false},
		{200, "status = 2xx", true}, {299, "status = 2xx", true}, {300, "status = 2xx", false},
		{302, "status = 3xx", true}, {404, "status = 4xx", true}, {503, "status = 5xx", true}, {600, "status = 6xx", true}, {699, "status = 6xx", true},
		{404, "status != 4xx", false}, {200, "status != 4xx", true}, {404, "status in (5xx, 4xx)", true}, {404, "status not in (5xx, 4xx)", false},
	} {
		m := sm{code: tc.code, cseqM: "INVITE"}.msg(1)
		if got := mustParse(t, tc.src, false).MatchMessage(m, nil); got != tc.want {
			t.Errorf("%d: %q = %v, want %v", tc.code, tc.src, got, tc.want)
		}
	}
	for _, bad := range []string{"status = 0xx", "status = 4x", "status = 45x"} {
		if _, err := Parse(bad, Options{}); err == nil {
			t.Errorf("Parse(%q) succeeded", bad)
		}
	}
	// final_code accepts classes too; other int fields do not.
	if _, err := Parse("final_code = 5xx", Options{}); err != nil {
		t.Errorf("final_code = 5xx: %v", err)
	}
	if _, err := Parse("sport = 5xx", Options{}); err == nil {
		t.Error("sport = 5xx parsed")
	}
}

func TestCaseSwitch(t *testing.T) {
	m := sm{method: "INVITE", from: "Alice", ua: "Cisco"}.msg(1)
	tests := []struct {
		src       string
		ci, cs    bool
		skipCS    bool
		skipCINeg bool
	}{
		{src: "from_user = alice", ci: true, cs: false},
		{src: "from_user = Alice", ci: true, cs: true},
		{src: "ua ~ cisco", ci: true, cs: false},
		{src: "ua ~ Cisco", ci: true, cs: true},
		{src: "ua !~ cisco", ci: false, cs: true},
		{src: "ua =~ '^cisco$'", ci: true, cs: false},
		{src: "ua =~ '^Cisco$'", ci: true, cs: true},
		{src: "ua in (cisco, x)", ci: true, cs: false},
		{src: "cisco", ci: true, cs: false},
		{src: "Cisco", ci: true, cs: true},
		{src: "method = invite", ci: true, cs: false},
		{src: "method = INVITE", ci: true, cs: true},
		{src: "ua =~ '(?i)^cisco$'", ci: true, cs: true},
	}
	for _, tc := range tests {
		if got := mustParse(t, tc.src, false).MatchMessage(m, nil); got != tc.ci {
			t.Errorf("insensitive %q = %v, want %v", tc.src, got, tc.ci)
		}
		if got := mustParse(t, tc.src, true).MatchMessage(m, nil); got != tc.cs {
			t.Errorf("sensitive %q = %v, want %v", tc.src, got, tc.cs)
		}
	}
	// Enums stay case-insensitive.
	c := answeredCall(t)
	if !mustParse(t, "state = COMPLETED", true).MatchCall(c) {
		t.Error("enum should ignore CaseSensitive")
	}
	// The option survives String().
	q := mustParse(t, "from ~ Alice", true)
	if q2 := mustParse(t, q.String(), true); !q2.MatchMessage(m, nil) || mustParse(t, "from ~ alice", true).MatchMessage(m, nil) {
		t.Error("case-sensitive normal form changed meaning")
	}
}

func TestUnicode(t *testing.T) {
	m := sm{method: "INVITE", ua: "Телефон Ünïcode ΣΊΣΥΦΟΣ İstanbul K\u212Aelvin ſtrasse"}.msg(1)
	for _, tc := range []matchCase{
		{"ua ~ телефон", true}, {"ua ~ ТЕЛЕФОН", true}, {"ua ~ ünïcode", true}, {"ua ~ ÜNÏCODE", true}, {"ua ~ σίσυφοσ", true},
		{"ua ~ σίσυφος", true}, {"ua ~ kelvin", true}, {"ua ~ KELVIN", true}, {"ua ~ strasse", true}, {"ua ~ STRASSE", true},
		{"ua = 'телефон ünïcode σίσυφος i̇stanbul'", false}, {"ua ~ 'Ünïcode Σ'", true}, {"телефон", true}, {"ТЕЛЕФОН", true},
		{"ua ~ 'ünï' and ua ~ 'ſtr'", true}, {"ua ~ ü", true}, {"ua ~ ï", true}, {"ua !~ ü", false},
	} {
		got := mustParse(t, tc.src, false).MatchMessage(m, nil)
		if got != tc.want {
			t.Errorf("%q = %v, want %v", tc.src, got, tc.want)
		}
	}
	if mustParse(t, "ua ~ телефон", true).MatchMessage(m, nil) {
		t.Error("case-sensitive match should fail")
	}
}

// Call fields on a call (MatchCall) and on a message with a call context.
func TestCallFields(t *testing.T) {
	c := answeredCall(t)
	rtpGood := rtp.Stream{Codec: "PCMA", MOS: 4.2, LossPct: 0.5, JitterMean: 4 * time.Millisecond}
	rtpBad := rtp.Stream{Codec: "PCMU", MOS: 2.9, LossPct: 7.5, JitterMean: 45 * time.Millisecond}
	media := withStreams(c, rtpGood, rtpBad)

	cases := []matchCase{
		{"state = completed", true}, {"state = COMPLETED", true}, {"state = failed", false}, {"state != failed", true}, {"state in (failed, completed)", true}, {"state not in (completed)", false},
		{"kind = call", true}, {"kind = registration", false}, {"kind in (call, options)", true},
		{"result ~ Reason", true}, {"result = '200 Reason'", true}, {"result ~ busy", false},
		{"final_code = 200", true}, {"final_code = 2xx", true}, {"final = 200", true}, {"final_code >= 400", false}, {"final_code in (200, 486)", true},
		{"duration > 30s", true}, {"duration > 34s", false}, {"duration < 33.1s", false}, {"duration <= 33100ms", true}, {"duration = 33s100ms", true}, {"duration in 30s..40s", true}, {"duration > 30", true},
		{"pdd = 2s", true}, {"pdd > 1s and pdd < 3s", true}, {"pdd > 3s", false},
		{"ring_time = 1s", true}, {"ring_time > 500ms", true},
		{"setup_time = 3s", true}, {"setup_time > 5s", false},
		{"talk_time = 30s", true}, {"talk_time < 5s", false},
		{"ended_by = callee", true}, {"ended_by = caller", false}, {"ended_by != caller", true},
		{"end_method = BYE", true}, {"end_method = bye", true}, {"end_method = CANCEL", false},
		{"reason ~ q.850", true}, {"reason ~ cause=16", true}, {"reason ~ cause=17", false},
		{"retransmissions = 0", true}, {"retrans >= 1", false}, {"retransmissions < 3", true},
		{"msgs = 7", true}, {"messages > 6", true}, {"msgs > 100", false}, {"msgs in 5..10", true},
		{"codec = PCMA", true}, {"codec = pcma", true}, {"codec ~ cma", true}, {"codec = G729", false}, {"codec != G729", true},
		{"user_agent ~ cisco", true}, {"user_agent ~ asterisk", true}, {"user_agent = 'Asterisk PBX 18'", true}, {"user_agent ~ yealink", false}, {"user_agent !~ cisco", false},
		{"start = 2026-03-01 12:00:00", true}, {"start >= 12:00", true}, {"start > 12:00", false}, {"start < 12:00:01", true}, {"start > 2026-02-28", true},
		{"end = 12:00:33", true}, {"end > 12:00:30 and end < 12:01", true}, {"end > 12:01", false}, {"end < 2026-03-01T12:00:34Z", true},
		{"caller = 10.0.0.1", true}, {"caller in 10.0.0.0/24", true}, {"caller in 192.168.0.0/16", false}, {"callee = 10.0.0.2", true}, {"callee != 10.0.0.2", false},
		{"has_media", false}, {"not has_media", true}, {"has_media = false", true},
		{"mos < 3.5", false}, {"mos != 4", true}, {"loss > 1", false}, {"jitter > 30ms", false}, {"mos >= 0", false}, {"loss = 0", false},
	}
	t.Run("MatchCall", func(t *testing.T) {
		for _, tc := range cases {
			q := mustParse(t, tc.src, false)
			if !q.NeedsCalls() {
				t.Errorf("%q: NeedsCalls = false", tc.src)
			}
			if got := q.MatchCall(c); got != tc.want {
				t.Errorf("MatchCall(%q) = %v, want %v (%s)", tc.src, got, tc.want, q)
			}
		}
	})
	t.Run("MatchMessage with call", func(t *testing.T) {
		for _, tc := range cases {
			q := mustParse(t, tc.src, false)
			if got := q.MatchMessage(c.Messages[0], c); got != tc.want {
				t.Errorf("MatchMessage(%q) = %v, want %v", tc.src, got, tc.want)
			}
			// nil call: every call-field comparison is false, negations included.
			if neg := strings.Contains(tc.src, "not ") || strings.Contains(tc.src, "!"); !neg && q.MatchMessage(c.Messages[0], nil) {
				t.Errorf("MatchMessage(%q, nil) = true", tc.src)
			}
		}
	})
	t.Run("media", func(t *testing.T) {
		for _, tc := range []matchCase{
			{"has_media", true}, {"not has_media", false}, {"mos < 3.5", true}, {"mos < 2.9", false}, {"mos = 2.9", true}, {"mos > 4", false},
			{"loss > 7", true}, {"loss = 7.5", true}, {"loss > 8", false}, {"jitter > 40ms", true}, {"jitter = 45ms", true}, {"jitter > 50ms", false},
			{"codec = PCMU", true}, {"codec = PCMA", true}, {"codec = opus", false}, {"mos < 3.5 and loss > 5 and has_media", true},
		} {
			if got := mustParse(t, tc.src, false).MatchCall(media); got != tc.want {
				t.Errorf("%q = %v, want %v", tc.src, got, tc.want)
			}
		}
	})
	t.Run("null call values", func(t *testing.T) {
		empty := &call.Call{CallID: "x", Kind: call.KindOptions, State: call.StateNoResponse}
		for _, tc := range []matchCase{
			{"pdd > 0s", false}, {"pdd < 1h", false}, {"pdd != 1s", true}, {"final_code = 200", false}, {"final_code != 200", true},
			{"duration > 0s", false}, {"start > 2000-01-01", false}, {"caller = 10.0.0.1", false}, {"caller != 10.0.0.1", true},
			{"msgs = 0", true}, {"state = no-response", true}, {"kind = options", true}, {"ended_by = ''", true}, {"user_agent = ''", true},
			{"mos < 5", false}, {"mos != 3", true}, {"codec = ''", true}, {"not has_media", true},
		} {
			if got := mustParse(t, tc.src, false).MatchCall(empty); got != tc.want {
				t.Errorf("%q = %v, want %v", tc.src, got, tc.want)
			}
		}
	})
}

// Message fields inside MatchCall are existential; call fields are not.
func TestExistentialSemantics(t *testing.T) {
	c := answeredCall(t)
	tests := []matchCase{
		{"status = 180", true}, {"status = 200", true}, {"status = 486", false},
		{"status >= 500", false}, {"status = 4xx", false}, {"status = 2xx", true},
		{"method = BYE", true}, {"method = REGISTER", false}, {"method in (REGISTER, BYE)", true},
		{"from_user = bob and from_user = alice", true}, // different messages
		{"from_user = bob and status = 180", true},
		{"status = 180 and status = 200", true}, // two messages
		{"method = BYE and status = 100", true},
		{"status != 200", true},     // some message is not 200 (requests included)
		{"not status = 200", false}, // no message has 200
		{"not status >= 500", true}, // no message has 5xx
		{"not (status >= 500 or status = 486)", true},
		{"status = 180 and not status = 486", true},
		{"src = 10.0.0.1 and dst = 10.0.0.1", true},
		{"src = 10.0.0.9", false},
		{"src in 10.0.0.0/24 and sport = 5060", true},
		{"ua ~ cisco", true}, {"ua ~ asterisk", true}, {"ua ~ yealink", false},
		{"has_sdp", true}, {"is_response and has_sdp", true},
		{"h.reason ~ q.850", true}, {"header.Reason", true}, {"header.X-Nope", false},
		{"time > 12:00:30", true}, {"time > 12:01", false}, {"time = 12:00:03", true},
		{"index = 7", true}, {"index = 8", false},
		{"'SIP/2.0 180'", true}, {"Q.850", true}, {"nothing-like-this", false},
		{"state = completed and status = 200 and from ~ alice", true},
		{"state = failed and status = 200", false},
		{"state = completed or status = 999", true},
		{"duration > 30s and (status = 486 or method = BYE)", true},
		{"duration > 40s and method = BYE", false},
	}
	for _, tc := range tests {
		q := mustParse(t, tc.src, false)
		if got := q.MatchCall(c); got != tc.want {
			t.Errorf("MatchCall(%q) = %v, want %v (%s)", tc.src, got, tc.want, q)
		}
	}
	// A call without messages has no message-field match at all.
	empty := &call.Call{}
	if mustParse(t, "status = 200", false).MatchCall(empty) {
		t.Error("empty call matched a message field")
	}
	if !mustParse(t, "not status = 200", false).MatchCall(empty) {
		t.Error("not over an empty call should hold")
	}
}

func TestMatchMessageNeedsCalls(t *testing.T) {
	m := sm{method: "INVITE"}.msg(1)
	q := mustParse(t, "method = INVITE and state = failed", false)
	if !q.NeedsCalls() {
		t.Fatal("NeedsCalls = false")
	}
	if q.MatchMessage(m, nil) {
		t.Error("nil call: call field must be false")
	}
	if !mustParse(t, "not state = failed", false).MatchMessage(m, nil) {
		// documented: the comparison is false, so its negation is true
		t.Error("not over a false call comparison should be true")
	}
	if mustParse(t, "method = INVITE", false).NeedsCalls() {
		t.Error("message-only query NeedsCalls")
	}
	if !mustParse(t, "method = INVITE or (a and not duration > 1s)", false).NeedsCalls() {
		t.Error("nested call field not detected")
	}
	failed := &call.Call{State: call.StateFailed}
	if !q.MatchMessage(m, failed) {
		t.Error("call context ignored")
	}
}

func TestNilQuery(t *testing.T) {
	var q *Query
	if !q.MatchMessage(trace.Message{}, nil) || !q.MatchCall(&call.Call{}) || q.NeedsCalls() || q.String() != "" {
		t.Error("nil Query must match all")
	}
}

func TestAnd(t *testing.T) {
	a := mustParse(t, "status >= 400 or method = BYE", false)
	b := mustParse(t, "from ~ alice and state = failed", false)
	if And() != nil || And(nil, nil) != nil {
		t.Error("And of nothing must be nil")
	}
	if And(nil, a) != a && And(nil, a).String() != a.String() {
		t.Error("And(nil, a) != a")
	}
	ab := And(a, nil, b)
	if got, want := ab.String(), `(status >= 400 or method = BYE) and from ~ alice and state = failed`; got != want {
		t.Errorf("And String = %q, want %q", got, want)
	}
	if !ab.NeedsCalls() || And(a, a).NeedsCalls() {
		t.Error("NeedsCalls of And wrong")
	}
	if _, err := Parse(ab.String(), Options{}); err != nil {
		t.Errorf("And normal form does not re-parse: %v", err)
	}
	c := answeredCall(t)
	if And(a, mustParse(t, "kind = call", false)).MatchCall(c) != true {
		t.Error("And(a, kind) should match")
	}
	if And(a, mustParse(t, "kind = options", false)).MatchCall(c) {
		t.Error("And with false part matched")
	}
}

func TestSugarConstructors(t *testing.T) {
	m := sm{method: "INVITE", from: "Alice", src: "10.1.1.1:5060"}.msg(1)
	if !Contains("from", "alice", false).MatchMessage(m, nil) || Contains("from", "alice", true).MatchMessage(m, nil) {
		t.Error("Contains case handling")
	}
	// the text is taken literally: no operators, quotes or keywords
	if Contains("raw", "a and (b", false).MatchMessage(m, nil) {
		t.Error("Contains matched a text that is not there")
	}
	if got := Contains("raw", `x "y" and`, false).String(); got != `raw ~ "x \"y\" and"` {
		t.Errorf("Contains String = %q", got)
	}
	if _, err := Parse(Contains("raw", `x "y" and`, false).String(), Options{}); err != nil {
		t.Errorf("Contains normal form: %v", err)
	}
	q, err := Eq("from_user", "ALICE", false)
	if err != nil || !q.MatchMessage(m, nil) {
		t.Errorf("Eq: %v", err)
	}
	if q, _ = Eq("from_user", "ALICE", true); q.MatchMessage(m, nil) {
		t.Error("Eq case-sensitive matched")
	}
	if q, err := Eq("status", "4xx", false); err != nil || q.MatchMessage(m, nil) {
		t.Errorf("Eq status: %v", err)
	}
	if _, err := Eq("status", "abc", false); err == nil {
		t.Error("Eq with bad value succeeded")
	}
	if _, err := Eq("nope", "x", false); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Errorf("Eq unknown field: %v", err)
	}
	q, err = InCIDR("src", "10.0.0.0/8")
	if err != nil || !q.MatchMessage(m, nil) {
		t.Errorf("InCIDR: %v", err)
	}
	if q, _ = InCIDR("src", "192.168.0.0/16"); q.MatchMessage(m, nil) {
		t.Error("InCIDR matched outside")
	}
	if q, err = InCIDR("dst", "10.0.0.2"); err != nil || q.MatchMessage(m, nil) == false {
		t.Errorf("InCIDR plain IP: %v", err)
	}
	for _, bad := range []struct{ f, c string }{{"src", "10.0.0.0/40"}, {"src", "x"}, {"from", "10.0.0.0/8"}, {"nope", "10.0.0.0/8"}} {
		if _, err := InCIDR(bad.f, bad.c); err == nil {
			t.Errorf("InCIDR(%q, %q) succeeded", bad.f, bad.c)
		}
	}
	defer func() {
		if recover() == nil {
			t.Error("Contains on a non-string field should panic")
		}
	}()
	Contains("status", "x", false)
}

func TestCIDRAndIPv6(t *testing.T) {
	mk := func(src, dst string) trace.Message {
		return sm{method: "INVITE", src: src, dst: dst}.msg(1)
	}
	m := mk("[2001:db8:1::5]:5060", "[::ffff:192.0.2.9]:5060")
	for _, tc := range []matchCase{
		{"src = 2001:db8:1::5", true}, {"src = 2001:db8:1:0::5", true}, {"src = 2001:db8::/32", true}, {"src = 2001:db8:2::/48", false},
		{"src in (10.0.0.0/8, 2001:db8::/32)", true}, {"src = ::/0", true}, {"src = 0.0.0.0/0", false},
		{"dst = 192.0.2.9", true}, {"dst = 192.0.2.0/24", true}, {"dst = ::ffff:192.0.2.9", true}, {"dst = ::ffff:192.0.2.0/120", true}, {"dst = ::/0", false},
		{"dst in 192.0.2.8/30", true}, {"dst in 192.0.2.0/30", false}, {"dst = 192.0.2.9/32", true},
		{"src != 2001:db8::/32", false}, {"src not in 192.0.0.0/8", true},
	} {
		if got := mustParse(t, tc.src, false).MatchMessage(m, nil); got != tc.want {
			t.Errorf("%q = %v, want %v", tc.src, got, tc.want)
		}
	}
	// Normal form of an IPv4-mapped literal.
	if got := mustParse(t, "dst = ::ffff:192.0.2.0/120", false).String(); got != "dst = 192.0.2.0/24" {
		t.Errorf("String = %q", got)
	}
	// Host bits in a CIDR are kept as written by netip but match the network.
	if !mustParse(t, "src = 2001:db8:1::5/32", false).MatchMessage(m, nil) {
		t.Error("CIDR with host bits did not match")
	}
}

func TestTimeOfDayAnchoring(t *testing.T) {
	// Times of day refer to the date of the message (or of the call start),
	// so they work on any capture day.
	for _, day := range []time.Time{t0, time.Date(2031, 12, 31, 0, 0, 0, 0, time.UTC), time.Date(1999, 7, 4, 0, 0, 0, 0, time.UTC)} {
		m := sm{method: "INVITE"}.msg(1)
		m.Time = day.Truncate(24 * time.Hour).Add(10*time.Hour + 30*time.Minute + 15*time.Second + 500*time.Millisecond)
		for _, tc := range []matchCase{
			{"time = 10:30", true}, {"time = 10:30:15", true}, {"time = 10:30:15.5", true}, {"time = 10:30:15.500", true}, {"time = 10:30:15.4", false},
			{"time >= 10:30", true}, {"time > 10:30", false}, {"time > 10:30:15", false}, {"time > 10:30:15.4", true}, {"time > 10:30:14", true}, {"time >= 10:30:15.5", true},
			{"time < 10:31", true}, {"time <= 10:30:15", true}, {"time < 10:30:16", true},
			{"time in 10:00..11:00", true}, {"time in (08:00..09:00, 10:30:15)", true}, {"time not in 10:00..11:00", false},
			{"time = 9:05", false}, {"time > 9:05", true},
		} {
			if got := mustParse(t, tc.src, false).MatchMessage(m, nil); got != tc.want {
				t.Errorf("%s: %q = %v, want %v", day.Format("2006-01-02"), tc.src, got, tc.want)
			}
		}
	}
	// a call field time of day is relative to the call's own day
	c := answeredCall(t)
	c.Start = time.Date(2030, 1, 2, 23, 59, 0, 0, time.UTC)
	c.End = c.Start.Add(2 * time.Minute)
	for _, tc := range []matchCase{{"start >= 23:59", true}, {"start < 23:59:30", true}, {"end < 00:02", false}, {"end >= 23:59", true}, {"end = 2030-01-03 00:01", true}} {
		if got := mustParse(t, tc.src, false).MatchCall(c); got != tc.want {
			t.Errorf("%q = %v, want %v", tc.src, got, tc.want)
		}
	}
}

func TestTimeFormats(t *testing.T) {
	m := sm{method: "INVITE"}.msg(1)
	m.Time = time.Date(2026, 3, 1, 12, 0, 0, 250_000_000, time.UTC)
	for _, tc := range []matchCase{
		{"time = 2026-03-01T12:00:00.25Z", true}, {"time = 2026-03-01T12:00:00Z", true}, {"time = 2026-03-01T12:00:01Z", false}, {"time >= 2026-03-01T12:00:00Z", true},
		{"time = 2026-03-01T12:00:00.250000000Z", true}, {"time = 2026-03-01T13:00:00.25+01:00", true}, {"time = 2026-03-01T07:00:00.25-05:00", true},
		{"time = 2026-03-01 12:00:00.25", true}, {"time = 2026-03-01T12:00:00.25", true}, {"time = '2026-03-01 12:00:00.250'", true},
		{"time = 2026-03-01T12:00", true}, {"time = 2026-03-01T12:01", false}, {"time = 2026-03-01", true},
		{"time > 2026-02-28", true}, {"time > 2026-03-01", false}, {"time >= 2026-03-01", true}, {"time < 2026-03-02", true}, {"time <= 2026-03-01", true},
		{"time in 2026-03-01..2026-03-02", true}, {"time in 2026-03-02..2026-03-03", false},
		{"time > 2026-03-01 11:59:59", true}, {"time < 2026-03-01 12:00:01", true},
	} {
		if got := mustParse(t, tc.src, false).MatchMessage(m, nil); got != tc.want {
			t.Errorf("%q = %v, want %v", tc.src, got, tc.want)
		}
	}
}

func TestHeaderLookupMatchesTrace(t *testing.T) {
	m := sm{method: "INVITE", ua: "UA/1", extra: []string{
		"Subject: first", "subject: second", "X-Fold: one", " two", "\tthree", "X-Empty:", "m: <sip:c@d>", "l: 0", "K: replaces, timer",
	}}.msg(1)
	m.Raw = strings.Replace(m.Raw, "\r\n", "\n", 1) // mixed line endings
	m.HeaderEnd = strings.Index(m.Raw, "\n\n") + 2
	if m.HeaderEnd < 2 {
		m.HeaderEnd = strings.Index(m.Raw, "\r\n\r\n") + 4
	}
	names := []string{"Subject", "subject", "SUBJECT", "X-Fold", "X-Empty", "Contact", "m", "Content-Length", "l", "Supported", "k", "Call-ID", "i", "From", "f", "To", "t", "Via", "v", "CSeq", "User-Agent", "X-Nothing", "Content-Type", "c", "Max-Forwards"}
	for _, n := range names {
		want := m.Header(n)
		if got := headerOf(m.Raw, m.HeaderEnd, newHeaderName(n)); got != want {
			t.Errorf("header %q: got %q, trace.Header gives %q", n, got, want)
		}
	}
}

func TestHasSDPMatchesTrace(t *testing.T) {
	multipart := sm{method: "INVITE"}.msg(1)
	body := "--b\r\nContent-Type: application/sdp\r\n\r\nv=0\r\n--b--\r\n"
	multipart.Raw = strings.TrimSuffix(multipart.Raw, "Content-Length: 0\r\n\r\n") + "Content-Type: multipart/mixed;boundary=b\r\n\r\n" + body
	multipart.HeaderEnd = len(multipart.Raw) - len(body)
	nosdp := multipart
	nosdp.Raw = strings.Replace(nosdp.Raw, "application/sdp", "text/plain", 1)
	other := sm{method: "MESSAGE"}.msg(2)
	other.Raw = strings.TrimSuffix(other.Raw, "Content-Length: 0\r\n\r\n") + "Content-Type: text/plain\r\n\r\nhello"
	other.HeaderEnd = len(other.Raw) - len("hello")
	for name, m := range map[string]trace.Message{
		"sdp": sm{method: "INVITE", sdp: sdpPCMA}.msg(1), "none": sm{method: "BYE"}.msg(1), "multipart": multipart, "multipart without sdp": nosdp, "text": other,
		"zero": {}, "bad header end": {Raw: "INVITE x SIP/2.0\r\n\r\n", HeaderEnd: 999},
	} {
		if got, want := hasSDP(&m), m.SDP() != ""; got != want {
			t.Errorf("%s: hasSDP = %v, SDP() != \"\" is %v", name, got, want)
		}
	}
}

func TestRegisterField(t *testing.T) {
	RegisterField(Field{Name: "x_test_len", Aliases: []string{"xtl"}, Type: TypeInt, Doc: "length of raw: x_test_len > 100",
		Message: func(m trace.Message) Value { return IntValue(int64(len(m.Raw))) }})
	RegisterField(Field{Name: "x_test_calls", Type: TypeBool, Doc: "always true",
		Call: func(c *call.Call) Value { return BoolValue(c != nil) }})
	RegisterField(Field{Name: "x_test_enum", Type: TypeEnum, Values: []string{"One", "Two"}, Doc: "enum: x_test_enum = one",
		Message: func(m trace.Message) Value { return StringValue("two") }})
	m := sm{method: "INVITE"}.msg(1)
	for _, tc := range []matchCase{{"x_test_len > 10", true}, {"xtl < 10", false}, {"x_test_enum = TWO", true}, {"x_test_enum = one", false}, {"x_test_enum in (one, two)", true}} {
		if got := mustParse(t, tc.src, false).MatchMessage(m, nil); got != tc.want {
			t.Errorf("%q = %v, want %v", tc.src, got, tc.want)
		}
	}
	q := mustParse(t, "x_test_calls", false)
	if !q.NeedsCalls() || !q.MatchCall(&call.Call{}) || q.MatchMessage(m, nil) || !q.MatchMessage(m, &call.Call{}) {
		t.Error("registered call field")
	}
	if _, err := Parse("x_test_enum = three", Options{}); err == nil || !strings.Contains(err.Error(), "One, Two") {
		t.Errorf("enum error: %v", err)
	}
	found := false
	for _, f := range Fields() {
		found = found || f.Name == "x_test_len"
	}
	if !found || !strings.Contains(Help(), "x_test_len") {
		t.Error("registered field missing from Fields/Help")
	}
	if !strings.Contains(unknownFieldMsg("zzzzzz"), "x_test_len") {
		t.Error("registered field missing from the field list in errors")
	}
	if s := suggestField("x_test_ln"); s != "x_test_len" {
		t.Errorf("suggest = %q", s)
	}
	bad := []Field{
		{}, {Name: "Bad"}, {Name: "x_t1", Type: TypeInt},
		{Name: "x_t2", Type: TypeInt, Message: func(trace.Message) Value { return Value{} }, Call: func(*call.Call) Value { return Value{} }},
		{Name: "method", Type: TypeString, Message: func(trace.Message) Value { return Value{} }},
		{Name: "x_t3", Aliases: []string{"status"}, Type: TypeString, Message: func(trace.Message) Value { return Value{} }},
		{Name: "and", Type: TypeString, Message: func(trace.Message) Value { return Value{} }},
		{Name: "h", Type: TypeString, Message: func(trace.Message) Value { return Value{} }},
		{Name: "x_t4", Type: Type(99), Message: func(trace.Message) Value { return Value{} }},
		{Name: "x_t5", Type: TypeString, Values: []string{"a"}, Message: func(trace.Message) Value { return Value{} }},
	}
	for i, f := range bad {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("bad field #%d (%q) did not panic", i, f.Name)
				}
			}()
			RegisterField(f)
		}()
	}
}

func TestBuiltinRegistry(t *testing.T) {
	want := strings.Fields(`method status uri callid from to from_user to_user from_tag to_tag contact cseq via branch src dst sport dport transport time
		ua is_request is_response has_sdp file index raw body
		state kind result final_code duration pdd ring_time setup_time talk_time ended_by end_method reason retransmissions msgs codec has_media mos loss jitter user_agent`)
	have := map[string]Field{}
	for _, f := range Fields() {
		have[f.Name] = f
	}
	for _, n := range want {
		f, ok := have[n]
		if !ok {
			t.Errorf("field %s is not registered", n)
			continue
		}
		if f.Doc == "" || !strings.Contains(f.Doc, ":") && !strings.Contains(f.Doc, "e.g.") {
			t.Errorf("field %s: Doc lacks an example: %q", n, f.Doc)
		}
		if (f.Message == nil) == (f.Call == nil) {
			t.Errorf("field %s: scope", n)
		}
	}
	// the documented split between the scopes
	for _, n := range want[:28] {
		if have[n].Scope() != "message" {
			t.Errorf("%s should be a message field", n)
		}
	}
	for _, n := range want[28:] {
		if have[n].Scope() != "call" {
			t.Errorf("%s should be a call field", n)
		}
	}
	// the Message getter of a built-in agrees with the compiled path
	m := sm{method: "INVITE", sdp: sdpPCMA, ua: "UA"}.msg(5)
	if v := have["status"].Message(m); !v.IsNull() {
		t.Error("status of a request must be null")
	}
	if v := have["method"].Message(m); v.IsNull() || v.s != "INVITE" {
		t.Errorf("method value %+v", v)
	}
	if v := have["has_sdp"].Message(m); v.n != 1 {
		t.Errorf("has_sdp value %+v", v)
	}
	// Aliases resolve case-insensitively, '-' is '_'.
	for _, a := range []string{"Call-ID", "CALL_ID", "Src-IP", "RURI", "Request_URI", "code", "final", "retrans", "messages", "src_port"} {
		if _, ok := lookupField(a); !ok {
			t.Errorf("alias %q unknown", a)
		}
	}
	fs := Fields()
	fs[0].Name = "mutated"
	if Fields()[0].Name == "mutated" {
		t.Error("Fields returns the registry's storage")
	}
}

func TestHelp(t *testing.T) {
	h := Help()
	for _, f := range Fields() {
		if !strings.Contains(h, f.Name) || !strings.Contains(h, f.Doc) {
			t.Errorf("Help misses field %s", f.Name)
		}
	}
	for _, s := range []string{"and", "or", "not", "in", "=~", "CIDR", "header.", "4xx", "HH:MM", "MESSAGE FIELDS", "CALL FIELDS", "ANY message"} {
		if !strings.Contains(h, s) {
			t.Errorf("Help misses %q", s)
		}
	}
	for _, l := range strings.Split(h, "\n") {
		if strings.TrimRight(l, " ") != l {
			t.Errorf("trailing space in %q", l)
		}
	}
	// the examples in the language reference parse
	for _, ex := range []string{"from ~ alice and status >= 500", "method in (INVITE, BYE) and src in 10.0.0.0/8", "duration > 30s and not has_media", `"a=sendonly"`, "h.P-Asserted-Identity ~ 4930", "status = 486"} {
		mustParse(t, ex, false)
	}
}

// Every Doc example "field OP value" in the registry parses (guards the docs).
func TestDocExamplesParse(t *testing.T) {
	for _, f := range Fields() {
		if strings.HasPrefix(f.Name, "x_test") {
			continue
		}
		_, ex, ok := strings.Cut(f.Doc, ": ")
		if !ok {
			continue
		}
		for _, e := range strings.Split(ex, ", ") {
			// Examples with commas inside parentheses are split wrongly; skip fragments.
			if strings.Count(e, "(") != strings.Count(e, ")") {
				continue
			}
			if _, err := Parse(e, Options{}); err != nil && !strings.Contains(e, " in (") {
				t.Errorf("%s: doc example %q: %v", f.Name, e, err)
			}
		}
	}
}
