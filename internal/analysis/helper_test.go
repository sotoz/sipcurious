package analysis

import (
	"fmt"
	"github.com/sotoz/sipcurious/internal/call"
	"github.com/sotoz/sipcurious/internal/rtp"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/sotoz/sipcurious/internal/trace"
)

var t0 = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

// Default endpoints of the test scenarios: alice (caller) -> proxy -> bob (callee).
var (
	alice = netip.MustParseAddrPort("10.0.0.1:5060")
	proxy = netip.MustParseAddrPort("10.0.0.100:5060")
	bob   = netip.MustParseAddrPort("10.0.1.2:5060")
)

// sg describes one test SIP message.
type sg struct {
	at       time.Duration // offset from t0
	src, dst netip.AddrPort
	method   string // request method; "" for responses
	code     int    // status code for responses
	reason   string
	callID   string
	cseq     int
	cseqM    string // CSeq method; defaults to method (requests) - required for responses
	fromTag  string
	toTag    string
	branch   string
	from     string // From user, default alice
	to       string // To user, default bob
	extra    []string
	sdp      string
	ctype    string // default application/sdp
	via      string // overrides the Via header value entirely
}

func (s sg) msg(index int) trace.Message {
	if s.from == "" {
		s.from = "alice"
	}
	if s.to == "" {
		s.to = "bob"
	}
	if s.cseqM == "" {
		s.cseqM = s.method
	}
	var b strings.Builder
	m := trace.Message{
		File: "t.pcap", Index: index, Time: t0.Add(s.at),
		Src: s.src.Addr(), SrcPort: s.src.Port(), Dst: s.dst.Addr(), DstPort: s.dst.Port(),
		Transport: "UDP", IsRequest: s.method != "", Method: s.cseqM, CallID: s.callID,
	}
	if s.method != "" {
		m.Method = s.method
		m.RequestURI = "sip:bob@example.com"
		fmt.Fprintf(&b, "%s sip:bob@example.com SIP/2.0\r\n", s.method)
	} else {
		m.StatusCode, m.Reason = s.code, s.reason
		if m.Reason == "" {
			m.Reason = reasonFor(s.code)
		}
		fmt.Fprintf(&b, "SIP/2.0 %d %s\r\n", m.StatusCode, m.Reason)
	}
	via := s.via
	if via == "" {
		via = "SIP/2.0/UDP " + s.src.String() + ";branch=" + s.branch
	}
	m.Via = via
	m.From = fmt.Sprintf("<sip:%s@example.com>;tag=%s", s.from, s.fromTag)
	m.To = fmt.Sprintf("<sip:%s@example.com>", s.to)
	if s.toTag != "" {
		m.To += ";tag=" + s.toTag
	}
	m.CSeq = fmt.Sprintf("%d %s", s.cseq, s.cseqM)
	fmt.Fprintf(&b, "Via: %s\r\nFrom: %s\r\nTo: %s\r\nCall-ID: %s\r\nCSeq: %s\r\n", m.Via, m.From, m.To, s.callID, m.CSeq)
	for _, e := range s.extra {
		b.WriteString(e + "\r\n")
	}
	if s.sdp != "" {
		ct := s.ctype
		if ct == "" {
			ct = "application/sdp"
		}
		fmt.Fprintf(&b, "Content-Type: %s\r\nContent-Length: %d\r\n\r\n", ct, len(s.sdp))
		m.HeaderEnd = b.Len()
		b.WriteString(s.sdp)
	} else {
		b.WriteString("Content-Length: 0\r\n\r\n")
		m.HeaderEnd = b.Len()
	}
	m.Raw = b.String()
	return m
}

func reasonFor(code int) string {
	switch code {
	case 100:
		return "Trying"
	case 180:
		return "Ringing"
	case 183:
		return "Session Progress"
	case 200:
		return "OK"
	case 302:
		return "Moved Temporarily"
	case 401:
		return "Unauthorized"
	case 407:
		return "Proxy Authentication Required"
	case 404:
		return "Not Found"
	case 480:
		return "Temporarily Unavailable"
	case 486:
		return "Busy Here"
	case 487:
		return "Request Terminated"
	case 488:
		return "Not Acceptable Here"
	case 500:
		return "Server Internal Error"
	case 503:
		return "Service Unavailable"
	case 603:
		return "Decline"
	}
	return "Status"
}

// msgs builds trace messages from descriptions, numbering them in order.
func msgs(list ...sg) []trace.Message {
	out := make([]trace.Message, len(list))
	for i, s := range list {
		out[i] = s.msg(i + 1)
	}
	return out
}

// ms is a duration in milliseconds.
func ms(n int) time.Duration { return time.Duration(n) * time.Millisecond }

// sdpBody builds an SDP body. attrs are extra a= lines for the media section.
func sdpBody(ip string, port int, codecs string, attrs ...string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "v=0\r\no=- 1 1 IN IP4 %s\r\ns=-\r\nc=IN IP4 %s\r\nt=0 0\r\n", ip, ip)
	fmt.Fprintf(&b, "m=audio %d RTP/AVP", port)
	for _, c := range strings.Fields(codecs) {
		b.WriteString(" " + strings.SplitN(c, "=", 2)[0])
	}
	b.WriteString("\r\n")
	for _, c := range strings.Fields(codecs) {
		if _, name, ok := strings.Cut(c, "="); ok {
			fmt.Fprintf(&b, "a=rtpmap:%s %s\r\n", strings.SplitN(c, "=", 2)[0], name)
		}
	}
	for _, a := range attrs {
		b.WriteString("a=" + a + "\r\n")
	}
	return b.String()
}

// scenario is a convenience builder for the usual caller -> callee INVITE flow.
type scenario struct {
	id      string
	cseq    int
	ftag    string
	ttag    string
	branch  string
	caller  netip.AddrPort
	callee  netip.AddrPort
	list    []sg
	callerS string // caller SDP (offer)
}

func newScenario(id string) *scenario {
	return &scenario{id: id, cseq: 1, ftag: "ft-" + id, ttag: "tt-" + id, branch: "z9hG4bK-" + id, caller: alice, callee: bob}
}

// c2s adds a caller -> callee message.
func (s *scenario) c2s(at int, x sg) *scenario {
	x.at, x.src, x.dst, x.callID = ms(at), s.caller, s.callee, s.id
	if x.fromTag == "" {
		x.fromTag = s.ftag
	}
	s.list = append(s.list, x)
	return s
}

// s2c adds a callee -> caller message.
func (s *scenario) s2c(at int, x sg) *scenario {
	x.at, x.src, x.dst, x.callID = ms(at), s.callee, s.caller, s.id
	if x.fromTag == "" {
		x.fromTag = s.ftag
	}
	s.list = append(s.list, x)
	return s
}

func (s *scenario) invite(at int, sdp string) *scenario {
	return s.c2s(at, sg{method: "INVITE", cseq: s.cseq, branch: s.branch, sdp: sdp})
}

func (s *scenario) resp(at, code int, sdp string) *scenario {
	toTag := s.ttag
	if code == 100 {
		toTag = ""
	}
	return s.s2c(at, sg{code: code, cseq: s.cseq, cseqM: "INVITE", branch: s.branch, toTag: toTag, sdp: sdp})
}

func (s *scenario) ack(at int) *scenario {
	return s.c2s(at, sg{method: "ACK", cseq: s.cseq, branch: s.branch + "-ack", toTag: s.ttag})
}

// bye adds a BYE from the caller (callerSide) or the callee.
func (s *scenario) bye(at int, callerSide bool, extra ...string) *scenario {
	if callerSide {
		return s.c2s(at, sg{method: "BYE", cseq: s.cseq + 1, branch: s.branch + "-bye", toTag: s.ttag, extra: extra})
	}
	// The callee's BYE swaps From and To: its From tag is the callee's tag.
	return s.s2c(at, sg{method: "BYE", cseq: 1, branch: s.branch + "-bye", fromTag: s.ttag, toTag: s.ftag, from: "bob", to: "alice", extra: extra})
}

func (s *scenario) messages() []trace.Message { return msgs(s.list...) }

type netipAddrPort = netip.AddrPort

func netipAP(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

func itoa(n int) string { return fmt.Sprint(n) }

// run executes one rule over the calls built from msgs (and streams).
func runRule(t *testing.T, id string, in *Input) []Finding {
	t.Helper()
	r, ok := Lookup(id)
	if !ok {
		t.Fatalf("no rule %s", id)
	}
	in.Config = in.Config.WithDefaults()
	return r.Check(in)
}

// input builds an Input from messages and streams, like the engine does.
func input(msgs []trace.Message, streams ...rtp.Stream) *Input {
	calls := call.Build(msgs, call.Options{})
	call.Attach(calls, streams)
	return &Input{Messages: msgs, Calls: calls, Streams: streams}
}

func mkStream(src, dst string, from, to time.Duration, ssrc uint32) rtp.Stream {
	return rtp.Stream{
		Key:  rtp.Key{Src: netipAP(src), Dst: netipAP(dst), SSRC: ssrc},
		File: "t.pcap", FirstIndex: 100 + int(ssrc),
		Start: t0.Add(from), End: t0.Add(to), Packets: 500, Expected: 500, PayloadType: 8, Codec: "PCMA", MOS: 4.3, RFactor: 93,
		JitterMean: 2 * time.Millisecond,
	}
}

func mustOne(t *testing.T, fs []Finding) Finding {
	t.Helper()
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(fs), fs)
	}
	f := fs[0]
	checkFinding(t, f)
	return f
}

// checkFinding verifies the contract every finding must keep.
func checkFinding(t *testing.T, f Finding) {
	t.Helper()
	if f.Rule == "" || f.Title == "" || strings.ContainsAny(f.Title, "\r\n") || f.Hint == "" || f.Detail == "" {
		t.Errorf("incomplete finding: %+v", f)
	}
	if len(f.Packets) == 0 {
		t.Errorf("%s: finding without packet refs", f.Rule)
	}
	for _, p := range f.Packets {
		if p.File == "" || p.Index <= 0 {
			t.Errorf("%s: bad ref %+v", f.Rule, p)
		}
	}
}

func contains(t *testing.T, what, s string, subs ...string) {
	t.Helper()
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			t.Errorf("%s = %q, want it to contain %q", what, s, sub)
		}
	}
}
