package flow

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/sotoz/sipcurious/internal/call"
	"github.com/sotoz/sipcurious/internal/rtp"
	"github.com/sotoz/sipcurious/internal/trace"
)

var t0 = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

func ap(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

// sg describes one test SIP message.
type sg struct {
	at       time.Duration
	src, dst string
	method   string // request method; "" for a response
	code     int
	reason   string
	cseq     int
	cseqM    string // CSeq method of a response
	branch   string
	toTag    string
	extra    []string
	sdp      string
	callID   string
}

func (s sg) msg(i int) trace.Message {
	src, dst := ap(s.src), ap(s.dst)
	if s.callID == "" {
		s.callID = "call-1@example.com"
	}
	m := trace.Message{
		File: "t.pcap", Index: i + 1, Time: t0.Add(s.at),
		Src: src.Addr(), SrcPort: src.Port(), Dst: dst.Addr(), DstPort: dst.Port(),
		Transport: "UDP", IsRequest: s.method != "", CallID: s.callID,
	}
	var b strings.Builder
	if s.method != "" {
		m.Method = s.method
		m.RequestURI = "sip:bob@example.com"
		fmt.Fprintf(&b, "%s sip:bob@example.com SIP/2.0\r\n", s.method)
	} else {
		m.Method = s.cseqM
		m.StatusCode, m.Reason = s.code, s.reason
		if m.Reason == "" {
			m.Reason = reasons[s.code]
		}
		fmt.Fprintf(&b, "SIP/2.0 %d %s\r\n", m.StatusCode, m.Reason)
		s.method = s.cseqM
	}
	m.Via = "SIP/2.0/UDP " + src.String() + ";branch=" + s.branch
	m.From = "<sip:alice@example.com>;tag=ft"
	m.To = "<sip:bob@example.com>"
	if s.toTag != "" {
		m.To += ";tag=" + s.toTag
	}
	m.CSeq = fmt.Sprintf("%d %s", s.cseq, s.method)
	fmt.Fprintf(&b, "Via: %s\r\nFrom: %s\r\nTo: %s\r\nCall-ID: %s\r\nCSeq: %s\r\n", m.Via, m.From, m.To, s.callID, m.CSeq)
	for _, e := range s.extra {
		b.WriteString(e + "\r\n")
	}
	if s.sdp != "" {
		fmt.Fprintf(&b, "Content-Type: application/sdp\r\nContent-Length: %d\r\n\r\n", len(s.sdp))
		m.HeaderEnd = b.Len()
		b.WriteString(s.sdp)
	} else {
		b.WriteString("Content-Length: 0\r\n\r\n")
		m.HeaderEnd = b.Len()
	}
	m.Raw = b.String()
	return m
}

var reasons = map[int]string{
	100: "Trying", 180: "Ringing", 200: "OK", 401: "Unauthorized", 486: "Busy Here",
	487: "Request Terminated", 503: "Service Unavailable",
}

func ms(n int) time.Duration { return time.Duration(n) * time.Millisecond }

func sdpBody(ip string, port int, codecs string, attrs ...string) string {
	var b strings.Builder
	b.WriteString("v=0\r\no=- 1 1 IN IP4 " + ip + "\r\ns=-\r\nc=IN IP4 " + ip + "\r\nt=0 0\r\n")
	fmt.Fprintf(&b, "m=audio %d RTP/AVP", port)
	var maps []string
	for _, c := range strings.Fields(codecs) {
		switch c {
		case "PCMU":
			b.WriteString(" 0")
		case "PCMA":
			b.WriteString(" 8")
		case "G722":
			b.WriteString(" 9")
		case "telephone-event":
			b.WriteString(" 101")
			maps = append(maps, "a=rtpmap:101 telephone-event/8000")
		}
	}
	b.WriteString("\r\n")
	for _, a := range maps {
		b.WriteString(a + "\r\n")
	}
	for _, a := range attrs {
		b.WriteString(a + "\r\n")
	}
	return b.String()
}

func build(list ...sg) call.Call {
	msgs := make([]trace.Message, len(list))
	for i, s := range list {
		msgs[i] = s.msg(i)
	}
	cs := call.Build(msgs, call.Options{})
	if len(cs) != 1 {
		panic(fmt.Sprintf("want 1 call, got %d", len(cs)))
	}
	return cs[0]
}

const (
	alice = "10.0.0.1:5060"
	proxy = "10.0.0.2:5060"
	bob   = "10.0.0.3:5060"
)

// answered is alice -> bob with SDP: INVITE, 100, 180, 200, ACK, BYE, 200.
func answered() call.Call {
	ua := "User-Agent: Linphone/4.5"
	srv := "Server: Asterisk PBX 18.1"
	return build(
		sg{at: 0, src: alice, dst: bob, method: "INVITE", cseq: 1, branch: "z9hG4bKa", extra: []string{ua}, sdp: sdpBody("10.0.0.1", 20000, "PCMU PCMA telephone-event")},
		sg{at: ms(10), src: bob, dst: alice, code: 100, cseq: 1, cseqM: "INVITE", branch: "z9hG4bKa", extra: []string{srv}},
		sg{at: ms(500), src: bob, dst: alice, code: 180, cseq: 1, cseqM: "INVITE", branch: "z9hG4bKa", toTag: "tt", extra: []string{srv}},
		sg{at: ms(2500), src: bob, dst: alice, code: 200, cseq: 1, cseqM: "INVITE", branch: "z9hG4bKa", toTag: "tt", extra: []string{srv}, sdp: sdpBody("10.0.0.3", 30000, "PCMA telephone-event")},
		sg{at: ms(2510), src: alice, dst: bob, method: "ACK", cseq: 1, branch: "z9hG4bKack", toTag: "tt"},
		sg{at: ms(7510), src: alice, dst: bob, method: "BYE", cseq: 2, branch: "z9hG4bKbye", toTag: "tt"},
		sg{at: ms(7520), src: bob, dst: alice, code: 200, cseq: 2, cseqM: "BYE", branch: "z9hG4bKbye", toTag: "tt"},
	)
}

func withStreams(c call.Call) call.Call {
	streams := []rtp.Stream{
		{Key: rtp.Key{Src: ap("10.0.0.1:20000"), Dst: ap("10.0.0.3:30000"), SSRC: 1}, Start: t0.Add(ms(2600)), End: t0.Add(ms(7500)), Codec: "PCMA", Packets: 245, LossPct: 0.4, JitterMean: ms(3), MOS: 4.31},
		{Key: rtp.Key{Src: ap("10.0.0.3:30000"), Dst: ap("10.0.0.1:20000"), SSRC: 2}, Start: t0.Add(ms(2700)), End: t0.Add(ms(7500)), Codec: "PCMA", Packets: 240, LossPct: 0, JitterMean: ms(1), MOS: 4.4},
	}
	cs := []call.Call{c}
	call.Attach(cs, streams)
	return cs[0]
}
