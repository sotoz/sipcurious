package query

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/sotoz/sipcurious/internal/call"
	"github.com/sotoz/sipcurious/internal/rtp"
	"github.com/sotoz/sipcurious/internal/trace"
)

var t0 = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

// sm describes one test SIP message.
type sm struct {
	at       time.Duration
	src, dst string // "ip:port"
	method   string // request; "" = response
	code     int
	reason   string
	cseqM    string
	callID   string
	from     string // From user
	to       string // To user
	fromTag  string
	toTag    string
	branch   string
	ua       string
	server   string
	extra    []string // raw extra header lines
	sdp      string
	transp   string
}

func (s sm) msg(idx int) trace.Message {
	def := func(p *string, v string) {
		if *p == "" {
			*p = v
		}
	}
	def(&s.src, "10.0.0.1:5060")
	def(&s.dst, "10.0.0.2:5060")
	def(&s.callID, "call-1@host")
	def(&s.from, "alice")
	def(&s.to, "bob")
	def(&s.fromTag, "ft1")
	def(&s.branch, "z9hG4bKb1")
	def(&s.transp, "UDP")
	if s.method != "" {
		def(&s.cseqM, s.method)
	}
	def(&s.cseqM, "INVITE")
	src, dst := netip.MustParseAddrPort(s.src), netip.MustParseAddrPort(s.dst)
	m := trace.Message{
		File: "t.pcap", Index: idx, Time: t0.Add(s.at),
		Src: src.Addr(), SrcPort: src.Port(), Dst: dst.Addr(), DstPort: dst.Port(),
		Transport: s.transp, IsRequest: s.method != "", Method: s.cseqM, CallID: s.callID,
	}
	var b strings.Builder
	if s.method != "" {
		m.RequestURI = "sip:" + s.to + "@example.com"
		fmt.Fprintf(&b, "%s %s SIP/2.0\r\n", s.method, m.RequestURI)
	} else {
		m.StatusCode, m.Reason = s.code, s.reason
		if m.Reason == "" {
			m.Reason = "Reason"
		}
		fmt.Fprintf(&b, "SIP/2.0 %d %s\r\n", m.StatusCode, m.Reason)
	}
	m.Via = "SIP/2.0/" + s.transp + " " + s.src + ";branch=" + s.branch
	m.From = "\"" + strings.ToUpper(s.from) + "\" <sip:" + s.from + "@example.com>;tag=" + s.fromTag
	m.To = "<sip:" + s.to + "@example.com>"
	if s.toTag != "" {
		m.To += ";tag=" + s.toTag
	}
	m.Contact = "<sip:" + s.from + "@" + src.Addr().String() + ">"
	m.CSeq = "1 " + s.cseqM
	fmt.Fprintf(&b, "Via: %s\r\nFrom: %s\r\nTo: %s\r\nCall-ID: %s\r\nCSeq: %s\r\nContact: %s\r\n",
		m.Via, m.From, m.To, m.CallID, m.CSeq, m.Contact)
	if s.ua != "" {
		fmt.Fprintf(&b, "User-Agent: %s\r\n", s.ua)
	}
	if s.server != "" {
		fmt.Fprintf(&b, "Server: %s\r\n", s.server)
	}
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

const sdpPCMA = "v=0\r\no=- 1 1 IN IP4 10.0.0.1\r\ns=-\r\nc=IN IP4 10.0.0.1\r\nt=0 0\r\nm=audio 4000 RTP/AVP 8\r\na=rtpmap:8 PCMA/8000\r\na=sendonly\r\n"

// buildCall assembles messages into one call through call.Build.
func buildCall(t testing.TB, ms ...sm) *call.Call {
	t.Helper()
	msgs := make([]trace.Message, len(ms))
	for i, s := range ms {
		msgs[i] = s.msg(i + 1)
	}
	calls := call.Build(msgs, call.Options{})
	if len(calls) != 1 {
		t.Fatalf("Build returned %d calls, want 1", len(calls))
	}
	return &calls[0]
}

// answered is a typical answered call: INVITE, 100, 180, 200 (with SDP), ACK, BYE by callee, 200.
func answeredCall(t testing.TB) *call.Call {
	bob, alice := "10.0.0.2:5060", "10.0.0.1:5060"
	return buildCall(t,
		sm{at: 0, method: "INVITE", sdp: sdpPCMA, ua: "Cisco-SIPGateway/IOS-15"},
		sm{at: 10 * time.Millisecond, src: bob, dst: alice, code: 100, cseqM: "INVITE"},
		sm{at: 2 * time.Second, src: bob, dst: alice, code: 180, cseqM: "INVITE", toTag: "tt1", server: "Asterisk PBX 18"},
		sm{at: 3 * time.Second, src: bob, dst: alice, code: 200, cseqM: "INVITE", toTag: "tt1", sdp: sdpPCMA, server: "Asterisk PBX 18"},
		sm{at: 3010 * time.Millisecond, method: "ACK", toTag: "tt1"},
		sm{at: 33 * time.Second, src: bob, dst: alice, method: "BYE", from: "bob", to: "alice", fromTag: "tt1", toTag: "ft1", extra: []string{"Reason: Q.850;cause=16"}},
		sm{at: 33100 * time.Millisecond, code: 200, cseqM: "BYE", from: "bob", to: "alice", fromTag: "tt1", toTag: "ft1"},
	)
}

// withStreams attaches synthetic RTP streams to c.
func withStreams(c *call.Call, ss ...rtp.Stream) *call.Call {
	cc := *c
	cc.Streams = ss
	return &cc
}
