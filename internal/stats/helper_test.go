package stats

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/sotoz/sipcurious/internal/trace"
)

var t0 = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

var (
	alice = netip.MustParseAddrPort("10.0.0.1:5060")
	bob   = netip.MustParseAddrPort("10.0.1.2:5060")
)

func ms(n int) time.Duration { return time.Duration(n) * time.Millisecond }

// sg describes one test SIP message (see internal/call/helper_test.go).
type sg struct {
	at       int // ms after t0
	src, dst netip.AddrPort
	method   string // request method, "" for a response
	code     int
	callID   string
	cseq     int
	cseqM    string // CSeq method of a response
	fromTag  string
	toTag    string
	branch   string
	from, to string
	ua       string // User-Agent (requests) or Server (responses)
	sdp      string
	tcp      bool
}

func reason(code int) string {
	return map[int]string{100: "Trying", 180: "Ringing", 200: "OK", 404: "Not Found", 486: "Busy Here",
		487: "Request Terminated", 503: "Service Unavailable"}[code]
}

func (s sg) msg(index int) trace.Message {
	m := trace.Message{
		File: "t.pcap", Index: index, Time: t0.Add(ms(s.at)),
		Src: s.src.Addr(), SrcPort: s.src.Port(), Dst: s.dst.Addr(), DstPort: s.dst.Port(),
		Transport: "UDP", IsRequest: s.method != "", CallID: s.callID,
	}
	if s.tcp {
		m.Transport = "TCP"
	}
	var b strings.Builder
	if s.method != "" {
		m.Method, m.RequestURI = s.method, "sip:"+s.to+"@example.com"
		fmt.Fprintf(&b, "%s %s SIP/2.0\r\n", s.method, m.RequestURI)
	} else {
		m.Method, m.StatusCode, m.Reason = s.cseqM, s.code, reason(s.code)
		fmt.Fprintf(&b, "SIP/2.0 %d %s\r\n", s.code, m.Reason)
	}
	m.Via = "SIP/2.0/UDP " + s.src.String() + ";branch=" + s.branch
	m.From = fmt.Sprintf("<sip:%s@example.com>;tag=%s", s.from, s.fromTag)
	m.To = fmt.Sprintf("<sip:%s@example.com>", s.to)
	if s.toTag != "" {
		m.To += ";tag=" + s.toTag
	}
	m.CSeq = fmt.Sprintf("%d %s", s.cseq, m.Method)
	fmt.Fprintf(&b, "Via: %s\r\nFrom: %s\r\nTo: %s\r\nCall-ID: %s\r\nCSeq: %s\r\n", m.Via, m.From, m.To, s.callID, m.CSeq)
	if s.ua != "" {
		if s.method != "" {
			b.WriteString("User-Agent: " + s.ua + "\r\n")
		} else {
			b.WriteString("Server: " + s.ua + "\r\n")
		}
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

func sdpBody(ip string, port int, codec string, pt int) string {
	return fmt.Sprintf("v=0\r\no=- 1 1 IN IP4 %s\r\ns=-\r\nc=IN IP4 %s\r\nt=0 0\r\nm=audio %d RTP/AVP %d\r\n", ip, ip, port, pt) +
		fmt.Sprintf("a=rtpmap:%d %s/8000\r\n", pt, codec)
}

// flow builds the messages of one INVITE dialog between caller and callee.
type flow struct {
	id       string
	from, to string
	caller   netip.AddrPort
	callee   netip.AddrPort
	list     []sg
}

func newFlow(id, from, to string) *flow {
	return &flow{id: id, from: from, to: to, caller: alice, callee: bob}
}

func (f *flow) base(at int, x sg) sg {
	x.at, x.callID = at, f.id
	x.from, x.to = f.from, f.to
	x.fromTag, x.branch = "ft-"+f.id, "z9hG4bK-"+f.id
	return x
}

func (f *flow) invite(at int, sdp string) *flow {
	f.list = append(f.list, f.base(at, sg{src: f.caller, dst: f.callee, method: "INVITE", cseq: 1, ua: "PhoneA/1.0", sdp: sdp}))
	return f
}

func (f *flow) resp(at, code int, sdp string) *flow {
	x := f.base(at, sg{src: f.callee, dst: f.caller, code: code, cseq: 1, cseqM: "INVITE", ua: "PBX-B/2.0", sdp: sdp})
	if code != 100 {
		x.toTag = "tt-" + f.id
	}
	f.list = append(f.list, x)
	return f
}

func (f *flow) cancel(at int) *flow {
	f.list = append(f.list, f.base(at, sg{src: f.caller, dst: f.callee, method: "CANCEL", cseq: 1}))
	return f
}

func (f *flow) cancelResp(at, code int) *flow {
	f.list = append(f.list, f.base(at, sg{src: f.callee, dst: f.caller, code: code, cseq: 1, cseqM: "CANCEL"}))
	return f
}

func (f *flow) ack(at int) *flow {
	x := f.base(at, sg{src: f.caller, dst: f.callee, method: "ACK", cseq: 1})
	x.branch += "-ack"
	x.toTag = "tt-" + f.id
	f.list = append(f.list, x)
	return f
}

func (f *flow) bye(at int) *flow {
	x := f.base(at, sg{src: f.caller, dst: f.callee, method: "BYE", cseq: 2})
	x.branch += "-bye"
	x.toTag = "tt-" + f.id
	f.list = append(f.list, x)
	return f
}

func (f *flow) byeResp(at int) *flow {
	x := f.base(at, sg{src: f.callee, dst: f.caller, code: 200, cseq: 2, cseqM: "BYE"})
	x.branch += "-bye"
	x.toTag = "tt-" + f.id
	f.list = append(f.list, x)
	return f
}

func (f *flow) register(at int) *flow {
	f.list = append(f.list, f.base(at, sg{src: f.caller, dst: f.callee, method: "REGISTER", cseq: 1, tcp: true}))
	return f
}

func (f *flow) registerOK(at int) *flow {
	x := f.base(at, sg{src: f.callee, dst: f.caller, code: 200, cseq: 1, cseqM: "REGISTER", tcp: true})
	x.toTag = "tt-" + f.id
	f.list = append(f.list, x)
	return f
}

func buildMessages(flows ...*flow) []trace.Message {
	var all []sg
	for _, f := range flows {
		all = append(all, f.list...)
	}
	out := make([]trace.Message, len(all))
	for i, s := range all {
		out[i] = s.msg(i + 1)
	}
	return out
}

func ap(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }
