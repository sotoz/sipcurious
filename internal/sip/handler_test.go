package sip

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/sotoz/sipcurious/internal/capture"
)

var (
	tcpA   = netip.MustParseAddr("10.0.0.1")
	tcpB   = netip.MustParseAddr("10.0.0.2")
	t0     = time.Date(2024, 5, 6, 7, 8, 9, 0, time.UTC)
	flowAB = flowKey{tcpA, tcpB, 40000, 5060}
)

// msg builds a request with an optional body and a correct Content-Length.
func msg(method, id, body string) string {
	return fmt.Sprintf("%s sip:bob@example.com SIP/2.0\r\nVia: SIP/2.0/TCP 10.0.0.1:40000;branch=z9hG4bK%s\r\nFrom: <sip:a@x>;tag=1\r\nTo: <sip:b@x>\r\nCall-ID: %s\r\nCSeq: 1 %s\r\nContent-Type: application/sdp\r\nContent-Length: %d\r\n\r\n%s",
		method, id, id, method, len(body), body)
}

// seg is one TCP segment fed to the handler.
type seg struct {
	k       flowKey
	seq     uint32
	data    string
	syn     bool
	fin     bool
	rst     bool
	partial bool
}

// feed runs the segments through a fresh Handler (packet index = position+1)
// and returns it together with the consumed flags.
func feed(t *testing.T, opt ParseOptions, segs ...seg) (*Handler, []bool) {
	t.Helper()
	h := &Handler{file: "x.pcap", opt: opt}
	used := make([]bool, len(segs))
	for i, s := range segs {
		p := &capture.Packet{
			File: "x.pcap", Index: i + 1, Time: t0.Add(time.Duration(i) * time.Millisecond),
			Src: s.k.src, Dst: s.k.dst, SrcPort: s.k.srcPort, DstPort: s.k.dstPort, Transport: "TCP",
			TCPSeq: s.seq, TCPSYN: s.syn, TCPFIN: s.fin, TCPRST: s.rst,
			Payload: []byte(s.data), Partial: s.partial,
		}
		used[i] = h.Handle(p)
	}
	h.Finish()
	return h, used
}

// summary renders "index:Method/CallID" per message.
func summary(h *Handler) string {
	var parts []string
	for _, m := range h.Messages() {
		parts = append(parts, fmt.Sprintf("%d:%s/%s", m.Index, m.Method, m.CallID))
	}
	return strings.Join(parts, " ")
}

// stream splits data into segments of the given sizes (the last one takes the
// rest), numbering them from seq.
func stream(k flowKey, seq uint32, data string, sizes ...int) []seg {
	var out []seg
	for i := 0; len(data) > 0; i++ {
		n := len(data)
		if i < len(sizes) {
			n = min(n, sizes[i])
		}
		out = append(out, seg{k: k, seq: seq, data: data[:n]})
		seq += uint32(n)
		data = data[n:]
	}
	return out
}

func TestTCPFraming(t *testing.T) {
	sdp := "v=0\r\ns=-\r\n"
	a, b, c := msg("INVITE", "a", sdp), msg("BYE", "b", ""), msg("OPTIONS", "c", "xyz")
	all := a + b + c
	c0 := msg("OPTIONS", "c", "")

	tests := []struct {
		name string
		segs []seg
		want string
	}{
		{"one message per segment", append(append(stream(flowAB, 1, a), stream(flowAB, 1+uint32(len(a)), b)...), stream(flowAB, 1+uint32(len(a)+len(b)), c)...), "1:INVITE/a 2:BYE/b 3:OPTIONS/c"},
		{"three messages in one segment", stream(flowAB, 1, all), "1:INVITE/a 1:BYE/b 1:OPTIONS/c"},
		{"split inside the start line", stream(flowAB, 1, a, 10), "1:INVITE/a"},
		{"split inside a header", stream(flowAB, 1, a, 60, 40), "1:INVITE/a"},
		{"split between headers and body", stream(flowAB, 1, a, len(a)-len(sdp)), "1:INVITE/a"},
		{"split inside the body", stream(flowAB, 1, a, len(a)-3), "1:INVITE/a"},
		{"split exactly before CRLFCRLF's second CRLF", stream(flowAB, 1, a, strings.Index(a, "\r\n\r\n")+2), "1:INVITE/a"},
		{"byte at a time", func() []seg {
			s := make([]int, len(all))
			for i := range s {
				s[i] = 1
			}
			return stream(flowAB, 1, all, s...)
		}(), fmt.Sprintf("1:INVITE/a %d:BYE/b %d:OPTIONS/c", len(a)+1, len(a)+len(b)+1)}, // each is placed at the packet carrying its first byte
		{"messages straddling segments", stream(flowAB, 1, all, len(a)+5, len(b)), "1:INVITE/a 1:BYE/b 2:OPTIONS/c"},
		{"CRLFCRLF keep-alives between messages", stream(flowAB, 1, "\r\n\r\n"+a+"\r\n\r\n"+b+"\r\n\r\n\r\n\r\n"), "1:INVITE/a 1:BYE/b"},
		{"keep-alive-only segments", append(stream(flowAB, 1, "\r\n\r\n"), stream(flowAB, 5, a)...), "2:INVITE/a"},
		{"retransmitted segment", append(stream(flowAB, 1, a), append(stream(flowAB, 1, a), stream(flowAB, 1+uint32(len(a)), b)...)...), "1:INVITE/a 3:BYE/b"},
		{"retransmission overlapping new data", []seg{
			{k: flowAB, seq: 1, data: a[:50]},
			{k: flowAB, seq: 1, data: a[:80]},
			{k: flowAB, seq: 41, data: a[40:]},
		}, "1:INVITE/a"},
		{"out-of-order segments", []seg{
			{k: flowAB, seq: 1, data: a[:40]},
			{k: flowAB, seq: 41 + 60, data: a[100:]},
			{k: flowAB, seq: 41, data: a[40:100]},
		}, "1:INVITE/a"},
		{"content-length 0 and no body", stream(flowAB, 1, msg("ACK", "z", "")), "1:ACK/z"},
		{"compact l header", stream(flowAB, 1, strings.Replace(a, "Content-Length: ", "l: ", 1)+b), "1:INVITE/a 1:BYE/b"},
		{"no Content-Length means no body", stream(flowAB, 1, strings.Replace(b, "Content-Length: 0\r\n", "", 1)+a), "1:BYE/b 1:INVITE/a"},
		{"bare LF framing", stream(flowAB, 1, strings.ReplaceAll(b+c0, "\r\n", "\n")), "1:BYE/b 1:OPTIONS/c"},
		{"sequence number wrap", func() []seg {
			s := stream(flowAB, 0xffffffff-uint32(len(a)/2), a, len(a)/2+1)
			return append(s, stream(flowAB, 0xffffffff-uint32(len(a)/2)+uint32(len(a)), b)...)
		}(), "1:INVITE/a 3:BYE/b"},
		{"SYN with fast-open data", []seg{{k: flowAB, seq: 99, data: a, syn: true}, {k: flowAB, seq: 100 + uint32(len(a)), data: b}}, "1:INVITE/a 2:BYE/b"},
		{"mid-stream capture: tail of a message ignored", append(stream(flowAB, 500, "ssion-Info: x\r\nContent-Length: 0\r\n\r\n"), stream(flowAB, 540, a)...), "2:INVITE/a"},
		{"binary garbage before and between messages", stream(flowAB, 1, "\x16\x03\x01\x02\x00garbage\x00\x01\n"+a+"\xff\xfe junk without newline"+"\n"+b), "1:INVITE/a 1:BYE/b"},
		{"garbage only", stream(flowAB, 1, "GET / HTTP/1.1\r\nHost: x\r\n\r\nHTTP/1.1 200 OK\r\n\r\n\x00\x01\x02"), ""},
		{"TLS records are ignored", stream(flowAB, 1, "\x16\x03\x03\x00\x20"+strings.Repeat("\x8a\x11", 50)), ""},
		{"two directions are separate streams", append(stream(flowAB, 1, a[:100]), append(stream(flowKey{tcpB, tcpA, 5060, 40000}, 7000, msg("OPTIONS", "r", "")), stream(flowAB, 101, a[100:])...)...), "1:INVITE/a 2:OPTIONS/r"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h, _ := feed(t, ParseOptions{}, tc.segs...)
			if got := summary(h); got != tc.want {
				t.Fatalf("got  %q\nwant %q", got, tc.want)
			}
		})
	}
}

func TestTCPMessageContent(t *testing.T) {
	sdp := "v=0\r\nm=audio 4000 RTP/AVP 0\r\n"
	a := msg("INVITE", "a", sdp)
	h, used := feed(t, ParseOptions{}, stream(flowAB, 1, a, 120, 77)...)
	for i, u := range used {
		if !u {
			t.Errorf("segment %d not consumed", i)
		}
	}
	ms := h.Messages()
	if len(ms) != 1 {
		t.Fatalf("messages = %d", len(ms))
	}
	m := ms[0]
	if m.Raw != a || m.HeaderEnd != len(a)-len(sdp) || m.Body() != sdp {
		t.Errorf("Raw/HeaderEnd/Body wrong: len(Raw)=%d HeaderEnd=%d", len(m.Raw), m.HeaderEnd)
	}
	if m.File != "x.pcap" || m.Index != 1 || !m.Time.Equal(t0) || m.Transport != "TCP" ||
		m.Src != tcpA || m.Dst != tcpB || m.SrcPort != 40000 || m.DstPort != 5060 {
		t.Errorf("metadata = %+v", m)
	}
	if m.CallID != "a" || m.Via == "" || m.Branch() != "z9hG4bKa" {
		t.Errorf("fields = %+v", m)
	}
}

func TestTCPBodyModes(t *testing.T) {
	json := strings.Replace(msg("MESSAGE", "j", `{"a":1}`), "application/sdp", "application/json", 1)
	sdp := msg("INVITE", "s", "v=0\r\n")
	for _, tc := range []struct {
		mode     BodyMode
		wantJSON string
		wantSDP  string
	}{
		{BodySDP, "", "v=0\r\n"},
		{BodyNone, "", ""},
		{BodyAll, `{"a":1}`, "v=0\r\n"},
	} {
		h, _ := feed(t, ParseOptions{Bodies: tc.mode}, stream(flowAB, 1, json+sdp, 30)...)
		ms := h.Messages()
		if len(ms) != 2 || ms[0].Body() != tc.wantJSON || ms[1].Body() != tc.wantSDP {
			t.Errorf("mode %v: %d messages, bodies %q / %q", tc.mode, len(ms), ms[0].Body(), ms[1].Body())
		}
	}
}

func TestTCPOversizedBodyIsSkipped(t *testing.T) {
	big := strings.Repeat("a=x\r\n", 40000) // 200 KB
	a, b := msg("INVITE", "a", big), msg("BYE", "b", "")
	h, _ := feed(t, ParseOptions{}, stream(flowAB, 1, a+b, 1400)...)
	ms := h.Messages()
	if len(ms) != 2 || ms[0].CallID != "a" || ms[1].CallID != "b" {
		t.Fatalf("messages = %s", summary(h))
	}
	if len(ms[0].Raw) != MaxMessageSize {
		t.Errorf("len(Raw) = %d, want %d", len(ms[0].Raw), MaxMessageSize)
	}
	if ms[0].Index != 1 || ms[1].Index <= 1 {
		t.Errorf("indexes = %d, %d", ms[0].Index, ms[1].Index)
	}
}

func TestTCPContentLengthLies(t *testing.T) {
	a, b := msg("INVITE", "a", "v=0\r\n"), msg("BYE", "b", "")
	t.Run("too large: swallows what follows, flushed at the end", func(t *testing.T) {
		h, _ := feed(t, ParseOptions{}, stream(flowAB, 1, strings.Replace(a, "Content-Length: 5", "Content-Length: 99999", 1)+b)...)
		if got := summary(h); got != "1:INVITE/a" {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("huge value does not allocate or hang", func(t *testing.T) {
		h, _ := feed(t, ParseOptions{}, stream(flowAB, 1, strings.Replace(a, "Content-Length: 5", "Content-Length: 4294967295", 1), 100)...)
		if got := summary(h); got != "1:INVITE/a" {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("too small: the rest of the body is garbage and the stream resyncs", func(t *testing.T) {
		h, _ := feed(t, ParseOptions{}, stream(flowAB, 1, strings.Replace(a, "Content-Length: 5", "Content-Length: 2", 1)+b)...)
		if got := summary(h); got != "1:INVITE/a 1:BYE/b" {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("negative and garbage values count as zero", func(t *testing.T) {
		for _, v := range []string{"-5", "abc", "", "1e3", "5 5"} {
			h, _ := feed(t, ParseOptions{}, stream(flowAB, 1, strings.Replace(a, "Content-Length: 5", "Content-Length: "+v, 1)+b)...)
			if got := summary(h); !strings.HasSuffix(got, "BYE/b") {
				t.Errorf("Content-Length %q: got %q", v, got)
			}
		}
	})
}

func TestTCPLossAndTeardown(t *testing.T) {
	a, b := msg("INVITE", "a", "v=0\r\n"), msg("BYE", "b", "")
	cut := strings.Index(a, "Content-Type") // whole header lines only
	t.Run("lost segment in the middle: message cut, stream resyncs", func(t *testing.T) {
		segs := []seg{
			{k: flowAB, seq: 1, data: a[:cut]},
			// the rest of the message never arrives
			{k: flowAB, seq: 1 + uint32(len(a)), data: b},
		}
		h, _ := feed(t, ParseOptions{}, segs...)
		if got := summary(h); got != "1:INVITE/a 2:BYE/b" {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("FIN flushes a half message", func(t *testing.T) {
		h, _ := feed(t, ParseOptions{}, seg{k: flowAB, seq: 1, data: a[:150], fin: true})
		if got := summary(h); got != "1:INVITE/a" {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("RST flushes and a reused 4-tuple starts clean", func(t *testing.T) {
		h, _ := feed(t, ParseOptions{},
			seg{k: flowAB, seq: 1, data: a[:150]},
			seg{k: flowAB, seq: 151, rst: true},
			seg{k: flowAB, seq: 5000, syn: true},
			seg{k: flowAB, seq: 5001, data: b},
		)
		if got := summary(h); got != "1:INVITE/a 4:BYE/b" {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("end of file flushes", func(t *testing.T) {
		h, _ := feed(t, ParseOptions{}, seg{k: flowAB, seq: 1, data: a[:200]})
		if got := summary(h); got != "1:INVITE/a" {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("a header cut mid-line by the flush is dropped", func(t *testing.T) {
		cut := strings.Index(a, "Call-ID") + 9
		h, _ := feed(t, ParseOptions{}, seg{k: flowAB, seq: 1, data: a[:cut]})
		ms := h.Messages()
		if len(ms) != 1 || ms[0].CallID != "" || ms[0].From == "" {
			t.Fatalf("got %+v", ms)
		}
	})
	t.Run("snaplen-cut segment ends the stream position", func(t *testing.T) {
		h, _ := feed(t, ParseOptions{},
			seg{k: flowAB, seq: 1, data: a[:cut], partial: true},
			seg{k: flowAB, seq: 1 + uint32(len(a)), data: b},
		)
		if got := summary(h); got != "1:INVITE/a 2:BYE/b" {
			t.Fatalf("got %q", got)
		}
	})
}
