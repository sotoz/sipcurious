package sip

import (
	"fmt"
	"math/rand/v2"
	"net/netip"
	"sort"
	"strings"
	"testing"

	"github.com/sotoz/sipcurious/internal/capture"
)

// callIDs lists the Call-IDs of the messages in order.
func callIDs(h *Handler) string {
	var ids []string
	for _, m := range h.Messages() {
		ids = append(ids, m.Method+"/"+m.CallID)
	}
	sort.Strings(ids) // reordered segments change the packet each message starts in
	return strings.Join(ids, " ")
}

// TestTCPAnySegmentation (the message list is compared as a set because
// reordering changes the packet a message starts in): however a clean stream is cut into segments,
// retransmitted, duplicated and (within the reorder budget) shuffled, the same
// messages come out as from one big segment.
func TestTCPAnySegmentation(t *testing.T) {
	var stream0 strings.Builder
	for i := range 12 {
		body := ""
		if i%3 == 0 {
			body = strings.Repeat("a=rtpmap:0 PCMU/8000\r\n", i+1)
		}
		method := []string{"INVITE", "ACK", "BYE", "OPTIONS"}[i%4]
		stream0.WriteString(msg(method, fmt.Sprint("id", i), body))
		if i%5 == 4 {
			stream0.WriteString("\r\n\r\n")
		}
	}
	data := stream0.String()
	base, _ := feed(t, ParseOptions{}, seg{k: flowAB, seq: 1000, data: data})
	want := callIDs(base)
	if n := len(base.Messages()); n != 12 {
		t.Fatalf("baseline has %d messages", n)
	}

	for seed := range uint64(300) {
		rng := rand.New(rand.NewPCG(seed, 99))
		var segs []seg
		for pos := 0; pos < len(data); {
			n := 1 + rng.IntN(1+rng.IntN(600))
			n = min(n, len(data)-pos)
			segs = append(segs, seg{k: flowAB, seq: 1000 + uint32(pos), data: data[pos : pos+n]})
			pos += n
		}
		// retransmit some, with random overlap into the past
		var mixed []seg
		for i, s := range segs {
			mixed = append(mixed, s)
			if rng.IntN(5) == 0 && i > 0 {
				back := segs[rng.IntN(i)]
				mixed = append(mixed, back)
			}
		}
		// swap a few adjacent segments (stays inside the reorder budget)
		for i := 1; i+1 < len(mixed); i++ { // the first segment opens the stream
			if rng.IntN(8) == 0 {
				mixed[i], mixed[i+1] = mixed[i+1], mixed[i]
			}
		}
		h, _ := feed(t, ParseOptions{}, mixed...)
		if got := callIDs(h); got != want {
			t.Fatalf("seed %d (%d segments):\n got %s\nwant %s", seed, len(mixed), got, want)
		}
		raws := map[string]string{}
		for _, m := range base.Messages() {
			raws[m.CallID] = m.Raw
		}
		for _, m := range h.Messages() {
			if m.Raw != raws[m.CallID] {
				t.Fatalf("seed %d: message %s Raw differs", seed, m.CallID)
			}
		}
	}
}

// TestTCPBoundedMemory: many half-open flows must not grow without limit and
// never exceed the tracked-flow cap.
func TestTCPBoundedMemory(t *testing.T) {
	h := &Handler{file: "x"}
	half := msg("INVITE", "x", "")[:80]
	for i := range 5 * maxFlows {
		src := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		p := &capture.Packet{Index: i + 1, Src: src, Dst: tcpB, SrcPort: 1000, DstPort: 5060, Transport: "TCP", TCPSeq: 1, Payload: []byte(half)}
		h.Handle(p)
		if len(h.flows) > maxFlows {
			t.Fatalf("%d flows tracked after %d packets, cap %d", len(h.flows), i+1, maxFlows)
		}
	}
	h.Finish()
	if len(h.flows) != 0 {
		t.Errorf("%d flows left after Finish", len(h.flows))
	}
	if got := len(h.Messages()); got != 5*maxFlows {
		t.Errorf("messages = %d, want every half message flushed (%d)", got, 5*maxFlows)
	}
}

// TestTCPReorderBudget: a stream whose first segment never arrives must not
// pile up segments forever.
func TestTCPReorderBudget(t *testing.T) {
	a := msg("INVITE", "a", "")
	h := &Handler{file: "x"}
	// first segment establishes the stream, then a hole, then lots of data
	h.Handle(&capture.Packet{Index: 1, Src: tcpA, Dst: tcpB, SrcPort: 1, DstPort: 2, Transport: "TCP", TCPSeq: 1, Payload: []byte(a[:50])})
	seq := uint32(100000)
	for i := range 1000 {
		h.Handle(&capture.Packet{Index: i + 2, Src: tcpA, Dst: tcpB, SrcPort: 1, DstPort: 2, Transport: "TCP", TCPSeq: seq, Payload: []byte(a)})
		seq += uint32(len(a))
		fl := h.flows[flowKey{tcpA, tcpB, 1, 2}]
		if fl.oooBytes > maxOOOBytes || len(fl.ooo) > maxOOOSegments {
			t.Fatalf("reorder buffer %d segments / %d bytes", len(fl.ooo), fl.oooBytes)
		}
	}
	h.Finish()
	if n := len(h.Messages()); n < 900 {
		t.Errorf("only %d of 1001 messages recovered", n)
	}
}

func TestUDPAndSCTP(t *testing.T) {
	a := msg("INVITE", "u1", "v=0\r\n")
	for _, tr := range []string{"UDP", "SCTP"} {
		h := &Handler{file: "f.pcap"}
		mk := func(i int, payload string, partial bool) *capture.Packet {
			return &capture.Packet{File: "f.pcap", Index: i, Time: t0, Src: tcpA, Dst: tcpB, SrcPort: 5060, DstPort: 5060, Transport: tr, Payload: []byte(payload), Partial: partial}
		}
		if !h.Handle(mk(1, a, false)) {
			t.Errorf("%s: SIP not consumed", tr)
		}
		for _, junk := range []string{"", "\r\n\r\n", "\x00", "hello", "\x80\x00\x00\x01rtp-ish", "HTTP/1.1 200 OK\r\n\r\n"} {
			if h.Handle(mk(2, junk, false)) {
				t.Errorf("%s: %q consumed", tr, junk)
			}
		}
		// A datagram holds ONE message: trailing bytes are not a second message.
		h.Handle(mk(3, msg("BYE", "u2", "")+msg("OPTIONS", "u3", ""), false))
		// snaplen cut: the cut header line is dropped
		h.Handle(mk(4, a[:strings.Index(a, "Call-ID")+9], true))
		ms := h.Messages()
		if len(ms) != 3 || ms[0].Transport != tr || ms[0].Index != 1 || ms[1].Method != "BYE" || ms[2].CallID != "" {
			t.Errorf("%s: messages = %+v", tr, ms)
		}
	}
}

func TestOtherTransportsIgnored(t *testing.T) {
	h := &Handler{}
	if h.Handle(&capture.Packet{Transport: "ICMP", Payload: []byte(msg("INVITE", "x", ""))}) {
		t.Fatal("consumed")
	}
}

func TestMessagesOrderedByIndex(t *testing.T) {
	a := msg("INVITE", "a", "")
	b := msg("BYE", "b", "")
	// b completes in packet 2 but a (packet 1) only completes in packet 3.
	k2 := flowKey{tcpB, tcpA, 5060, 40000}
	h, _ := feed(t, ParseOptions{},
		seg{k: flowAB, seq: 1, data: a[:100]},
		seg{k: k2, seq: 1, data: b},
		seg{k: flowAB, seq: 101, data: a[100:]},
	)
	if got := summary(h); got != "1:INVITE/a 2:BYE/b" {
		t.Fatalf("got %q", got)
	}
}

func FuzzHandler(f *testing.F) {
	a := msg("INVITE", "a", "v=0\r\n")
	f.Add([]byte(a), uint8(3), uint8(7))
	f.Add([]byte(a+a+"\r\n\r\n"+a[:40]), uint8(1), uint8(200))
	f.Add([]byte("\x00\xff\n"+a), uint8(0), uint8(0))
	f.Add([]byte(strings.Replace(a, "Content-Length: 5", "Content-Length: 99999999999", 1)), uint8(9), uint8(1))
	f.Fuzz(func(t *testing.T, data []byte, step, shuffle uint8) {
		h := &Handler{file: "f"}
		n := int(step)%64 + 1
		var segs []*capture.Packet
		for pos, i := 0, 0; pos < len(data); i++ {
			e := min(pos+n+i%3, len(data))
			segs = append(segs, &capture.Packet{Index: i + 1, Src: tcpA, Dst: tcpB, SrcPort: 1, DstPort: 2, Transport: "TCP",
				TCPSeq: 1 + uint32(pos), Payload: data[pos:e], TCPFIN: e == len(data) && shuffle%7 == 0, Partial: shuffle%11 == 0 && i == 1})
			pos = e
		}
		if shuffle > 0 && len(segs) > 2 {
			segs[0], segs[len(segs)-1] = segs[len(segs)-1], segs[0]
		}
		for _, p := range segs {
			h.Handle(p)
		}
		h.Finish()
		for _, m := range h.Messages() {
			if len(m.Raw) > MaxMessageSize || m.HeaderEnd > len(m.Raw) || m.Index < 1 {
				t.Fatalf("bad message: len(Raw)=%d HeaderEnd=%d Index=%d", len(m.Raw), m.HeaderEnd, m.Index)
			}
		}
		if len(h.flows) != 0 {
			t.Fatalf("flows left: %d", len(h.flows))
		}
	})
}
