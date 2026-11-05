package rtp

import (
	"encoding/binary"
	"fmt"
	"math"
	"net/netip"
	"testing"
	"time"

	"github.com/sotoz/sipcurious/internal/capture"
)

var t0 = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

var (
	addrA = netip.MustParseAddr("10.0.1.10")
	addrB = netip.MustParseAddr("10.0.2.20")
)

// feed sends synthetic datagrams to a Handler.
type feed struct {
	h     *Handler
	idx   int
	src   netip.Addr
	dst   netip.Addr
	sport uint16
	dport uint16
	ssrc  uint32
}

func newFeed(opt HandlerOptions) *feed {
	return &feed{h: newHandler("t.pcap", opt), src: addrA, dst: addrB, sport: 16384, dport: 18000, ssrc: 0x11223344}
}

// raw delivers an arbitrary UDP payload.
func (f *feed) raw(at time.Duration, b []byte) bool {
	f.idx++
	p := capture.Packet{File: "t.pcap", Index: f.idx, Time: t0.Add(at), Src: f.src, Dst: f.dst,
		SrcPort: f.sport, DstPort: f.dport, Transport: "UDP", Payload: b}
	return f.h.Handle(&p)
}

// pkt delivers an RTP packet with n payload bytes.
func (f *feed) pkt(at time.Duration, pt byte, seq uint16, ts uint32, n int) {
	f.raw(at, rtpBytes(0x80, pt, seq, ts, f.ssrc, nil, n))
}

// run sends count PCMU packets of 20 ms starting at sequence seq0 with the
// timestamp derived from the sequence number, skipping those drop reports true.
func (f *feed) run(count int, seq0 uint16, pt byte, drop func(i int) bool) {
	for i := 0; i < count; i++ {
		if drop != nil && drop(i) {
			continue
		}
		f.pkt(time.Duration(i)*20*time.Millisecond, pt, seq0+uint16(i), uint32(i)*160, 160)
	}
}

func only(t *testing.T, f *feed) Stream {
	t.Helper()
	ss := f.h.Streams()
	if len(ss) != 1 {
		t.Fatalf("got %d streams, want 1: %+v", len(ss), ss)
	}
	return ss[0]
}

func TestCleanStream(t *testing.T) {
	f := newFeed(HandlerOptions{})
	f.run(100, 1000, 0, nil)
	s := only(t, f)
	if s.Packets != 100 || s.Expected != 100 || s.Lost != 0 || s.LossPct != 0 || s.Duplicates != 0 || s.Reordered != 0 {
		t.Errorf("counts: %+v", s)
	}
	if s.Bytes != 100*160 || s.PayloadType != 0 || s.Codec != "PCMU" || s.ClockRate != 8000 {
		t.Errorf("identity: pt=%d codec=%q rate=%d bytes=%d", s.PayloadType, s.Codec, s.ClockRate, s.Bytes)
	}
	if s.JitterMean != 0 || s.JitterMax != 0 || s.MaxGap != 20*time.Millisecond {
		t.Errorf("timing: jitter %v/%v gap %v", s.JitterMean, s.JitterMax, s.MaxGap)
	}
	if !s.Start.Equal(t0) || !s.End.Equal(t0.Add(99*20*time.Millisecond)) || s.Duration() != 99*20*time.Millisecond {
		t.Errorf("times: %v %v", s.Start, s.End)
	}
	if s.FirstIndex != 1 || s.File != "t.pcap" {
		t.Errorf("origin: %d %q", s.FirstIndex, s.File)
	}
	if s.Src != netip.AddrPortFrom(addrA, 16384) || s.Dst != netip.AddrPortFrom(addrB, 18000) || s.SSRC != 0x11223344 {
		t.Errorf("key: %+v", s.Key)
	}
	wantR, wantMOS := Quality("PCMU", 0, 0)
	if s.RFactor != wantR || s.MOS != wantMOS || s.MOS < 4.3 {
		t.Errorf("quality: R=%v MOS=%v", s.RFactor, s.MOS)
	}
}

func TestLossPatterns(t *testing.T) {
	tests := []struct {
		name     string
		count    int
		seq0     uint16
		drop     func(i int) bool
		wantLost int64
		wantExp  uint64
		wantGap  time.Duration
	}{
		{"single", 100, 0, func(i int) bool { return i == 50 }, 1, 100, 40 * time.Millisecond},
		{"burst of 10", 100, 0, func(i int) bool { return i >= 40 && i < 50 }, 10, 100, 220 * time.Millisecond},
		{"every 10th", 100, 5, func(i int) bool { return i%10 == 5 }, 10, 100, 40 * time.Millisecond},
		{"across wrap", 100, 65500, func(i int) bool { return i >= 30 && i < 45 }, 15, 100, 320 * time.Millisecond},
		{"first packets lost are not visible", 100, 0, func(i int) bool { return i < 3 }, 0, 97, 20 * time.Millisecond},
		{"last packets lost are not visible", 100, 0, func(i int) bool { return i >= 95 }, 0, 95, 20 * time.Millisecond},
	}
	for _, tc := range tests {
		f := newFeed(HandlerOptions{})
		f.run(tc.count, tc.seq0, 0, tc.drop)
		s := only(t, f)
		recv := uint64(0)
		for i := 0; i < tc.count; i++ {
			if !tc.drop(i) {
				recv++
			}
		}
		if s.Packets != recv || s.Expected != tc.wantExp || s.Lost != int64(tc.wantExp)-int64(recv) {
			t.Errorf("%s: packets=%d expected=%d lost=%d; want packets=%d expected=%d", tc.name, s.Packets, s.Expected, s.Lost, recv, tc.wantExp)
		}
		if s.Lost != tc.wantLost {
			t.Errorf("%s: lost=%d want %d", tc.name, s.Lost, tc.wantLost)
		}
		wantPct := 100 * float64(s.Lost) / float64(s.Expected)
		if math.Abs(s.LossPct-wantPct) > 1e-9 {
			t.Errorf("%s: loss%% = %v, want %v", tc.name, s.LossPct, wantPct)
		}
		if s.MaxGap != tc.wantGap {
			t.Errorf("%s: MaxGap = %v, want %v", tc.name, s.MaxGap, tc.wantGap)
		}
		if s.Duplicates != 0 || s.Reordered != 0 {
			t.Errorf("%s: dup=%d reorder=%d", tc.name, s.Duplicates, s.Reordered)
		}
	}
}

func TestSequenceWrap(t *testing.T) {
	f := newFeed(HandlerOptions{})
	f.run(200, 65436, 0, nil) // seq 65436 .. 65535, 0 .. 99
	s := only(t, f)
	if s.Expected != 200 || s.Lost != 0 || s.Packets != 200 {
		t.Errorf("wrap: %+v", s)
	}
}

func TestSeveralWraps(t *testing.T) {
	f := newFeed(HandlerOptions{})
	for i := 0; i < 3*65536; i++ {
		f.pkt(time.Duration(i)*20*time.Millisecond, 0, uint16(i+7), uint32(i)*160, 20)
	}
	s := only(t, f)
	if s.Expected != 3*65536 || s.Lost != 0 {
		t.Errorf("three wraps: expected=%d lost=%d", s.Expected, s.Lost)
	}
}

func TestReorderAndDuplicates(t *testing.T) {
	f := newFeed(HandlerOptions{})
	// Arrival order of sequence numbers; timestamps follow the sequence number.
	order := []int{0, 1, 2, 3, 4, 6, 5, 7, 8, 9, 10, 11, 12, 12, 13, 14, 15, 16, 14, 17, 19, 18, 20}
	for i, seq := range order {
		f.pkt(time.Duration(i)*20*time.Millisecond, 0, uint16(seq), uint32(seq)*160, 160)
	}
	s := only(t, f)
	// Late arrivals: 5 (reordered), 18 (reordered). Duplicates: 12 and 14 (14 arrives again after 16).
	if s.Packets != uint64(len(order)) || s.Expected != 21 {
		t.Errorf("packets=%d expected=%d", s.Packets, s.Expected)
	}
	if s.Reordered != 2 || s.Duplicates != 2 {
		t.Errorf("reordered=%d duplicates=%d, want 2 and 2", s.Reordered, s.Duplicates)
	}
	if s.Lost != int64(s.Expected)-int64(s.Packets) || s.Lost != -2 || s.LossPct != 0 {
		t.Errorf("lost=%d loss%%=%v: duplicates make Lost negative, LossPct is clamped to 0", s.Lost, s.LossPct)
	}
}

func TestReorderedFirstPackets(t *testing.T) {
	f := newFeed(HandlerOptions{})
	for i, seq := range []int{10, 12, 11, 9, 13, 14, 15, 16} {
		f.pkt(time.Duration(i)*20*time.Millisecond, 0, uint16(seq), uint32(seq)*160, 160)
	}
	s := only(t, f)
	if s.Expected != 8 || s.Lost != 0 || s.Reordered != 2 {
		t.Errorf("expected=%d lost=%d reordered=%d", s.Expected, s.Lost, s.Reordered)
	}
}

func TestSenderRestart(t *testing.T) {
	f := newFeed(HandlerOptions{})
	for i := 0; i < 100; i++ {
		f.pkt(time.Duration(i)*20*time.Millisecond, 0, uint16(5000+i), uint32(i)*160, 160)
	}
	for i := 0; i < 100; i++ { // same SSRC, sequence numbers restart at 100
		f.pkt(time.Duration(100+i)*20*time.Millisecond, 0, uint16(100+i), uint32(900000+i*160), 160)
	}
	s := only(t, f)
	if s.Packets != 200 || s.Expected != 200 || s.Lost != 0 {
		t.Errorf("restart: packets=%d expected=%d lost=%d", s.Packets, s.Expected, s.Lost)
	}
}

func TestStrayPacket(t *testing.T) {
	f := newFeed(HandlerOptions{})
	for i := 0; i < 50; i++ {
		f.pkt(time.Duration(i)*20*time.Millisecond, 0, uint16(i), uint32(i)*160, 160)
	}
	f.pkt(time.Second, 0, 40000, 123, 160) // one corrupted sequence number
	for i := 50; i < 100; i++ {
		f.pkt(time.Duration(i+1)*20*time.Millisecond, 0, uint16(i), uint32(i)*160, 160)
	}
	s := only(t, f)
	if s.Packets != 101 || s.Expected != 101 || s.Lost != 0 || s.Duplicates != 0 || s.Reordered != 0 {
		t.Errorf("stray: %+v", s)
	}
}

func TestSSRCChange(t *testing.T) {
	f := newFeed(HandlerOptions{})
	f.run(50, 100, 0, nil)
	f.ssrc = 0x99887766
	for i := 0; i < 50; i++ {
		f.pkt(time.Second+time.Duration(i)*20*time.Millisecond, 8, uint16(7000+i), uint32(i)*160, 160)
	}
	ss := f.h.Streams()
	if len(ss) != 2 {
		t.Fatalf("got %d streams, want 2", len(ss))
	}
	if ss[0].SSRC != 0x11223344 || ss[1].SSRC != 0x99887766 || ss[0].Codec != "PCMU" || ss[1].Codec != "PCMA" {
		t.Errorf("streams: %+v / %+v", ss[0].Key, ss[1].Key)
	}
	for _, s := range ss {
		if s.Packets != 50 || s.Expected != 50 || s.Lost != 0 || s.Src != ss[0].Src || s.Dst != ss[0].Dst {
			t.Errorf("stream %08x: %+v", s.SSRC, s)
		}
	}
	if ss[1].FirstIndex != 51 {
		t.Errorf("FirstIndex = %d, want 51", ss[1].FirstIndex)
	}
}

func TestDirectionsAreSeparateStreams(t *testing.T) {
	f := newFeed(HandlerOptions{})
	f.run(20, 0, 0, nil)
	f.src, f.dst, f.sport, f.dport = f.dst, f.src, f.dport, f.sport
	f.run(20, 0, 0, nil) // same SSRC, reversed 4-tuple
	if n := len(f.h.Streams()); n != 2 {
		t.Errorf("got %d streams, want 2", n)
	}
}

// jitterModel replays the RFC 3550 A.8 recurrence for per-packet delays.
func jitterModel(delays []time.Duration, step time.Duration) (mean, maxJ float64) {
	var j, sum float64
	var prev float64
	for i, d := range delays {
		tr := d.Seconds()
		if i > 0 {
			j += (math.Abs(tr-prev) - j) / 16
			sum += j
			maxJ = math.Max(maxJ, j)
		}
		prev = tr
	}
	return sum / float64(len(delays)-1), maxJ
}

func TestJitterMatchesRFC3550(t *testing.T) {
	f := newFeed(HandlerOptions{})
	delays := make([]time.Duration, 300)
	for i := range delays {
		// Deterministic pseudo-random delay 0..9 ms.
		delays[i] = time.Duration((i*7919+13)%10) * time.Millisecond
		f.pkt(time.Duration(i)*20*time.Millisecond+delays[i], 0, uint16(i), uint32(i)*160, 160)
	}
	s := only(t, f)
	mean, mx := jitterModel(delays, 20*time.Millisecond)
	if math.Abs(s.JitterMean.Seconds()-mean) > 2e-6 || math.Abs(s.JitterMax.Seconds()-mx) > 2e-6 {
		t.Errorf("jitter mean/max = %v/%v, want %.6fs/%.6fs", s.JitterMean, s.JitterMax, mean, mx)
	}
	if s.JitterMax < s.JitterMean || s.JitterMean <= 0 {
		t.Errorf("jitter ordering: %v %v", s.JitterMean, s.JitterMax)
	}
}

func TestJitterClockRates(t *testing.T) {
	// 20 ms packets with alternating 0/4 ms arrival delay: |D| = 4 ms each step.
	for _, tc := range []struct {
		name  string
		pt    byte
		step  uint32 // timestamp ticks per packet
		rate  int
		codec string
		fmts  map[uint8]Format
	}{
		{"PCMU static", 0, 160, 8000, "PCMU", nil},
		{"G722 timestamps run at 8000", 9, 160, 8000, "G722", nil},
		{"opus via SetFormats", 111, 960, 48000, "opus", map[uint8]Format{111: {"opus", 48000}}},
		{"unknown dynamic 8k estimated", 100, 160, 8000, "", nil},
		{"unknown dynamic 16k estimated", 100, 320, 16000, "", nil},
		{"unknown dynamic 32k estimated", 100, 640, 32000, "", nil},
		{"unknown dynamic 48k estimated", 100, 960, 48000, "", nil},
		{"unknown dynamic 90k estimated", 100, 1800, 90000, "", nil},
		{"hint overrides name", 96, 320, 16000, "AMR-WB", map[uint8]Format{96: {"AMR-WB", 16000}}},
	} {
		f := newFeed(HandlerOptions{Formats: tc.fmts})
		var delays []time.Duration
		for i := 0; i < 200; i++ {
			d := time.Duration(i%2) * 4 * time.Millisecond
			delays = append(delays, d)
			f.pkt(time.Duration(i)*20*time.Millisecond+d, tc.pt, uint16(i), uint32(i)*tc.step, 100)
		}
		s := only(t, f)
		mean, _ := jitterModel(delays, 0)
		if s.ClockRate != tc.rate || s.Codec != tc.codec {
			t.Errorf("%s: rate=%d codec=%q, want %d %q", tc.name, s.ClockRate, s.Codec, tc.rate, tc.codec)
		}
		if math.Abs(s.JitterMean.Seconds()-mean) > 2e-6 {
			t.Errorf("%s: jitter mean %v, want %.6fs", tc.name, s.JitterMean, mean)
		}
	}
}

func TestSetFormatsAfterPackets(t *testing.T) {
	f := newFeed(HandlerOptions{})
	for i := 0; i < 50; i++ {
		f.pkt(time.Duration(i)*20*time.Millisecond, 111, uint16(i), uint32(i)*960, 60)
	}
	f.h.SetFormats(map[uint8]Format{111: {"opus", 48000}, 200: {"x", 1}})
	s := only(t, f)
	if s.Codec != "opus" || s.ClockRate != 48000 || s.PayloadType != 111 {
		t.Errorf("late hint: %q %d pt=%d", s.Codec, s.ClockRate, s.PayloadType)
	}
	r, m := Quality("opus", 0, 0)
	if s.RFactor != r || s.MOS != m {
		t.Errorf("opus quality %v/%v, want %v/%v", s.RFactor, s.MOS, r, m)
	}
}

func TestJitterIgnoresTimestampRebase(t *testing.T) {
	f := newFeed(HandlerOptions{})
	for i := 0; i < 50; i++ {
		f.pkt(time.Duration(i)*20*time.Millisecond, 0, uint16(i), uint32(i)*160, 160)
	}
	// Sender re-bases its timestamps by 10 minutes; sequence numbers continue.
	for i := 50; i < 100; i++ {
		f.pkt(time.Duration(i)*20*time.Millisecond, 0, uint16(i), uint32(i)*160+48_000_000, 160)
	}
	s := only(t, f)
	if s.JitterMax > time.Millisecond || s.Lost != 0 {
		t.Errorf("jitter max %v, lost %d", s.JitterMax, s.Lost)
	}
}

func TestComfortNoiseAndDTX(t *testing.T) {
	f := newFeed(HandlerOptions{})
	seq, ts := uint16(0), uint32(0)
	at := time.Duration(0)
	for i := 0; i < 60; i++ { // 1.2 s of speech
		f.pkt(at, 0, seq, ts, 160)
		seq, ts, at = seq+1, ts+160, at+20*time.Millisecond
	}
	f.pkt(at, 13, seq, ts, 1) // CN frame, then silence suppression
	seq++
	at += 3 * time.Second // DTX: nothing sent, timestamp follows the clock
	ts += 3 * 8000
	for i := 0; i < 40; i++ { // speech resumes with marker bit
		b := rtpBytes(0x80, 0x80, seq, ts, f.ssrc, nil, 160)
		f.raw(at, b)
		seq, ts, at = seq+1, ts+160, at+20*time.Millisecond
	}
	s := only(t, f)
	if s.Lost != 0 || s.Expected != 101 || s.Packets != 101 || s.LossPct != 0 {
		t.Errorf("DTX is not loss: packets=%d expected=%d lost=%d", s.Packets, s.Expected, s.Lost)
	}
	if s.MaxGap != 3*time.Second {
		t.Errorf("MaxGap = %v", s.MaxGap)
	}
	if s.PayloadType != 0 || s.Codec != "PCMU" {
		t.Errorf("PT = %d %q: comfort noise must not become the stream PT", s.PayloadType, s.Codec)
	}
	if s.JitterMax > time.Millisecond {
		t.Errorf("DTX gap leaked into jitter: %v", s.JitterMax)
	}
	if s.MOS < 4.3 {
		t.Errorf("MOS = %v", s.MOS)
	}
}

func TestMostFrequentPayloadType(t *testing.T) {
	f := newFeed(HandlerOptions{})
	for i := 0; i < 100; i++ {
		pt := byte(8)
		if i%10 == 3 {
			pt = 0
		}
		f.pkt(time.Duration(i)*20*time.Millisecond, pt, uint16(i), uint32(i)*160, 160)
	}
	if s := only(t, f); s.PayloadType != 8 || s.Codec != "PCMA" {
		t.Errorf("PT = %d %q", s.PayloadType, s.Codec)
	}
}

// dtmf sends one telephone-event (RFC 4733) of the given duration in 20 ms
// steps: start marker, updates, three end packets. Returns the next sequence
// number.
func (f *feed) dtmf(at time.Duration, pt byte, seq uint16, ts uint32, digit byte, steps int) uint16 {
	for i := 0; i < steps+3; i++ {
		b := rtpBytes(0x80, pt, seq, ts, f.ssrc, nil, 4)
		if i == 0 {
			b[1] |= 0x80
		}
		end := byte(0)
		if i >= steps {
			end = 0x80
		}
		dur := uint16(160 * (min(i, steps-1) + 1))
		b[12], b[13], b[14], b[15] = digit, end|10, byte(dur>>8), byte(dur)
		f.raw(at+time.Duration(i)*20*time.Millisecond, b)
		seq++
	}
	return seq
}

func TestTelephoneEvent(t *testing.T) {
	for _, withHint := range []bool{true, false} {
		t.Run(fmt.Sprint("hint=", withHint), func(t *testing.T) {
			opt := HandlerOptions{}
			if withHint {
				opt.Formats = map[uint8]Format{101: {"telephone-event", 8000}}
			}
			f := newFeed(opt)
			seq, ts := uint16(0), uint32(0)
			media := func(n int, at0 time.Duration) {
				for i := 0; i < n; i++ {
					f.pkt(at0+time.Duration(i)*20*time.Millisecond, 0, seq, ts, 160)
					seq, ts = seq+1, ts+160
				}
			}
			media(30, 0)
			evTS := ts
			seq = f.dtmf(600*time.Millisecond, 101, seq, evTS, 5, 8) // 11 packets, one event
			ts += 11 * 160
			media(30, 820*time.Millisecond)
			seq = f.dtmf(1420*time.Millisecond, 101, seq, ts, 7, 4)
			ts += 7 * 160
			media(20, 1560*time.Millisecond)
			s := only(t, f)
			if s.DTMFEvents != 2 {
				t.Errorf("DTMFEvents = %d, want 2", s.DTMFEvents)
			}
			if s.PayloadType != 0 || s.Codec != "PCMU" {
				t.Errorf("PT = %d %q", s.PayloadType, s.Codec)
			}
			if s.Lost != 0 || s.Expected != s.Packets {
				t.Errorf("events are packets in the sequence space: expected=%d packets=%d lost=%d", s.Expected, s.Packets, s.Lost)
			}
			if s.Packets != 80+11+7 {
				t.Errorf("Packets = %d", s.Packets)
			}
			if s.JitterMax > time.Millisecond {
				t.Errorf("event packets leaked into jitter: %v", s.JitterMax)
			}
		})
	}
}

func TestSRTPLikePayload(t *testing.T) {
	// Opaque payload: random-looking bytes, padding bit clear, plus a 10 byte
	// authentication tag; the last byte (tag) is a big "pad count" if the
	// padding bit were set. Headers stay readable.
	f := newFeed(HandlerOptions{})
	x := uint32(1)
	for i := 0; i < 100; i++ {
		b := rtpBytes(0x80, 0, uint16(i), uint32(i)*160, f.ssrc, nil, 170)
		for j := 12; j < len(b); j++ {
			x = x*1664525 + 1013904223
			b[j] = byte(x >> 24)
		}
		f.raw(time.Duration(i)*20*time.Millisecond, b)
	}
	s := only(t, f)
	if s.Packets != 100 || s.Lost != 0 || s.Bytes != 100*170 || s.DTMFEvents != 0 || s.Codec != "PCMU" {
		t.Errorf("srtp: %+v", s)
	}
	// With the extension bit and padding bit set but nonsense contents the
	// header must still be handled without trouble.
	g := newFeed(HandlerOptions{})
	for i := 0; i < 20; i++ {
		b := rtpBytes(0xb0, 111, uint16(i), uint32(i)*960, g.ssrc, []byte{0xbe, 0xde, 0, 1, 1, 2, 3, 4}, 50)
		b[len(b)-1] = 0xff
		g.raw(time.Duration(i)*20*time.Millisecond, b)
	}
	if s := only(t, g); s.Packets != 20 || s.Bytes != 20*50 {
		t.Errorf("srtp ext: packets=%d bytes=%d", s.Packets, s.Bytes)
	}
}

func TestDetection(t *testing.T) {
	t.Run("fewer than five packets are not a stream", func(t *testing.T) {
		f := newFeed(HandlerOptions{})
		f.run(4, 0, 0, nil)
		if n := len(f.h.Streams()); n != 0 {
			t.Errorf("%d streams", n)
		}
		f.pkt(time.Second, 0, 4, 640, 160)
		if n := len(f.h.Streams()); n != 1 {
			t.Errorf("%d streams after the fifth packet", n)
		}
	})
	t.Run("MinPackets", func(t *testing.T) {
		f := newFeed(HandlerOptions{MinPackets: 10})
		f.run(9, 0, 0, nil)
		if len(f.h.Streams()) != 0 {
			t.Error("reported at 9")
		}
		f.pkt(time.Second, 0, 9, 1440, 160)
		if len(f.h.Streams()) != 1 {
			t.Error("not reported at 10")
		}
	})
	t.Run("random sequence numbers are not a stream", func(t *testing.T) {
		f := newFeed(HandlerOptions{})
		for i, seq := range []uint16{10, 9000, 31, 50000, 7, 20000, 40000, 3, 12345, 60000} {
			f.pkt(time.Duration(i)*20*time.Millisecond, 0, seq, 0, 100)
		}
		if n := len(f.h.Streams()); n != 0 {
			t.Errorf("%d streams", n)
		}
	})
	t.Run("loss during probation tolerated", func(t *testing.T) {
		f := newFeed(HandlerOptions{})
		for i, seq := range []uint16{10, 12, 20, 21, 50, 51} {
			f.pkt(time.Duration(i)*20*time.Millisecond, 0, seq, uint32(seq)*160, 100)
		}
		s := only(t, f)
		if s.Packets != 6 || s.Expected != 42 {
			t.Errorf("packets=%d expected=%d", s.Packets, s.Expected)
		}
	})
	t.Run("a different SSRC does not extend the probation of another", func(t *testing.T) {
		f := newFeed(HandlerOptions{})
		for i := 0; i < 8; i++ {
			f.ssrc = uint32(i)
			f.pkt(time.Duration(i)*20*time.Millisecond, 0, uint16(i), 0, 100)
		}
		if n := len(f.h.Streams()); n != 0 {
			t.Errorf("%d streams", n)
		}
	})
	t.Run("not consumed", func(t *testing.T) {
		stun := make([]byte, 28)
		stun[1] = 1 // binding request
		binary.BigEndian.PutUint16(stun[2:], 8)
		copy(stun[4:], []byte{0x21, 0x12, 0xa4, 0x42})
		stunV2 := append([]byte(nil), stun...)
		stunV2[0] = 0x80 // even a "V=2" lookalike with the cookie must not become a stream
		dtls := []byte{22, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 40, 1, 0, 0, 0, 0, 0, 0}
		tests := []struct {
			name string
			b    []byte
			ptOK bool
		}{
			{"stun", stun, false},
			{"dtls", dtls, false},
			{"short", []byte{0x80, 0, 0, 1}, false},
			{"empty", nil, false},
			{"version 1", rtpBytes(0x40, 0, 1, 2, 3, nil, 100), false},
			{"sip", []byte("INVITE sip:a@b SIP/2.0\r\n\r\n"), false},
			{"implausible pt 72", rtpBytes(0x80, 72, 1, 2, 3, nil, 100), false},
			{"implausible pt 50", rtpBytes(0x80, 50, 1, 2, 3, nil, 100), false},
			{"csrc beyond end", rtpBytes(0x8f, 0, 1, 2, 3, nil, 10), false},
			{"rtcp with bad length", []byte{0x80, 201, 0, 99, 1, 2, 3, 4}, false},
		}
		for _, tc := range tests {
			f := newFeed(HandlerOptions{})
			if f.raw(0, tc.b) {
				t.Errorf("%s consumed", tc.name)
			}
		}
		f := newFeed(HandlerOptions{})
		if f.raw(0, stunV2) {
			// V=2 with PT 1 (the STUN message type low byte) is plausible RTP
			// by header alone; it just must not become a stream by itself.
			if len(f.h.Streams()) != 0 {
				t.Error("stun lookalike became a stream")
			}
		}
		g := newFeed(HandlerOptions{})
		g.pkt(0, 0, 1, 1, 10)
		g.h.fmts[0] = fmtHint{} // keep the API surface exercised
		for _, tr := range []string{"TCP", "SCTP", ""} {
			p := capture.Packet{Transport: tr, Payload: rtpBytes(0x80, 0, 1, 2, 3, nil, 100), Time: t0}
			if g.h.Handle(&p) {
				t.Errorf("%s consumed", tr)
			}
		}
		var _ capture.Handler = g.h
	})
	t.Run("consumed", func(t *testing.T) {
		f := newFeed(HandlerOptions{})
		if !f.raw(0, rtpBytes(0x80, 0, 1, 2, 3, nil, 100)) {
			t.Error("rtp not consumed")
		}
		if !f.raw(0, []byte{0x80, 201, 0, 1, 1, 2, 3, 4}) {
			t.Error("rtcp not consumed")
		}
	})
}

func TestCandidateMemoryBounded(t *testing.T) {
	f := newFeed(HandlerOptions{MaxCandidates: 64})
	for i := 0; i < 100_000; i++ {
		f.ssrc = uint32(i)
		f.sport = uint16(i)
		f.pkt(time.Duration(i)*time.Millisecond, 0, uint16(i), 0, 20)
	}
	if n := len(f.h.young) + len(f.h.old); n > 64 {
		t.Errorf("%d candidates retained, cap 64", n)
	}
	if len(f.h.free) > 64 {
		t.Errorf("free list %d", len(f.h.free))
	}
	if len(f.h.Streams()) != 0 {
		t.Error("noise became streams")
	}
	// A real stream among the noise survives the eviction.
	f.ssrc, f.sport = 0xabcdef, 5000
	for i := 0; i < 10; i++ {
		f.pkt(time.Second, 0, uint16(i), uint32(i)*160, 160)
		for j := 0; j < 5; j++ { // five noise flows between packets
			g := *f
			g.ssrc, g.sport = uint32(1_000_000+i*5+j), uint16(30000+j)
			g.pkt(time.Second, 0, 1, 1, 10)
		}
	}
	if n := len(f.h.Streams()); n != 1 {
		t.Errorf("real stream lost among noise: %d streams", n)
	}
}

func TestStreamsOrderAndRepeatable(t *testing.T) {
	f := newFeed(HandlerOptions{})
	for k, base := range []time.Duration{3 * time.Second, 0, time.Second} {
		f.ssrc = uint32(k + 1)
		f.sport = uint16(2000 + k)
		for i := 0; i < 10; i++ {
			f.pkt(base+time.Duration(i)*20*time.Millisecond, 0, uint16(i), uint32(i)*160, 160)
		}
	}
	a := f.h.Streams()
	if len(a) != 3 || a[0].SSRC != 2 || a[1].SSRC != 3 || a[2].SSRC != 1 {
		t.Fatalf("order: %v %v %v", a[0].SSRC, a[1].SSRC, a[2].SSRC)
	}
	b := f.h.Streams()
	for i := range a {
		if a[i] != b[i] {
			t.Errorf("Streams() not repeatable")
		}
	}
}

func TestIPv6AndMapped(t *testing.T) {
	f := newFeed(HandlerOptions{})
	f.src = netip.MustParseAddr("2001:db8::1")
	f.dst = netip.MustParseAddr("2001:db8::2")
	f.run(10, 0, 0, nil)
	s := only(t, f)
	if s.Src.Addr() != f.src || s.Dst.Addr() != f.dst {
		t.Errorf("key %+v", s.Key)
	}
}

func TestFactoryPerFile(t *testing.T) {
	fac := NewHandler(HandlerOptions{})
	a, b := fac("a.pcap").(*Handler), fac("b.pcap").(*Handler)
	if a == b {
		t.Fatal("factory returns a shared handler")
	}
	f := &feed{h: a, src: addrA, dst: addrB, sport: 1, dport: 2, ssrc: 1}
	f.run(10, 0, 0, nil)
	if len(a.Streams()) != 1 || len(b.Streams()) != 0 || a.Streams()[0].File != "a.pcap" {
		t.Error("state shared between handlers")
	}
}

func TestZeroAllocsSteadyState(t *testing.T) {
	f := newFeed(HandlerOptions{})
	f.run(50, 0, 0, nil)
	b := rtpBytes(0x80, 0, 0, 0, f.ssrc, nil, 160)
	var p capture.Packet
	p = capture.Packet{File: "t.pcap", Time: t0, Src: f.src, Dst: f.dst, SrcPort: f.sport, DstPort: f.dport, Transport: "UDP", Payload: b}
	seq := uint16(50)
	n := testing.AllocsPerRun(1000, func() {
		binary.BigEndian.PutUint16(b[2:], seq)
		binary.BigEndian.PutUint32(b[4:], uint32(seq)*160)
		seq++
		p.Time = p.Time.Add(20 * time.Millisecond)
		f.h.Handle(&p)
	})
	if n != 0 {
		t.Errorf("%v allocs per packet", n)
	}
}

func FuzzHandler(f *testing.F) {
	f.Add(rtpBytes(0x80, 0, 1, 2, 3, nil, 160), rtpBytes(0x80, 0, 2, 162, 3, nil, 160))
	f.Add([]byte{0x81, 200, 0, 12, 1, 2, 3, 4}, []byte{0x80, 201, 0, 1, 1, 2, 3, 4})
	f.Add(rtpBytes(0x90, 101, 5, 6, 7, []byte{0xbe, 0xde, 0, 0}, 4), []byte{0x80, 0xc8})
	f.Fuzz(func(t *testing.T, a, b []byte) {
		fd := newFeed(HandlerOptions{MinPackets: 2, MaxCandidates: 8})
		for i := 0; i < 8; i++ {
			fd.raw(time.Duration(i)*time.Millisecond, a)
			fd.raw(time.Duration(i)*time.Millisecond, b)
			if len(a) > 3 {
				a = append([]byte(nil), a...)
				a[3]++ // advancing sequence numbers get past probation
			}
		}
		for _, s := range fd.h.Streams() {
			if s.Packets == 0 || s.LossPct < 0 || s.LossPct > 100 || s.MOS < 0 || s.MOS > 4.5 || s.JitterMean < 0 {
				t.Fatalf("bad stream %+v", s)
			}
		}
	})
}

func BenchmarkHandle1MPackets200Streams(b *testing.B) {
	const streams = 200
	const total = 1_000_000
	f := newFeed(HandlerOptions{})
	payload := make([][]byte, streams)
	ps := make([]capture.Packet, streams)
	for i := range payload {
		payload[i] = rtpBytes(0x80, 0, 0, 0, uint32(0x1000+i), nil, 160)
		ps[i] = capture.Packet{File: "b.pcap", Time: t0, Src: addrA, Dst: addrB, SrcPort: uint16(10000 + 2*i), DstPort: 20000,
			Transport: "UDP", Payload: payload[i]}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		h := newHandler("b.pcap", HandlerOptions{})
		for i := 0; i < total; i++ {
			s := i % streams
			k := uint32(i / streams)
			binary.BigEndian.PutUint16(payload[s][2:], uint16(k))
			binary.BigEndian.PutUint32(payload[s][4:], k*160)
			ps[s].Time = t0.Add(time.Duration(k) * 20 * time.Millisecond)
			h.Handle(&ps[s])
		}
		if len(h.Streams()) != streams {
			b.Fatal("streams")
		}
	}
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/total, "ns/pkt")
	_ = f
}
