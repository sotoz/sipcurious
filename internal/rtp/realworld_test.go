package rtp

import (
	"math"
	"net/netip"
	"testing"
	"time"
)

// Expected values below come from `tshark -r <file> -q -z rtp,streams`
// (Wireshark 4.x; h263 with -d udp.port==...,rtp because it is not announced
// by SDP in the capture; the DTMF/RTCP files additionally from -Y rtpevent
// and -T fields on rtcp.*), never from this package. tshark columns:
// Pkts, Lost, Max Delta, Mean/Max Jitter.
//
// Known, intended deltas against tshark:
//   - Jitter is compared with 2 microseconds absolute tolerance, except
//     where noted: both implement RFC 3550 A.8, we only differ in what
//     counts as a media packet (telephone-event packets, duplicates and
//     stray packets are excluded here; tshark includes events and then
//     reports a bogus jitter for them).
//   - tshark's "Mean Jitter" of the h263 file (15.505 ms) is 12% lower than
//     ours (17.659 ms): same recurrence, tshark averages the per-packet
//     jitter in a way that includes the zero-valued start; Max Jitter,
//     packet count and loss are identical. Tolerance 15%.
//   - rtcpReport for the asterisk file (5) is our own count of the SRTCP-like
//     sender reports (readable first 8 bytes, encrypted rest) that tshark
//     does not dissect; the FreeSWITCH value (5) matches the tshark dump.
//   - Streams with fewer than 5 packets (tshark reports a 2-packet stream
//     in the asterisk file) are not reported by design.
type want struct {
	src, dst   string
	ssrc       uint32
	pkts       uint64
	lost       int64
	maxGap     time.Duration // tshark "Max Delta"
	jMean      float64       // ms
	jMax       float64       // ms
	jMeanTol   float64       // relative tolerance for jMean (0: 2 us absolute)
	codec      string
	pt         uint8
	dtmf       int
	rtcpReport int
}

func TestAgainstTshark(t *testing.T) {
	const rw = "../../testdata/realworld/"
	const sm = "../../testdata/samples/"
	ms := func(f float64) time.Duration { return time.Duration(math.Round(f * 1e6)) }
	tests := []struct {
		file string
		want []want
	}{
		{sm + "basic-call.pcap", []want{
			{src: "10.0.1.10:16384", dst: "10.0.2.20:18000", ssrc: 0x1A2B3C01, pkts: 250, maxGap: ms(20), codec: "PCMU"},
			{src: "10.0.2.20:18000", dst: "10.0.1.10:16384", ssrc: 0x1A2B3C02, pkts: 250, maxGap: ms(20), codec: "PCMU"},
		}},
		{sm + "bad-media.pcap", []want{
			{src: "10.0.1.10:47810", dst: "10.0.2.20:14714", ssrc: 0xBAD00001, pkts: 300, maxGap: ms(20), codec: "PCMU"},
			{src: "10.0.2.20:14714", dst: "10.0.1.10:47810", ssrc: 0xBAD00002, pkts: 182, lost: 118, maxGap: ms(1964.602), jMean: 26.552, jMax: 38.131, codec: "PCMU"},
			{src: "10.0.1.10:20132", dst: "10.0.2.21:18574", ssrc: 0xBAD00003, pkts: 300, maxGap: ms(20), codec: "PCMU"},
		}},
		{rw + "wireshark-sip-rtp-g711.pcap", []want{
			{src: "10.0.2.15:27942", dst: "10.0.2.20:6000", ssrc: 0x343DA99B, pkts: 425, maxGap: ms(20.049), jMean: 0.006, jMax: 0.010, codec: "PCMU"},
			{src: "10.0.2.15:28102", dst: "10.0.2.20:6000", ssrc: 0x343FFA34, pkts: 414, maxGap: ms(20.115), jMean: 0.004, jMax: 0.019, codec: "PCMA", pt: 8},
		}},
		{rw + "wireshark-asterisk-zfone-xlite.pcap", []want{
			{src: "192.168.10.40:49848", dst: "192.168.10.41:64508", ssrc: 0xB72A7104, pkts: 790, lost: 1, maxGap: ms(102.076), jMean: 0.484, jMax: 6.824, codec: "PCMU", rtcpReport: 5},
			{src: "192.168.10.41:64508", dst: "192.168.10.40:49848", ssrc: 0xBEE0F2ED, pkts: 205, lost: 369, maxGap: ms(4680.243), jMean: 0.402, jMax: 1.265, codec: "PCMU"},
		}},
		{rw + "wireshark-nb6-telephone.pcap", []want{
			{src: "109.3.79.137:44344", dst: "10.251.23.139:35560", ssrc: 0x2D7B0B2C, pkts: 261, maxGap: ms(63.439), jMean: 2.631, jMax: 11.261, codec: "PCMA", pt: 8},
			{src: "10.251.23.139:35560", dst: "109.3.79.137:44344", ssrc: 0x446E4B53, pkts: 248, maxGap: ms(66.048), jMean: 0.529, jMax: 6.441, codec: "PCMA", pt: 8},
		}},
		{rw + "wireshark-switchport-sip-with-arp-stp.pcap", []want{
			{src: "192.168.25.51:50006", dst: "192.168.24.50:50068", ssrc: 0xE74D6DFE, pkts: 266, maxGap: ms(20.734), jMean: 0.061, jMax: 0.089, codec: "PCMA", pt: 8},
		}},
		{rw + "wireshark-h263-over-rtp.pcap", []want{
			{src: "192.168.6.199:57128", dst: "192.168.6.199:32976", ssrc: 0x5482ECE0, pkts: 45, maxGap: ms(324.072), jMean: 15.505, jMax: 32.186, jMeanTol: 0.15, codec: "H263", pt: 34},
		}},
		// SIP_DTMF2.cap up to t=86 s: 35 telephone-event packets of 7 digits
		// (tshark -Y rtpevent), PT 96 via SDP. tshark counts the events as
		// media (mean jitter 2.224 ms for the sending side); we exclude them.
		{rw + "wireshark-rtp-dtmf-event.pcap", []want{
			{src: "192.168.105.110:4374", dst: "192.168.105.172:4376", ssrc: 0x9A7B5382, pkts: 306, maxGap: ms(30.097 + 0), jMean: 0.009, jMax: 0.019, codec: "PCMA", pt: 8},
			{src: "192.168.105.172:4376", dst: "192.168.105.110:4376", ssrc: 0x5711BF84, pkts: 305, maxGap: ms(30.068 + 0.188), jMean: 0.009, jMax: 0.015, codec: "PCMA", pt: 8, dtmf: 7},
		}},
		// FreeSWITCH G.722 call: tshark -T fields on rtcp.*: SR at frames
		// 201/404/607 (sender), RR at 406/609 with cumulative lost 1 and
		// interarrival jitter 6/22 timestamp units (frame 203 reports SSRC 0).
		{rw + "wireshark-rtp-rtcp-g722-freeswitch.pcap", []want{
			{src: "217.12.244.34:25962", dst: "217.12.247.98:31600", ssrc: 0x5D931534, pkts: 607, maxGap: ms(21.751), jMean: 0.046, jMax: 0.264, jMeanTol: 0.05, codec: "G722", pt: 9, rtcpReport: 5},
		}},
	}
	for _, tc := range tests {
		t.Run(tc.file[len("../../testdata/"):], func(t *testing.T) {
			h := newHandler(tc.file, HandlerOptions{})
			readUDP(t, tc.file, h)
			got := h.Streams()
			if len(got) != len(tc.want) {
				t.Fatalf("%d streams, tshark %d: %+v", len(got), len(tc.want), got)
			}
			for _, w := range tc.want {
				var s *Stream
				for i := range got {
					if got[i].SSRC == w.ssrc && got[i].Src == netip.MustParseAddrPort(w.src) && got[i].Dst == netip.MustParseAddrPort(w.dst) {
						s = &got[i]
					}
				}
				if s == nil {
					t.Errorf("stream %s>%s %08x missing", w.src, w.dst, w.ssrc)
					continue
				}
				if s.Packets != w.pkts {
					t.Errorf("%08x: packets %d, tshark %d", w.ssrc, s.Packets, w.pkts)
				}
				if s.Lost != w.lost {
					t.Errorf("%08x: lost %d, tshark %d", w.ssrc, s.Lost, w.lost)
				}
				if d := s.MaxGap - w.maxGap; d < -time.Microsecond || d > time.Microsecond {
					t.Errorf("%08x: MaxGap %v, tshark %v", w.ssrc, s.MaxGap, w.maxGap)
				}
				jm := float64(s.JitterMean) / 1e6
				tol := 2e-3
				if w.jMeanTol > 0 {
					tol = w.jMean * w.jMeanTol
				}
				if math.Abs(jm-w.jMean) > tol {
					t.Errorf("%08x: mean jitter %.4f ms, tshark %.3f ms (tol %.4f)", w.ssrc, jm, w.jMean, tol)
				}
				if jx := float64(s.JitterMax) / 1e6; math.Abs(jx-w.jMax) > 2e-3 {
					t.Errorf("%08x: max jitter %.4f ms, tshark %.3f ms", w.ssrc, jx, w.jMax)
				}
				if s.Codec != w.codec || s.PayloadType != w.pt {
					t.Errorf("%08x: codec %q pt %d, want %q %d", w.ssrc, s.Codec, s.PayloadType, w.codec, w.pt)
				}
				if s.DTMFEvents != w.dtmf {
					t.Errorf("%08x: DTMFEvents %d, want %d", w.ssrc, s.DTMFEvents, w.dtmf)
				}
				if s.RTCP.Reports != w.rtcpReport {
					t.Errorf("%08x: RTCP reports %d, want %d", w.ssrc, s.RTCP.Reports, w.rtcpReport)
				}
				if s.MOS < 1 || s.MOS > 4.5 || s.RFactor <= 0 {
					t.Errorf("%08x: quality R=%v MOS=%v", w.ssrc, s.RFactor, s.MOS)
				}
			}
		})
	}
}

// TestRealRTCP checks the RTCP summary of the FreeSWITCH capture against the
// tshark field dump (RR frame 609: cumulative lost 1, fraction 0, jitter 22
// timestamp units at the G.722 RTP clock of 8000 Hz = 2.75 ms).
func TestRealRTCP(t *testing.T) {
	const f = "../../testdata/realworld/wireshark-rtp-rtcp-g722-freeswitch.pcap"
	h := newHandler(f, HandlerOptions{})
	readUDP(t, f, h)
	ss := h.Streams()
	if len(ss) != 1 {
		t.Fatalf("%d streams", len(ss))
	}
	r := ss[0].RTCP
	if r.Reports != 5 || r.PacketsLost != 1 || r.MaxFractionLost != 0 || r.MaxJitter != 2750*time.Microsecond {
		t.Errorf("RTCP = %+v", r)
	}
}

// TestRealRTCPNotAttributedWhenEncrypted: the zfone/xlite capture contains
// SRTCP-like sender reports whose reception blocks are encrypted; their
// garbage must not be attributed to any stream, and the plain RR with no
// blocks (frames 21 and 25) adds nothing.
func TestRealRTCPNotAttributedWhenEncrypted(t *testing.T) {
	const f = "../../testdata/realworld/wireshark-asterisk-zfone-xlite.pcap"
	h := newHandler(f, HandlerOptions{})
	readUDP(t, f, h)
	for _, s := range h.Streams() {
		if s.RTCP.MaxFractionLost != 0 || s.RTCP.PacketsLost != 0 || s.RTCP.MaxJitter != 0 {
			t.Errorf("%08x: garbage attributed: %+v", s.SSRC, s.RTCP)
		}
	}
}

func BenchmarkRealCapture(b *testing.B) {
	const f = "../../testdata/samples/basic-call.pcap"
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		readUDP(b, f, newHandler(f, HandlerOptions{}))
	}
}
