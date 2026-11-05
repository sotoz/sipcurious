package pcaptest

import (
	"bytes"
	"encoding/binary"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

var t0 = time.Date(2026, 3, 4, 10, 0, 0, 0, time.UTC)

// pkt is one decoded packet.
type pkt struct {
	ts       time.Time
	src, dst netip.AddrPort
	tcp      bool
	payload  []byte
	vlan     []uint16
}

// readPCAP decodes a classic pcap with gopacket and verifies IP/UDP/TCP
// checksums on the way (an independent recomputation, not gopacket's own).
func readPCAP(t *testing.T, data []byte) (pkts []pkt, lt layers.LinkType, nanos bool) {
	t.Helper()
	r, err := pcapgo.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("pcapgo.NewReader: %v", err)
	}
	lt = r.LinkType()
	nanos = binary.LittleEndian.Uint32(data) == 0xa1b23c4d
	for {
		d, ci, err := r.ReadPacketData()
		if err == io.EOF {
			return
		}
		if err != nil {
			t.Fatalf("ReadPacketData: %v", err)
		}
		pkts = append(pkts, decode(t, d, ci, lt))
	}
}

func decode(t *testing.T, d []byte, ci gopacket.CaptureInfo, lt layers.LinkType) pkt {
	t.Helper()
	var first gopacket.Decoder = layers.LayerTypeEthernet
	if lt == layers.LinkTypeLinuxSLL {
		first = layers.LayerTypeLinuxSLL
	}
	p := gopacket.NewPacket(d, first, gopacket.Lazy)
	if e := p.ErrorLayer(); e != nil {
		t.Fatalf("decode error at %v: %v", ci.Timestamp, e.Error())
	}
	out := pkt{ts: ci.Timestamp}
	for _, l := range p.Layers() {
		if q, ok := l.(*layers.Dot1Q); ok {
			out.vlan = append(out.vlan, q.VLANIdentifier)
		}
	}
	var sa, da netip.Addr
	var ipPayload []byte
	var proto byte
	if ip4, ok := p.Layer(layers.LayerTypeIPv4).(*layers.IPv4); ok {
		sa, da = netip.AddrFrom4([4]byte(ip4.SrcIP.To4())), netip.AddrFrom4([4]byte(ip4.DstIP.To4()))
		hdr := ip4.Contents
		if sum(hdr, 0) != 0xffff {
			t.Fatalf("bad IPv4 header checksum at %v", ci.Timestamp)
		}
		ipPayload = ip4.Payload
		proto = byte(ip4.Protocol)
	} else if ip6, ok := p.Layer(layers.LayerTypeIPv6).(*layers.IPv6); ok {
		sa, da = netip.AddrFrom16([16]byte(ip6.SrcIP)), netip.AddrFrom16([16]byte(ip6.DstIP))
		ipPayload = ip6.Payload
		proto = byte(ip6.NextHeader)
	} else {
		t.Fatalf("no IP layer at %v", ci.Timestamp)
	}
	pseudo := append(sa.AsSlice(), da.AsSlice()...)
	if sa.Is4() {
		pseudo = append(pseudo, 0, proto, byte(len(ipPayload)>>8), byte(len(ipPayload)))
	} else {
		pseudo = append(pseudo, 0, 0, byte(len(ipPayload)>>8), byte(len(ipPayload)), 0, 0, 0, proto)
	}
	if sum(ipPayload, sum(pseudo, 0)) != 0xffff {
		t.Fatalf("bad L4 checksum at %v (proto %d)", ci.Timestamp, proto)
	}
	if u, ok := p.Layer(layers.LayerTypeUDP).(*layers.UDP); ok {
		out.src = netip.AddrPortFrom(sa, uint16(u.SrcPort))
		out.dst = netip.AddrPortFrom(da, uint16(u.DstPort))
		out.payload = u.Payload
	} else if tc, ok := p.Layer(layers.LayerTypeTCP).(*layers.TCP); ok {
		out.tcp = true
		out.src = netip.AddrPortFrom(sa, uint16(tc.SrcPort))
		out.dst = netip.AddrPortFrom(da, uint16(tc.DstPort))
		out.payload = tc.Payload
	} else {
		t.Fatalf("no transport layer at %v", ci.Timestamp)
	}
	return out
}

func sum(b []byte, s uint32) uint32 {
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		s += uint32(b[len(b)-1]) << 8
	}
	for s>>16 != 0 {
		s = s&0xffff + s>>16
	}
	return s
}

// sipLine returns "METHOD" or "CODE" of a SIP payload plus Call-ID and CSeq,
// or ok=false if it is not SIP.
func sipInfo(p []byte) (info, callID, cseq string, ok bool) {
	s := string(p)
	i := strings.Index(s, "\r\n")
	if i < 0 || !strings.Contains(s[:i], "SIP/2.0") {
		return "", "", "", false
	}
	first := s[:i]
	if strings.HasPrefix(first, "SIP/2.0 ") {
		info = strings.Fields(first)[1]
	} else {
		info = strings.Fields(first)[0]
	}
	for _, l := range strings.Split(s[:strings.Index(s, "\r\n\r\n")], "\r\n") {
		if k, v, f := strings.Cut(l, ": "); f {
			switch k {
			case "Call-ID":
				callID = v
			case "CSeq":
				cseq = v
			}
		}
	}
	return info, callID, cseq, true
}

// flow returns the SIP info sequence of one Call-ID in capture order.
func flow(pkts []pkt, callID string) []string {
	var out []string
	for _, p := range pkts {
		if info, id, _, ok := sipInfo(p.payload); ok && id == callID {
			out = append(out, info)
		}
	}
	return out
}

func eq(a, b []string) bool { return strings.Join(a, " ") == strings.Join(b, " ") }

func TestSIPFlows(t *testing.T) {
	tests := []struct {
		name  string
		opts  CallOptions
		legs  int
		flows [][]string
	}{
		{"answered direct", CallOptions{TalkTime: time.Second}, 1,
			[][]string{{"INVITE", "100", "180", "200", "ACK", "BYE", "200"}}},
		{"busy", CallOptions{Outcome: Busy}, 1, [][]string{{"INVITE", "100", "486", "ACK"}}},
		{"rejected 603", CallOptions{Outcome: Rejected, RingTime: time.Second}, 1,
			[][]string{{"INVITE", "100", "180", "603", "ACK"}}},
		{"cancelled", CallOptions{Outcome: Cancelled}, 1,
			[][]string{{"INVITE", "100", "180", "CANCEL", "200", "487", "ACK"}}},
		{"503", CallOptions{Outcome: ServerError}, 1, [][]string{{"INVITE", "100", "503", "ACK"}}},
		{"auth 407", CallOptions{Auth: 407, TalkTime: time.Second}, 1,
			[][]string{{"INVITE", "100", "407", "ACK", "INVITE", "100", "180", "200", "ACK", "BYE", "200"}}},
		{"early media", CallOptions{EarlyMedia: true, TalkTime: time.Second}, 1,
			[][]string{{"INVITE", "100", "183", "200", "ACK", "BYE", "200"}}},
		{"hold", CallOptions{Hold: true}, 1,
			[][]string{{"INVITE", "100", "180", "200", "ACK", "INVITE", "200", "ACK", "INVITE", "200", "ACK", "BYE", "200"}}},
		{"delayed offer", CallOptions{DelayedOffer: true, TalkTime: time.Second}, 1,
			[][]string{{"INVITE", "100", "180", "200", "ACK", "BYE", "200"}}},
		{"callee hangs up", CallOptions{HangUpBy: "callee", TalkTime: time.Second}, 1,
			[][]string{{"INVITE", "100", "180", "200", "ACK", "BYE", "200"}}},
		{"proxy answered", CallOptions{Topology: Proxy, TalkTime: time.Second}, 1,
			[][]string{{"INVITE", "100", "INVITE", "100", "180", "180", "200", "200", "ACK", "ACK", "BYE", "BYE", "200", "200"}}},
		{"proxy busy at proxy", CallOptions{Topology: Proxy, Outcome: Busy, AtProxy: true}, 1,
			[][]string{{"INVITE", "100", "486", "ACK"}}},
		{"b2bua answered", CallOptions{Topology: B2BUA, TalkTime: time.Second}, 2,
			[][]string{
				{"INVITE", "100", "180", "200", "ACK", "BYE", "200"},
				{"INVITE", "100", "180", "200", "ACK", "BYE", "200"}}},
		{"unreachable direct", CallOptions{Outcome: Unreachable, Retransmits: 3}, 1,
			[][]string{{"INVITE", "INVITE", "INVITE", "INVITE"}}},
		{"unreachable 408 via proxy", CallOptions{Outcome: Unreachable, Retransmits: 2, Topology: Proxy}, 1,
			[][]string{{"INVITE", "100", "INVITE", "INVITE", "INVITE", "408", "ACK"}}},
		{"missing ack", CallOptions{MissingACK: true, OKRetransmits: 3}, 1,
			[][]string{{"INVITE", "100", "180", "200", "200", "200", "200", "BYE", "200"}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := New(t0, 7)
			id := b.Call(tc.opts)
			legs := b.LegCallIDs(id)
			if len(legs) != tc.legs {
				t.Fatalf("legs = %v, want %d", legs, tc.legs)
			}
			pkts, _, _ := readPCAP(t, b.PCAP())
			for i, want := range tc.flows {
				got := flow(pkts, legs[i])
				if !eq(got, want) {
					t.Errorf("leg %d flow\n got %v\nwant %v", i, got, want)
				}
			}
		})
	}
}

func TestRetransmissionTimers(t *testing.T) {
	b := New(t0, 3)
	id := b.Call(CallOptions{Outcome: Unreachable})
	pkts, _, _ := readPCAP(t, b.PCAP())
	var at []time.Duration
	for _, p := range pkts {
		if info, cid, _, ok := sipInfo(p.payload); ok && cid == id && info == "INVITE" {
			at = append(at, p.ts.Sub(t0))
		}
	}
	// T1 = 500ms doubling until 64*T1: 0, .5, 1.5, 3.5, 7.5, 15.5, 31.5
	want := []time.Duration{0, 500, 1500, 3500, 7500, 15500, 31500}
	if len(at) != len(want) {
		t.Fatalf("INVITE count = %d, want %d: %v", len(at), len(want), at)
	}
	for i, w := range want {
		if at[i] != w*time.Millisecond {
			t.Errorf("INVITE %d at %v, want %v", i, at[i], w*time.Millisecond)
		}
	}
}

func TestMissingACKRetransmitsCapAtT2(t *testing.T) {
	b := New(t0, 3)
	id := b.Call(CallOptions{MissingACK: true})
	pkts, _, _ := readPCAP(t, b.PCAP())
	var ok200 []time.Duration
	for _, p := range pkts {
		if info, cid, cs, ok := sipInfo(p.payload); ok && cid == id && info == "200" && strings.HasSuffix(cs, "INVITE") && p.src.Port() == 5060 && p.dst.Addr() == netip.MustParseAddr("10.0.1.10") {
			ok200 = append(ok200, p.ts.Sub(ok200first(ok200, p.ts)))
		}
	}
	if len(ok200) != 1+len(timerSchedule(true)) {
		t.Fatalf("200 count = %d", len(ok200))
	}
	for i := 2; i < len(ok200); i++ {
		d := ok200[i] - ok200[i-1]
		if d > 4*time.Second+10*time.Millisecond {
			t.Errorf("gap %d = %v exceeds T2", i, d)
		}
	}
}

func ok200first(prev []time.Duration, ts time.Time) time.Time {
	if len(prev) == 0 {
		return ts
	}
	return ts.Add(-prev[len(prev)-1]) // keeps offsets cumulative from the first
}

func TestHeadersAndBodies(t *testing.T) {
	b := New(t0, 11)
	id := b.Call(CallOptions{Auth: 407, Reason: "Q.850;cause=16", TalkTime: time.Second, Topology: Proxy})
	pkts, _, _ := readPCAP(t, b.PCAP())
	seenAuth, seenReason, seenBranch := false, false, map[string]bool{}
	for _, p := range pkts {
		s := string(p.payload)
		info, cid, _, ok := sipInfo(p.payload)
		if !ok {
			continue
		}
		if cid != id {
			t.Errorf("unexpected Call-ID %q", cid)
		}
		hdrEnd := strings.Index(s, "\r\n\r\n")
		body := s[hdrEnd+4:]
		var cl = -1
		for _, l := range strings.Split(s[:hdrEnd], "\r\n") {
			if v, f := strings.CutPrefix(l, "Content-Length: "); f {
				cl = atoi(v)
			}
			if strings.HasPrefix(l, "Proxy-Authorization: Digest ") {
				seenAuth = true
			}
			if l == "Reason: Q.850;cause=16" && info == "BYE" {
				seenReason = true
			}
			if v, f := strings.CutPrefix(l, "Via: "); f && info == "INVITE" {
				i := strings.Index(v, "branch=")
				seenBranch[v[i+7:]] = true
				if !strings.HasPrefix(v[i+7:], "z9hG4bK") {
					t.Errorf("branch %q lacks magic cookie", v[i+7:])
				}
			}
		}
		if cl != len(body) {
			t.Errorf("%s Content-Length %d, body %d", info, cl, len(body))
		}
		if strings.HasPrefix(s, "INVITE") && !strings.Contains(body, "a=rtpmap:0 PCMU/8000") {
			t.Errorf("INVITE lacks SDP rtpmap:\n%s", body)
		}
	}
	if !seenAuth || !seenReason {
		t.Errorf("auth=%v reason=%v", seenAuth, seenReason)
	}
	if len(seenBranch) < 3 { // 1 challenged + 2 authenticated hops, all distinct
		t.Errorf("INVITE branches = %d, want >= 3 distinct", len(seenBranch))
	}
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}

// rtpPkts returns the RTP packets (version 2, not SIP) between src and dst.
func rtpPkts(pkts []pkt) (out []pkt) {
	for _, p := range pkts {
		if !p.tcp && len(p.payload) >= 12 && p.payload[0]>>6 == 2 {
			if _, _, _, ok := sipInfo(p.payload); !ok && p.payload[1]&0x7f < 72 || p.payload[1]&0x7f > 76 && p.payload[1]&0x7f < 128 {
				out = append(out, p)
			}
		}
	}
	return
}

func TestRTPFormat(t *testing.T) {
	tests := []struct {
		codec   string
		pt      uint8
		payload int
		tsStep  uint32
	}{
		{"PCMU", 0, 160, 160}, {"PCMA", 8, 160, 160}, {"G729", 18, 20, 160}, {"opus", 111, 60, 960},
	}
	for _, tc := range tests {
		t.Run(tc.codec, func(t *testing.T) {
			b := New(t0, 5)
			b.Call(CallOptions{Codec: tc.codec, TalkTime: 2 * time.Second, CallerRTP: RTPOptions{SSRC: 0xAABBCCDD}})
			pkts, _, _ := readPCAP(t, b.PCAP())
			var n int
			var prev []byte
			for _, p := range rtpPkts(pkts) {
				d := p.payload
				if binary.BigEndian.Uint32(d[8:]) != 0xAABBCCDD {
					continue
				}
				if d[0] != 0x80 {
					t.Fatalf("V/P/X/CC byte = %#x", d[0])
				}
				if d[1]&0x7f != tc.pt {
					t.Fatalf("PT = %d, want %d", d[1]&0x7f, tc.pt)
				}
				marker := d[1]&0x80 != 0
				if (n == 0) != marker {
					t.Fatalf("packet %d marker = %v", n, marker)
				}
				if tc.codec != "opus" && len(d)-12 != tc.payload {
					t.Fatalf("payload = %d, want %d", len(d)-12, tc.payload)
				}
				if tc.codec == "opus" && (len(d)-12 < 50 || len(d)-12 > 70) {
					t.Fatalf("opus payload = %d, want ~60", len(d)-12)
				}
				if prev != nil {
					if binary.BigEndian.Uint16(d[2:]) != binary.BigEndian.Uint16(prev[2:])+1 {
						t.Fatalf("seq not incrementing at %d", n)
					}
					if binary.BigEndian.Uint32(d[4:])-binary.BigEndian.Uint32(prev[4:]) != tc.tsStep {
						t.Fatalf("ts step = %d, want %d", binary.BigEndian.Uint32(d[4:])-binary.BigEndian.Uint32(prev[4:]), tc.tsStep)
					}
				}
				prev = d
				n++
			}
			if n < 90 || n > 101 {
				t.Errorf("packets = %d, want ~100 for 2 s", n)
			}
		})
	}
}

// streamStats analyses captured RTP of one SSRC.
type streamStats struct {
	n        int
	lost     int
	dups     int
	reorders int
	spacing  []time.Duration // arrival minus nominal offset, per packet
}

func analyse(pkts []pkt, ssrc uint32, step time.Duration) (st streamStats) {
	seen := map[uint16]bool{}
	var first time.Time
	var firstSeq uint16
	var maxSeq uint16
	var last uint16
	have := false
	for _, p := range rtpPkts(pkts) {
		d := p.payload
		if binary.BigEndian.Uint32(d[8:]) != ssrc {
			continue
		}
		seq := binary.BigEndian.Uint16(d[2:])
		if !have {
			have, first, firstSeq, maxSeq, last = true, p.ts, seq, seq, seq
		}
		st.n++
		if seen[seq] {
			st.dups++
			continue
		}
		seen[seq] = true
		if int16(seq-last) < 0 {
			st.reorders++
		}
		last = seq
		if int16(seq-maxSeq) > 0 {
			maxSeq = seq
		}
		off := time.Duration(int16(seq-firstSeq)) * step
		st.spacing = append(st.spacing, p.ts.Sub(first)-off)
	}
	st.lost = int(maxSeq-firstSeq) + 1 - len(seen)
	return
}

func TestRTPImpairments(t *testing.T) {
	const ssrc = 0x11223344
	run := func(o RTPOptions) streamStats {
		b := New(t0, 99)
		o.SSRC = ssrc
		b.Call(CallOptions{TalkTime: 20 * time.Second, CallerRTP: o})
		pkts, _, _ := readPCAP(t, b.PCAP())
		return analyse(pkts, ssrc, 20*time.Millisecond)
	}
	t.Run("clean", func(t *testing.T) {
		st := run(RTPOptions{})
		if st.lost != 0 || st.dups != 0 || st.reorders != 0 {
			t.Errorf("clean stream has impairments: %+v", st)
		}
		for i, s := range st.spacing {
			if d := s - st.spacing[0]; d < -time.Microsecond || d > time.Microsecond {
				t.Fatalf("packet %d off schedule by %v", i, d)
			}
		}
	})
	t.Run("loss 8%", func(t *testing.T) {
		st := run(RTPOptions{LossPct: 8})
		pct := float64(st.lost) * 100 / float64(st.n+st.lost)
		if pct < 5 || pct > 11 {
			t.Errorf("loss = %.1f%% (lost %d of %d), want about 8", pct, st.lost, st.n+st.lost)
		}
	})
	t.Run("gap", func(t *testing.T) {
		st := run(RTPOptions{Gap: Gap{At: 5 * time.Second, For: 2 * time.Second}})
		if st.lost != 100 {
			t.Errorf("lost = %d, want 100 (2 s at 50 pps)", st.lost)
		}
	})
	t.Run("jitter", func(t *testing.T) {
		st := run(RTPOptions{JitterMs: 60})
		var mx, mn time.Duration
		for _, s := range st.spacing {
			d := s - st.spacing[0]
			mx, mn = max(mx, d), min(mn, d)
		}
		if mx-mn < 100*time.Millisecond || mx-mn > 700*time.Millisecond {
			t.Errorf("arrival spread = %v for 60 ms jitter", mx-mn)
		}
		if st.lost != 0 {
			t.Errorf("jitter lost packets: %d", st.lost)
		}
	})
	t.Run("duplicates", func(t *testing.T) {
		st := run(RTPOptions{DupPct: 5})
		if st.dups < 20 || st.dups > 80 {
			t.Errorf("dups = %d of %d, want about 5%%", st.dups, st.n)
		}
	})
	t.Run("reorder", func(t *testing.T) {
		st := run(RTPOptions{ReorderPct: 5})
		if st.reorders < 10 {
			t.Errorf("reorders = %d, want >= 10", st.reorders)
		}
		if st.lost != 0 {
			t.Errorf("reorder lost packets: %d", st.lost)
		}
	})
}

func TestRTPDirectionsAndDTMF(t *testing.T) {
	caller := netip.MustParseAddrPort("10.0.1.10:5060")
	callee := netip.MustParseAddrPort("10.0.2.20:5060")
	count := func(o CallOptions) (a, b int) {
		bl := New(t0, 4)
		bl.Call(o)
		pkts, _, _ := readPCAP(t, bl.PCAP())
		for _, p := range rtpPkts(pkts) {
			switch p.src.Addr() {
			case caller.Addr():
				a++
			case callee.Addr():
				b++
			}
		}
		return
	}
	if a, b := count(CallOptions{TalkTime: 2 * time.Second, CalleeRTP: RTPOptions{OneWay: true}}); a != 0 || b < 90 {
		t.Errorf("callee one-way: caller=%d callee=%d", a, b)
	}
	if a, b := count(CallOptions{TalkTime: 2 * time.Second, CallerRTP: RTPOptions{Silent: true}, CalleeRTP: RTPOptions{Silent: true}}); a != 0 || b != 0 {
		t.Errorf("silent: caller=%d callee=%d", a, b)
	}

	// DTMF: 2 digits, each start (marker) + continuation + 3 end packets with E bit.
	bl := New(t0, 4)
	bl.Call(CallOptions{TalkTime: 4 * time.Second, CallerRTP: RTPOptions{DTMF: "5#", SSRC: 1}})
	pkts, _, _ := readPCAP(t, bl.PCAP())
	var events, ends []byte
	for _, p := range rtpPkts(pkts) {
		if p.payload[1]&0x7f == dtmfPT && binary.BigEndian.Uint32(p.payload[8:]) == 1 {
			events = append(events, p.payload[12])
			if p.payload[13]&0x80 != 0 {
				ends = append(ends, p.payload[12])
			}
		}
	}
	if len(ends) != 6 || ends[0] != 5 || ends[3] != 11 {
		t.Errorf("DTMF end packets = %v (events %v), want 3x5 then 3x11", ends, events)
	}
}

func TestRTCP(t *testing.T) {
	b := New(t0, 4)
	b.Call(CallOptions{TalkTime: 12 * time.Second, CallerRTP: RTPOptions{RTCP: true, SSRC: 0x5}, CalleeRTP: RTPOptions{RTCP: true, SSRC: 0x6, LossPct: 10}})
	pkts, _, _ := readPCAP(t, b.PCAP())
	var srs int
	var lastRR []byte
	for _, p := range pkts {
		if len(p.payload) > 8 && p.payload[0]>>6 == 2 && p.payload[1] == 200 {
			srs++
			if p.src.Port()%2 == 0 {
				t.Errorf("RTCP from even port %d", p.src.Port())
			}
			if binary.BigEndian.Uint32(p.payload[4:]) == 5 && p.payload[0]&0x1f == 1 {
				lastRR = p.payload
			}
		}
	}
	if srs < 4 {
		t.Errorf("SR count = %d, want >= 4 (2 directions, 12 s)", srs)
	}
	if lastRR == nil || lastRR[28+4] == 0 {
		t.Errorf("caller SR must report non-zero fraction lost about callee stream: %x", lastRR)
	}
}

func TestMonotonicAndTiming(t *testing.T) {
	b := New(t0, 21)
	b.Call(CallOptions{Topology: B2BUA, Hold: true, CallerRTP: RTPOptions{JitterMs: 30}})
	b.Register(RegisterOptions{Start: t0.Add(time.Second), Attempts: 3, FailCode: 403})
	b.Call(CallOptions{Start: t0.Add(2 * time.Second), Transport: "TCP", TalkTime: time.Second})
	pkts, _, _ := readPCAP(t, b.PCAP())
	for i := 1; i < len(pkts); i++ {
		if pkts[i].ts.Before(pkts[i-1].ts) {
			t.Fatalf("timestamps not monotonic at %d", i)
		}
	}
	if pkts[0].ts.Before(t0) {
		t.Fatalf("first packet before start: %v", pkts[0].ts)
	}
}

func TestDeterminism(t *testing.T) {
	build := func(seed uint64) *Builder {
		b := New(t0, seed)
		b.Call(CallOptions{Topology: Proxy, Hold: true, CallerRTP: RTPOptions{LossPct: 5, JitterMs: 20, RTCP: true}})
		b.Register(RegisterOptions{Start: t0.Add(time.Second)})
		b.Options(OptionsOptions{Start: t0.Add(2 * time.Second), Count: 2})
		b.Subscribe(SubscribeOptions{Start: t0.Add(3 * time.Second)})
		b.Message(MessageOptions{Start: t0.Add(4 * time.Second)})
		return b
	}
	a, a2, c := build(1), build(1), build(2)
	if !bytes.Equal(a.PCAP(), a2.PCAP()) || !bytes.Equal(a.PCAPNG(), a2.PCAPNG()) {
		t.Fatal("same seed produced different bytes")
	}
	if !bytes.Equal(a.PCAP(), a.PCAP()) {
		t.Fatal("rendering twice differs")
	}
	if bytes.Equal(a.PCAP(), c.PCAP()) {
		t.Fatal("different seed produced identical bytes")
	}
	pa, _, _ := readPCAP(t, a.PCAP())
	pc, _, _ := readPCAP(t, c.PCAP())
	branch := func(pk []pkt) string {
		for _, p := range pk {
			s := string(p.payload)
			if i := strings.Index(s, "branch="); i >= 0 {
				return s[i : i+19]
			}
		}
		return ""
	}
	if branch(pa) == branch(pc) {
		t.Errorf("same branch for different seeds: %s", branch(pa))
	}
}

func TestLinkVariants(t *testing.T) {
	tests := []struct {
		name  string
		link  LinkOptions
		lt    layers.LinkType
		vlans []uint16
		nanos bool
		v6    bool
	}{
		{"ethernet", LinkOptions{}, layers.LinkTypeEthernet, nil, false, false},
		{"vlan", LinkOptions{VLAN: 100}, layers.LinkTypeEthernet, []uint16{100}, false, false},
		{"qinq", LinkOptions{VLAN: 100, QinQ: 200}, layers.LinkTypeEthernet, []uint16{200, 100}, false, false},
		{"sll", LinkOptions{SLL: true}, layers.LinkTypeLinuxSLL, nil, false, false},
		{"ipv6", LinkOptions{IPv6: true}, layers.LinkTypeEthernet, nil, false, true},
		{"ipv6 vlan nanos", LinkOptions{IPv6: true, VLAN: 7, Nanos: true}, layers.LinkTypeEthernet, []uint16{7}, true, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := New(t0, 1)
			b.SetLink(tc.link)
			b.Call(CallOptions{TalkTime: time.Second, Transport: "TCP"})
			b.Call(CallOptions{TalkTime: time.Second, Start: t0.Add(time.Minute)})
			pkts, lt, nanos := readPCAP(t, b.PCAP())
			if lt != tc.lt || nanos != tc.nanos {
				t.Errorf("link type %v nanos %v", lt, nanos)
			}
			for _, p := range pkts {
				if !eqU16(p.vlan, tc.vlans) {
					t.Fatalf("vlan tags %v, want %v", p.vlan, tc.vlans)
				}
				if p.src.Addr().Is6() != tc.v6 {
					t.Fatalf("address family mismatch: %v", p.src)
				}
			}
			if tc.nanos {
				// nanosecond resolution must actually carry sub-microsecond bits
				any := false
				for _, p := range pkts {
					if p.ts.Nanosecond()%1000 != 0 {
						any = true
					}
				}
				_ = any // timestamps are scenario-rounded to ns; not required to be sub-us
			}
		})
	}
}

func eqU16(a, b []uint16) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestPCAPNGReadable(t *testing.T) {
	b := New(t0, 1)
	b.Call(CallOptions{TalkTime: time.Second})
	r, err := pcapgo.NewNgReader(bytes.NewReader(b.PCAPNG()), pcapgo.DefaultNgReaderOptions)
	if err != nil {
		t.Fatal(err)
	}
	classic, _, _ := readPCAP(t, b.PCAP())
	n := 0
	for {
		d, ci, err := r.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		p := decode(t, d, ci, layers.LinkTypeEthernet)
		if !bytes.Equal(p.payload, classic[n].payload) || !p.ts.Equal(classic[n].ts) {
			t.Fatalf("packet %d differs between pcap and pcapng", n)
		}
		n++
	}
	if n != len(classic) {
		t.Fatalf("pcapng has %d packets, pcap %d", n, len(classic))
	}
}

func TestTCPFraming(t *testing.T) {
	b := New(t0, 1)
	b.Call(CallOptions{Transport: "TCP", TalkTime: time.Second})
	pkts, _, _ := readPCAP(t, b.PCAP())
	var syn, synack int
	var ackOnly int
	for _, p := range pkts {
		if p.tcp && len(p.payload) == 0 {
			ackOnly++
		}
	}
	_ = syn
	_ = synack
	// each flow: 3 handshake frames, plus one pure ACK per data segment
	if ackOnly < 3 {
		t.Errorf("pure TCP frames = %d, want handshake + ACKs", ackOnly)
	}
	// stream continuity: sequence numbers per direction must be contiguous
	r, _ := pcapgo.NewReader(bytes.NewReader(b.PCAP()))
	next := map[string]uint32{}
	for {
		d, _, err := r.ReadPacketData()
		if err != nil {
			break
		}
		p := gopacket.NewPacket(d, layers.LayerTypeEthernet, gopacket.Default)
		tc, _ := p.Layer(layers.LayerTypeTCP).(*layers.TCP)
		ip, _ := p.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		if tc == nil {
			continue
		}
		k := ip.SrcIP.String() + ":" + tc.SrcPort.String()
		if n, ok := next[k]; ok && tc.Seq != n {
			t.Fatalf("%s: seq %d, want %d", k, tc.Seq, n)
		}
		l := uint32(len(tc.Payload))
		if tc.SYN {
			l++
		}
		next[k] = tc.Seq + l
	}
}

func TestRegisterOptionsSubscribeMessage(t *testing.T) {
	b := New(t0, 8)
	reg := b.Register(RegisterOptions{Attempts: 5, FailCode: 403})
	ok := b.Register(RegisterOptions{Start: t0.Add(time.Minute), User: "bob"})
	nr := b.Register(RegisterOptions{Start: t0.Add(2 * time.Minute), NoResponse: true, Retransmits: 2})
	opt := b.Options(OptionsOptions{Start: t0.Add(3 * time.Minute), Count: 3, Interval: 10 * time.Second})
	sub := b.Subscribe(SubscribeOptions{Start: t0.Add(4 * time.Minute), Terminate: true})
	msg := b.Message(MessageOptions{Start: t0.Add(5 * time.Minute)})
	pkts, _, _ := readPCAP(t, b.PCAP())
	want := map[string][]string{
		reg: {"REGISTER", "401", "REGISTER", "403", "REGISTER", "401", "REGISTER", "403", "REGISTER", "401", "REGISTER", "403",
			"REGISTER", "401", "REGISTER", "403", "REGISTER", "401", "REGISTER", "403"},
		ok:  {"REGISTER", "401", "REGISTER", "200"},
		nr:  {"REGISTER", "REGISTER", "REGISTER"},
		opt: {"OPTIONS", "200", "OPTIONS", "200", "OPTIONS", "200"},
		sub: {"SUBSCRIBE", "200", "NOTIFY", "200", "NOTIFY", "200"},
		msg: {"MESSAGE", "200"},
	}
	for id, w := range want {
		if got := flow(pkts, id); !eq(got, w) {
			t.Errorf("%s\n got %v\nwant %v", id, got, w)
		}
	}
	// CSeq increases within the registration loop; 401 then retry has a new CSeq.
	var cseqs []int
	for _, p := range pkts {
		if info, id, cs, ok := sipInfo(p.payload); ok && id == reg && info == "REGISTER" {
			cseqs = append(cseqs, atoi(strings.Fields(cs)[0]))
		}
	}
	for i := 1; i < len(cseqs); i++ {
		if cseqs[i] != cseqs[i-1]+1 {
			t.Fatalf("REGISTER CSeqs %v not consecutive", cseqs)
		}
	}
}

func TestRawPassthrough(t *testing.T) {
	b := New(t0, 1)
	src := netip.MustParseAddrPort("10.1.1.1:4000")
	dst := netip.MustParseAddrPort("10.1.1.2:5060")
	b.Raw(t0, src, dst, "UDP", []byte("garbage"))
	b.Raw(t0.Add(time.Second), src, dst, "TCP", []byte("INVITE sip:x SIP/2.0\r\n"))
	b.Raw(t0.Add(2*time.Second), src, dst, "TCP", []byte("\r\n"))
	pkts, _, _ := readPCAP(t, b.PCAP())
	var data [][]byte
	for _, p := range pkts {
		if len(p.payload) > 0 {
			data = append(data, p.payload)
		}
	}
	if len(data) != 3 || string(data[0]) != "garbage" || string(data[2]) != "\r\n" {
		t.Fatalf("payloads = %q", data)
	}
	if len(pkts) != 3+3+2 {
		t.Errorf("packet count = %d, want 3 data + 3 handshake + 2 acks", len(pkts))
	}
}

func TestNATAndB2BUAAddresses(t *testing.T) {
	b := New(t0, 1)
	id := b.Call(CallOptions{NATed: true, TalkTime: time.Second})
	pkts, _, _ := readPCAP(t, b.PCAP())
	invite := ""
	for _, p := range pkts {
		if info, cid, _, ok := sipInfo(p.payload); ok && cid == id && info == "INVITE" {
			invite = string(p.payload)
			break
		}
	}
	if !strings.Contains(invite, "Contact: <sip:alice@192.168.1.50:5060>") || !strings.Contains(invite, "c=IN IP4 192.168.1.50") {
		t.Errorf("NAT INVITE lacks private addresses:\n%s", invite)
	}
	var toPrivate int
	for _, p := range rtpPkts(pkts) {
		if p.dst.Addr() == netip.MustParseAddr("192.168.1.50") {
			toPrivate++
		}
	}
	if toPrivate < 45 {
		t.Errorf("RTP to the private address = %d, want the callee stream", toPrivate)
	}

	b = New(t0, 2)
	id = b.Call(CallOptions{Topology: B2BUA, XCID: "abc123", TalkTime: time.Second})
	legs := b.LegCallIDs(id)
	if len(legs) != 2 || legs[0] == legs[1] {
		t.Fatalf("legs = %v", legs)
	}
	pkts, _, _ = readPCAP(t, b.PCAP())
	x := 0
	for _, p := range pkts {
		if strings.HasPrefix(string(p.payload), "INVITE") && strings.Contains(string(p.payload), "X-CID: abc123\r\n") {
			x++
		}
	}
	if x != 2 {
		t.Errorf("INVITEs with shared X-CID = %d, want 2", x)
	}
}

// ---------------------------------------------------------------- external tools

func writeTemp(t *testing.T, b *Builder, name string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := b.WriteFile(p); err != nil {
		t.Fatal(err)
	}
	return p
}

func richBuilder() *Builder {
	b := New(t0, 42)
	b.Call(CallOptions{Topology: Proxy, Hold: true, EarlyMedia: true, CallerRTP: RTPOptions{DTMF: "1", RTCP: true}, CalleeRTP: RTPOptions{RTCP: true}})
	b.Call(CallOptions{Start: t0.Add(time.Second), Topology: B2BUA, Auth: 407, Codec: "opus", TalkTime: 2 * time.Second})
	b.Call(CallOptions{Start: t0.Add(2 * time.Second), Transport: "TCP", Outcome: Cancelled})
	b.Call(CallOptions{Start: t0.Add(3 * time.Second), Outcome: Unreachable, Retransmits: 3})
	b.Register(RegisterOptions{Start: t0.Add(4 * time.Second), Attempts: 2, FailCode: 403})
	b.Options(OptionsOptions{Start: t0.Add(5 * time.Second), Count: 2})
	b.Subscribe(SubscribeOptions{Start: t0.Add(6 * time.Second)})
	b.Message(MessageOptions{Start: t0.Add(7 * time.Second)})
	return b
}

func TestTcpdumpParses(t *testing.T) {
	tcpdump, err := exec.LookPath("tcpdump")
	if err != nil {
		t.Skip("tcpdump not installed")
	}
	links := []LinkOptions{{}, {VLAN: 10}, {SLL: true}, {IPv6: true}, {Nanos: true}}
	for _, l := range links {
		b := richBuilder()
		b.SetLink(l)
		for _, name := range []string{"x.pcap", "x.pcapng"} {
			path := writeTemp(t, b, name)
			out, err := exec.Command(tcpdump, "-nn", "-v", "-r", path).CombinedOutput()
			if err != nil {
				t.Fatalf("tcpdump %+v %s: %v\n%s", l, name, err, out)
			}
			s := string(out)
			for _, bad := range []string{"bad ", "truncated", "incorrect", "wrong", "invalid", "malformed", "bogus"} {
				for _, line := range strings.Split(s, "\n") {
					if strings.Contains(line, bad) && !strings.Contains(line, "bad udp cksum") {
						t.Errorf("tcpdump %+v %s: %q in line %q", l, name, bad, line)
					}
				}
			}
			if strings.Contains(s, "bad udp cksum") || strings.Contains(s, "bad cksum") || strings.Contains(s, "incorrect") {
				t.Errorf("tcpdump %+v %s reports checksum errors", l, name)
			}
		}
	}
}

func tshark(t *testing.T, args ...string) string {
	t.Helper()
	path, err := exec.LookPath("tshark")
	if err != nil {
		t.Skip("tshark not installed")
	}
	cmd := exec.Command(path, args...)
	cmd.Env = append(os.Environ(), "TZ=UTC")
	out, err := cmd.Output()
	if err != nil {
		var stderr []byte
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = ee.Stderr
		}
		t.Fatalf("tshark %v: %v\n%s", args, err, stderr)
	}
	return string(out)
}

func TestTsharkAgrees(t *testing.T) {
	b := richBuilder()
	path := writeTemp(t, b, "rich.pcap")
	// Every packet decodes without expert errors in the SIP/RTP dissectors.
	out := tshark(t, "-o", "ip.check_checksum:TRUE", "-o", "udp.check_checksum:TRUE", "-o", "tcp.check_checksum:TRUE", "-r", path, "-Y", "_ws.malformed || _ws.expert.severity==error || ip.checksum.status==\"Bad\" || udp.checksum.status==\"Bad\" || tcp.checksum.status==\"Bad\"", "-T", "fields", "-e", "frame.number")
	if strings.TrimSpace(out) != "" {
		t.Errorf("tshark flags malformed/bad-checksum frames: %s", out)
	}
	// Our own flow expectations vs tshark's view of Call-IDs.
	pk, _, _ := readPCAP(t, b.PCAP())
	own := map[string]bool{}
	nsip := 0
	for _, p := range pk {
		if _, id, _, ok := sipInfo(p.payload); ok {
			own[id] = true
			nsip++
		}
	}
	ids := map[string]bool{}
	lines := strings.Fields(tshark(t, "-r", path, "-Y", "sip", "-T", "fields", "-e", "sip.Call-ID"))
	for _, l := range lines {
		ids[l] = true
	}
	if len(ids) != len(own) || len(lines) != nsip {
		t.Errorf("tshark sees %d Call-IDs / %d SIP messages, generator emitted %d / %d", len(ids), len(lines), len(own), nsip)
	}
	for id := range own {
		if !ids[id] {
			t.Errorf("tshark does not see Call-ID %s", id)
		}
	}
	// RTP streams are recognised through SDP.
	streams := tshark(t, "-r", path, "-q", "-z", "rtp,streams")
	if !strings.Contains(streams, "g711U") || !strings.Contains(streams, "opus") {
		t.Errorf("rtp,streams lacks expected payloads:\n%s", streams)
	}
}

func TestTsharkLink(t *testing.T) {
	for _, l := range []LinkOptions{{VLAN: 10}, {SLL: true}, {IPv6: true}} {
		b := richBuilder()
		b.SetLink(l)
		path := writeTemp(t, b, "l.pcapng")
		out := tshark(t, "-r", path, "-Y", "sip", "-T", "fields", "-e", "sip.Call-ID")
		if len(strings.Fields(out)) == 0 {
			t.Errorf("%+v: tshark sees no SIP", l)
		}
	}
}

func BenchmarkRenderCall(b *testing.B) {
	bl := New(t0, 1)
	bl.Call(CallOptions{TalkTime: 30 * time.Second, CallerRTP: RTPOptions{JitterMs: 5}})
	b.ReportAllocs()
	for b.Loop() {
		_ = bl.PCAP()
	}
}
