package pcaptest

import (
	"encoding/binary"
	"fmt"
	"math"
	"net/netip"
	"sort"
	"strings"
	"time"
)

// Gap is a hole in a media stream: nothing is captured from At (relative to
// the first packet of the stream) for For. The sender's sequence numbers and
// timestamps keep advancing, so a receiver sees the gap as packet loss.
type Gap struct {
	At, For time.Duration
}

// RTPOptions shapes the media of one direction of a call.
type RTPOptions struct {
	// PacketsPerSecond defaults to 50 (ptime 20 ms).
	PacketsPerSecond int
	// LossPct is the percentage of packets dropped before the capture point
	// (0-100). The pattern is deterministic for a given seed.
	LossPct float64
	// JitterMs is the standard deviation, in milliseconds, of the per-packet
	// network delay. Packets are delivered FIFO (a late packet delays the
	// ones behind it into a burst), RTP sequence numbers and timestamps are
	// untouched. The RFC 3550 interarrival jitter a receiver computes from
	// such a stream is about 1.13 times JitterMs.
	JitterMs float64
	// DupPct is the percentage of packets captured twice (same sequence number, 1 ms apart).
	DupPct float64
	// ReorderPct is the percentage of packets whose arrival is swapped with the next packet.
	ReorderPct float64
	// Gap, when Gap.For > 0, removes the packets inside the gap.
	Gap Gap
	// Silent suppresses this direction entirely (no RTP is sent).
	Silent bool
	// OneWay makes this the only direction with media: the opposite
	// direction is silent.
	OneWay bool
	// SSRC is the synchronisation source; 0 picks one from the seed.
	SSRC uint32
	// DTMF is a string of digits (0-9, *, #, A-D) sent as RFC 4733
	// telephone-event packets, starting DTMFAt after the first packet.
	DTMF string
	// DTMFAt defaults to 1 s.
	DTMFAt time.Duration
	// RTCP adds an RTCP sender report (or receiver report when the
	// direction is silent) every 5 s on RTP port + 1.
	RTCP bool
	// MaxPackets, when positive, stops the direction after that many
	// packets (a short burst; the packets are still timed as at the start of
	// the talk spurt).
	MaxPackets int
	// Port overrides the RTP port of the sending side; 0 picks a random even port.
	Port uint16
}

// codecInfo describes a codec as negotiated in SDP.
type codecInfo struct {
	name    string
	pt      uint8
	clock   int
	bytesPS int // payload bytes per second
	fmtp    string
	chans   string
}

var codecTable = map[string]codecInfo{
	"PCMU": {name: "PCMU", pt: 0, clock: 8000, bytesPS: 8000},
	"PCMA": {name: "PCMA", pt: 8, clock: 8000, bytesPS: 8000},
	"G729": {name: "G729", pt: 18, clock: 8000, bytesPS: 1000, fmtp: "annexb=no"},
	"opus": {name: "opus", pt: 111, clock: 48000, bytesPS: 3000, fmtp: "minptime=10;useinbandfec=1", chans: "/2"},
}

const dtmfPT = 101

func lookupCodec(name string) codecInfo {
	if name == "" {
		name = "PCMU"
	}
	if c, ok := codecTable[name]; ok {
		return c
	}
	panic(fmt.Sprintf("pcaptest: unknown codec %q (want PCMU, PCMA, G729 or opus)", name))
}

// sdpMedia describes one SDP body.
type sdpMedia struct {
	addr    netip.AddrPort
	codecs  []codecInfo
	dir     string // sendrecv, sendonly, recvonly, inactive
	zeroIP  bool   // c=0.0.0.0 (hold)
	pps     int
	sessID  uint64
	version int
	name    string // s= line
	user    string // o= username
	dtmf    bool
	compact bool // no fmtp, ptime or telephone-event
}

func (s sdpMedia) String() string {
	ipv := "IP4"
	if s.addr.Addr().Is6() {
		ipv = "IP6"
	}
	caddr := s.addr.Addr().String()
	if s.zeroIP {
		caddr = "0.0.0.0"
		if s.addr.Addr().Is6() {
			caddr = "::"
		}
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "v=0\r\no=%s %d %d IN %s %s\r\ns=%s\r\nc=IN %s %s\r\nt=0 0\r\n",
		s.user, s.sessID, s.sessID+uint64(s.version), ipv, s.addr.Addr(), s.name, ipv, caddr)
	fmt.Fprintf(&sb, "m=audio %d RTP/AVP", s.addr.Port())
	for _, c := range s.codecs {
		fmt.Fprintf(&sb, " %d", c.pt)
	}
	dtmf := s.dtmf && !s.compact
	if dtmf {
		fmt.Fprintf(&sb, " %d", dtmfPT)
	}
	sb.WriteString("\r\n")
	for _, c := range s.codecs {
		fmt.Fprintf(&sb, "a=rtpmap:%d %s/%d%s\r\n", c.pt, c.name, c.clock, c.chans)
		if c.fmtp != "" && !s.compact {
			fmt.Fprintf(&sb, "a=fmtp:%d %s\r\n", c.pt, c.fmtp)
		}
	}
	if dtmf {
		clock := s.codecs[0].clock
		fmt.Fprintf(&sb, "a=rtpmap:%d telephone-event/%d\r\na=fmtp:%d 0-16\r\n", dtmfPT, clock, dtmfPT)
	}
	pps := s.pps
	if pps <= 0 {
		pps = 50
	}
	if !s.compact {
		fmt.Fprintf(&sb, "a=ptime:%d\r\n", 1000/pps)
	}
	fmt.Fprintf(&sb, "a=%s\r\n", s.dir)
	return sb.String()
}

// rtpRec is one generated media packet before it is rendered.
type rtpRec struct {
	nominal time.Time
	arrive  time.Time
	seq     uint16
	ts      uint32
	size    int
	lost    bool
	dup     bool
}

// rtpPlan is one media direction to be generated.
type rtpPlan struct {
	src, dst  netip.AddrPort
	codec     codecInfo
	o         RTPOptions
	ssrc      uint32
	intervals [][2]time.Time // active [start, end) windows
	dtmf      bool           // telephone-event negotiated
	delay     time.Duration  // fixed extra delay (relay)
	clean     bool           // ignore loss/jitter/dup/reorder (relay leg)
}

// rtpStats summarises a generated stream for RTCP.
type rtpStats struct {
	recs  []rtpRec
	first time.Time
	pkts  []timedPkt // captured packets (incl. duplicates), for relaying
}

// timedPkt is one captured UDP payload.
type timedPkt struct {
	at   time.Time
	data []byte
}

// relay re-emits the captured packets of st from src to dst with a new SSRC
// and a fixed extra delay, as a media relay (SBC) would. Sequence numbers,
// timestamps, loss gaps, jitter and reordering are preserved.
func (b *Builder) relay(st rtpStats, src, dst netip.AddrPort, ssrc uint32, delay time.Duration) rtpStats {
	out := rtpStats{recs: st.recs, first: st.first.Add(delay)}
	for _, p := range st.pkts {
		d := append([]byte(nil), p.data...)
		binary.BigEndian.PutUint32(d[8:], ssrc)
		at := p.at.Add(delay)
		b.add(at, src, dst, false, d)
		out.pkts = append(out.pkts, timedPkt{at, d})
	}
	return out
}

// normal returns an approximately Gaussian sample (mean 0, std 1), the sum of
// 6 uniforms, so it is bounded and cheap.
func (b *Builder) normal() float64 {
	s := 0.0
	for range 6 {
		s += b.rng.Float64()
	}
	return (s - 3) / math.Sqrt(0.5)
}

var dtmfEvents = map[byte]uint8{'0': 0, '1': 1, '2': 2, '3': 3, '4': 4, '5': 5, '6': 6, '7': 7, '8': 8, '9': 9, '*': 10, '#': 11, 'A': 12, 'B': 13, 'C': 14, 'D': 15}

// genRTP generates the packets of p, adds them to the builder and returns the
// stats RTCP needs.
func (b *Builder) genRTP(p rtpPlan) rtpStats {
	var st rtpStats
	if p.o.Silent || len(p.intervals) == 0 {
		return st
	}
	pps := p.o.PacketsPerSecond
	if pps <= 0 {
		pps = 50
	}
	step := time.Second / time.Duration(pps)
	tsStep := uint32(p.codec.clock / pps)
	base := p.intervals[0][0]
	st.first = base
	seq := uint16(b.rng.Uint32())
	ts0 := b.rng.Uint32()
	payloadN := p.codec.bytesPS / pps
	if payloadN < 1 {
		payloadN = 1
	}
	jit := p.o.JitterMs
	loss, dup, reorder := p.o.LossPct/100, p.o.DupPct/100, p.o.ReorderPct/100
	if p.clean {
		jit, loss, dup, reorder = 0, 0, 0, 0
	}

	// DTMF schedule: slot ranges replaced by event packets.
	type dtmfSlot struct {
		event    uint8
		durUnits uint16 // duration in clock ticks at this slot
		end      bool
		first    bool
		evTS     uint32 // timestamp of the event start
	}
	dslots := map[int]dtmfSlot{}
	if p.o.DTMF != "" && p.dtmf {
		at := p.o.DTMFAt
		if at <= 0 {
			at = time.Second
		}
		slot := int(at / step)
		for i := range len(p.o.DTMF) {
			ev, ok := dtmfEvents[p.o.DTMF[i]]
			if !ok {
				continue
			}
			n := 6 // 120 ms of tone
			evTS := ts0 + uint32(slot)*tsStep
			for k := range n {
				dslots[slot+k] = dtmfSlot{event: ev, durUnits: uint16((k + 1) * int(tsStep)), first: k == 0, evTS: evTS}
			}
			for k := range 3 {
				dslots[slot+n+k] = dtmfSlot{event: ev, durUnits: uint16(n * int(tsStep)), end: true, evTS: evTS}
			}
			slot += n + 3 + 5 // 100 ms pause between digits
		}
	}

	var recs []rtpRec
	var lastArrive time.Time
	for ii, iv := range p.intervals {
		first := true
		k0 := int(iv[0].Sub(base) / step)
		for t := iv[0]; t.Before(iv[1]); t = t.Add(step) {
			if p.o.MaxPackets > 0 && len(recs) >= p.o.MaxPackets {
				break
			}
			slot := int(t.Sub(base) / step)
			_ = k0
			cur := seq
			seq++
			rec := rtpRec{nominal: t, seq: cur, ts: ts0 + uint32(slot)*tsStep, size: payloadN}
			if ds, ok := dslots[slot]; ok {
				rec.ts = ds.evTS
				rec.size = 4
			}
			if first && ii >= 0 {
				first = false
				// marker is decided at render time via the nominal start of an interval.
				rec.dup = false
			}
			g := p.o.Gap
			inGap := g.For > 0 && t.Sub(base) >= g.At && t.Sub(base) < g.At+g.For
			if inGap || (loss > 0 && b.rng.Float64() < loss) {
				rec.lost = true
			}
			delay := p.delay
			if jit > 0 {
				d := 3*jit + jit*b.normal()
				if d < 0 {
					d = 0
				}
				delay += time.Duration(d * float64(time.Millisecond))
			}
			rec.arrive = t.Add(delay)
			if !rec.lost {
				if !rec.arrive.After(lastArrive) {
					rec.arrive = lastArrive.Add(20 * time.Microsecond)
				}
				lastArrive = rec.arrive
			}
			recs = append(recs, rec)
		}
	}
	// reorder: swap arrival times with the next captured packet
	if reorder > 0 {
		var prev = -1
		for i := range recs {
			if recs[i].lost {
				continue
			}
			if prev >= 0 && b.rng.Float64() < reorder {
				recs[prev].arrive, recs[i].arrive = recs[i].arrive, recs[prev].arrive
				prev = -1
				continue
			}
			prev = i
		}
	}
	st.recs = recs

	// render
	starts := map[time.Time]bool{}
	for _, iv := range p.intervals {
		starts[iv[0]] = true
	}
	for _, r := range recs {
		if r.lost {
			continue
		}
		slot := int(r.nominal.Sub(base) / step)
		hdr := make([]byte, 12, 12+r.size)
		hdr[0] = 0x80
		pt := p.codec.pt
		marker := starts[r.nominal]
		ds, isD := dslots[slot]
		if isD {
			pt = dtmfPT
			marker = ds.first
		}
		hdr[1] = pt
		if marker {
			hdr[1] |= 0x80
		}
		binary.BigEndian.PutUint16(hdr[2:], r.seq)
		binary.BigEndian.PutUint32(hdr[4:], r.ts)
		binary.BigEndian.PutUint32(hdr[8:], p.ssrc)
		pkt := hdr
		if isD {
			e := ds.event
			var flag byte = 10 // volume -10 dBm0
			if ds.end {
				flag |= 0x80
			}
			var d [2]byte
			binary.BigEndian.PutUint16(d[:], ds.durUnits)
			pkt = append(pkt, e, flag, d[0], d[1])
		} else {
			pkt = b.appendNoise(pkt, r.size, p.codec)
		}
		b.add(r.arrive, p.src, p.dst, false, pkt)
		st.pkts = append(st.pkts, timedPkt{r.arrive, pkt})
		if dup > 0 && b.rng.Float64() < dup {
			b.add(r.arrive.Add(time.Millisecond), p.src, p.dst, false, pkt)
			st.pkts = append(st.pkts, timedPkt{r.arrive.Add(time.Millisecond), pkt})
		}
	}
	return st
}

// appendNoise appends n pseudo-random payload bytes (deterministic).
func (b *Builder) appendNoise(dst []byte, n int, c codecInfo) []byte {
	if c.name == "opus" {
		// opus frames vary in size; the first byte is a valid TOC byte
		// (CELT fullband, 20 ms, code 0: a single frame) so dissectors accept it.
		n = n - 10 + b.rng.IntN(21)
		dst = append(dst, 0xf8)
		n--
	}
	for n >= 8 {
		var w [8]byte
		binary.LittleEndian.PutUint64(w[:], b.rng.Uint64())
		dst = append(dst, w[:]...)
		n -= 8
	}
	for ; n > 0; n-- {
		dst = append(dst, byte(b.rng.Uint32()))
	}
	return dst
}

// counts returns packets sent, packets captured, payload octets sent and the
// last timestamp at or before t.
func (st rtpStats) counts(t time.Time) (sent, got, octets int, lastTS uint32, lastSeq uint16) {
	for _, r := range st.recs {
		if r.nominal.After(t) {
			break
		}
		sent++
		octets += r.size
		lastTS, lastSeq = r.ts, r.seq
		if !r.lost && !r.arrive.After(t) {
			got++
		}
	}
	return
}

// genRTCP adds a compound RTCP packet every 5 s for each plan with RTCP
// enabled. a is the plan being reported on, rev the opposite direction (its
// stats feed the reception report block).
func (b *Builder) genRTCP(a rtpPlan, as rtpStats, rev rtpPlan, rs rtpStats, cname string) {
	if !a.o.RTCP || len(a.intervals) == 0 {
		return
	}
	end := a.intervals[len(a.intervals)-1][1]
	start := a.intervals[0][0]
	if as.recs == nil {
		// silent direction: its owner sends RR about the reverse stream
		start = rev.intervals0()
	}
	var lastExp, lastGot int
	for t := start.Add(5 * time.Second); t.Before(end); t = t.Add(5 * time.Second) {
		var pkt []byte
		sent, _, octets, lastTS, _ := as.counts(t)
		blockSSRC := rev.ssrc
		exp, got, _, _, lastSeq := rs.counts(t)
		haveBlock := rs.recs != nil && exp > 0
		var blk []byte
		if haveBlock {
			lost := exp - got
			frac := 0
			if de := exp - lastExp; de > 0 {
				frac = (de - (got - lastGot)) * 256 / de
				if frac > 255 {
					frac = 255
				}
				if frac < 0 {
					frac = 0
				}
			}
			lastExp, lastGot = exp, got
			blk = make([]byte, 24)
			binary.BigEndian.PutUint32(blk[0:], blockSSRC)
			blk[4] = byte(frac)
			blk[5], blk[6], blk[7] = byte(lost>>16), byte(lost>>8), byte(lost)
			binary.BigEndian.PutUint32(blk[8:], uint32(lastSeq)|0)
			jit := uint32(rev.o.JitterMs * 1.13 * float64(rev.codec.clock) / 1000)
			binary.BigEndian.PutUint32(blk[12:], jit)
			// LSR / DLSR left at zero (no SR received yet)
		}
		rc := 0
		if haveBlock {
			rc = 1
		}
		if as.recs != nil {
			sr := make([]byte, 28)
			sr[0] = 0x80 | byte(rc)
			sr[1] = 200
			binary.BigEndian.PutUint16(sr[2:], uint16(6+6*rc))
			binary.BigEndian.PutUint32(sr[4:], a.ssrc)
			binary.BigEndian.PutUint64(sr[8:], ntpTime(t))
			binary.BigEndian.PutUint32(sr[16:], lastTS)
			binary.BigEndian.PutUint32(sr[20:], uint32(sent))
			binary.BigEndian.PutUint32(sr[24:], uint32(octets))
			pkt = append(sr, blk...)
		} else {
			rr := make([]byte, 8)
			rr[0] = 0x80 | byte(rc)
			rr[1] = 201
			binary.BigEndian.PutUint16(rr[2:], uint16(1+6*rc))
			binary.BigEndian.PutUint32(rr[4:], a.ssrc)
			pkt = append(rr, blk...)
		}
		// SDES with CNAME
		cn := []byte(cname)
		item := append([]byte{1, byte(len(cn))}, cn...)
		chunk := append(make([]byte, 4), item...)
		binary.BigEndian.PutUint32(chunk, a.ssrc)
		chunk = append(chunk, 0)
		for len(chunk)%4 != 0 {
			chunk = append(chunk, 0)
		}
		sd := make([]byte, 4)
		sd[0] = 0x81
		sd[1] = 202
		binary.BigEndian.PutUint16(sd[2:], uint16(len(chunk)/4))
		pkt = append(pkt, sd...)
		pkt = append(pkt, chunk...)
		src := netip.AddrPortFrom(a.src.Addr(), a.src.Port()+1)
		dst := netip.AddrPortFrom(a.dst.Addr(), a.dst.Port()+1)
		b.add(t.Add(3*time.Millisecond), src, dst, false, pkt)
	}
}

func (p rtpPlan) intervals0() time.Time {
	if len(p.intervals) == 0 {
		return time.Time{}
	}
	return p.intervals[0][0]
}

// mergeIntervals sorts and drops empty intervals.
func mergeIntervals(iv [][2]time.Time) [][2]time.Time {
	out := iv[:0:0]
	for _, i := range iv {
		if i[1].After(i[0]) {
			out = append(out, i)
		}
	}
	sort.Slice(out, func(a, c int) bool { return out[a][0].Before(out[c][0]) })
	return out
}
