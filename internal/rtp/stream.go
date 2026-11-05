package rtp

import (
	"math"

	"github.com/sotoz/sipcurious/internal/capture"
)

const (
	// RFC 3550 appendix A.1 sequence number validation constants.
	maxDropout  = 3000
	maxMisorder = 100
	// probationGap is the largest forward sequence step that still counts as
	// "plausibly continuous" while a flow is under probation (loss of up to
	// 99 consecutive packets does not prevent detection).
	probationGap = 100

	// jitterResetSec: a jump of the packet transit time larger than this is
	// a timestamp discontinuity (sender re-based its timestamps after a pause
	// or restart) and re-baselines the jitter estimator instead of being
	// averaged into it. The stall itself is visible in MaxGap.
	jitterResetSec = 2.0
)

// ptSlot counts packets of one payload type (a stream rarely has more than
// two or three; see stream.pts).
type ptSlot struct {
	n  uint32
	pt uint8
}

// stream is the mutable state of one (src, dst, SSRC) flow. It holds only
// counters and fixed-size arrays: memory per stream is constant (about 0.7 KB)
// no matter how long it lasts.
type stream struct {
	key        Key
	firstIndex int
	startNs    int64
	endNs      int64
	lastNs     int64 // arrival time of the previous packet, UnixNano

	// RFC 3550 A.1 / A.3 sequence tracking.
	packets, bytes uint64
	baseExt        uint32 // extended seq of the first packet of the current segment
	maxExt         uint32 // highest extended seq (cycles << 16 | seq)
	expAcc         uint64 // expected packets of finished segments (after a restart)
	stray          uint64 // packets outside any segment (isolated bad sequence numbers)
	badNext        uint16
	hasBad         bool
	win            [2]uint64 // bit i set: seq maxExt-i was received (i < 128)
	dups, reorders uint64
	maxGap         int64
	valid          int // probation: plausibly continuous packets so far
	reported       bool

	// payload types
	pts      [4]ptSlot
	mediaPT  uint8
	hasMedia bool
	evtPT    uint8
	hasEvt   bool
	events   int
	evtTS    [4]uint32 // timestamps of the most recent distinct events
	evtN     int       // number of valid entries in evtTS (saturating at 4)
	evtNext  int

	// RFC 3550 A.8 jitter, one estimator per candidate clock rate because the
	// rate of a dynamic payload type may only be known when results are read.
	lastTS   uint32
	tsExt    int64 // unwrapped timestamp relative to the first jitter packet
	jInit    bool
	jFirstNs int64
	jLastNs  int64
	jN       uint64
	transit  [nRates]float64
	jit      [nRates]float64
	jSum     [nRates]float64
	jMax     [nRates]float64
}

// Sequence classification of one packet.
const (
	seqInOrder = iota
	seqReordered
	seqDuplicate
	seqStray
	seqRestart
)

// add accounts one RTP packet of the stream.
func (s *stream) add(h *Handler, hd *Header, p *capture.Packet) {
	nowNs := p.Time.UnixNano()
	if s.packets > 0 && !s.reported && !probationStep(hd.Seq, uint16(s.maxExt)) {
		// Not plausibly continuous: forget the candidate's past.
		*s = stream{key: s.key, firstIndex: p.Index}
	}
	first := s.packets == 0
	s.packets++
	s.bytes += uint64(hd.PayloadLen)
	if first {
		s.startNs, s.endNs, s.lastNs = nowNs, nowNs, nowNs
		s.baseExt, s.maxExt = uint32(hd.Seq), uint32(hd.Seq)
		s.win = [2]uint64{1, 0}
		s.valid = 1
	} else {
		if gap := nowNs - s.lastNs; gap > s.maxGap {
			s.maxGap = gap
		}
		s.lastNs = nowNs
		s.startNs = min(s.startNs, nowNs)
		s.endNs = max(s.endNs, nowNs)
	}

	kind := seqInOrder
	if !first {
		kind = s.updateSeq(hd.Seq)
	}

	event := s.classify(h, hd)
	if event {
		s.countEvent(hd.Timestamp)
	} else {
		s.countPT(hd.PayloadType)
	}
	if event || kind == seqDuplicate || kind == seqStray {
		return
	}
	s.jitter(hd.Timestamp, nowNs)
}

// probationStep reports whether seq may follow last in a flow under probation.
func probationStep(seq, last uint16) bool {
	d := seq - last
	return d <= probationGap || d >= 65536-maxMisorder
}

// updateSeq implements RFC 3550 appendix A.1 with a 128-packet history for
// duplicate detection, and returns what the packet was.
func (s *stream) updateSeq(seq uint16) int {
	udelta := seq - uint16(s.maxExt)
	switch {
	case udelta < maxDropout:
		s.hasBad = false
		if udelta == 0 {
			s.dups++
			return seqDuplicate
		}
		s.maxExt += uint32(udelta)
		s.shiftWindow(uint(udelta))
		s.valid++
		return seqInOrder
	case udelta <= 65536-maxMisorder:
		// A large jump: a restart of the sender, a long outage, or garbage.
		if s.hasBad && seq == s.badNext {
			// Two sequential packets after the jump: the sender restarted.
			// Close the old segment and open a new one that includes the
			// first of the two (counted as stray until now).
			s.expAcc += uint64(s.maxExt-s.baseExt) + 1
			s.baseExt = uint32(seq - 1)
			s.maxExt = s.baseExt + 1
			s.win = [2]uint64{3, 0}
			s.hasBad = false
			s.stray--
			s.valid++
			return seqRestart
		}
		s.hasBad = true
		s.badNext = seq + 1
		s.stray++
		return seqStray
	default:
		// Late packet: duplicate or reordered.
		back := uint(65536-int(udelta)) % 65536
		if ext := s.maxExt - uint32(back); int32(ext-s.baseExt) < 0 {
			s.baseExt = ext // the first packets of the stream arrived reordered
		}
		if s.win[back>>6]&(1<<(back&63)) != 0 {
			s.dups++
			return seqDuplicate
		}
		s.win[back>>6] |= 1 << (back & 63)
		s.reorders++
		return seqReordered
	}
}

// shiftWindow advances the duplicate-detection window by d packets.
func (s *stream) shiftWindow(d uint) {
	switch {
	case d >= 128:
		s.win = [2]uint64{1, 0}
	case d >= 64:
		s.win[1] = s.win[0] << (d - 64)
		s.win[0] = 1
	default:
		s.win[1] = s.win[1]<<d | s.win[0]>>(64-d)
		s.win[0] = s.win[0]<<d | 1
	}
}

// classify decides whether the packet is an RFC 4733 telephone-event packet.
// With a telephone-event hint for the payload type (SetFormats before the
// packets) the answer is exact. Without it an event packet is a packet of a
// dynamic payload type (96..127) that differs from the stream's current media
// payload type and carries exactly one 4-byte event (or, once the event
// payload type is learned, any multiple of 4 bytes). SRTP-protected events
// carry an authentication tag, so they are only recognised through a hint.
func (s *stream) classify(h *Handler, hd *Header) bool {
	pt := hd.PayloadType
	if h.fmts[pt].event {
		s.evtPT, s.hasEvt = pt, true
		return true
	}
	if pt >= 96 {
		n := hd.PayloadLen
		if s.hasEvt && pt == s.evtPT && n >= 4 && n%4 == 0 {
			return true
		}
		if s.hasMedia && pt != s.mediaPT && n == 4 && !h.fmts[pt].set {
			s.evtPT, s.hasEvt = pt, true
			return true
		}
	}
	s.mediaPT, s.hasMedia = pt, true
	return false
}

// countEvent counts distinct RFC 4733 events: packets of one event share the
// RTP timestamp of its start, retransmissions of the end packets repeat it.
func (s *stream) countEvent(ts uint32) {
	for i := 0; i < s.evtN; i++ {
		if s.evtTS[i] == ts {
			return
		}
	}
	s.events++
	s.evtTS[s.evtNext] = ts
	s.evtNext = (s.evtNext + 1) % len(s.evtTS)
	if s.evtN < len(s.evtTS) {
		s.evtN++
	}
}

// countPT counts a media packet of payload type pt in the small PT table.
func (s *stream) countPT(pt uint8) {
	lo := 0
	for i := range s.pts {
		sl := &s.pts[i]
		if sl.n > 0 && sl.pt == pt {
			sl.n++
			return
		}
		if sl.n < s.pts[lo].n {
			lo = i
		}
	}
	// New payload type: take a free slot or replace the least used one.
	s.pts[lo] = ptSlot{pt: pt, n: 1}
}

// jitter feeds the RFC 3550 A.8 interarrival jitter estimators with one media
// packet (not duplicate, not telephone-event).
func (s *stream) jitter(ts uint32, nowNs int64) {
	if !s.jInit {
		s.jInit = true
		s.jFirstNs, s.jLastNs = nowNs, nowNs
		s.lastTS = ts
		return
	}
	s.tsExt += int64(int32(ts - s.lastTS))
	s.lastTS = ts
	s.jLastNs = nowNs
	arr := float64(nowNs-s.jFirstNs) * 1e-9
	ext := float64(s.tsExt)
	s.jN++
	for i := range s.transit {
		tr := arr - ext*invRate[i]
		d := math.Abs(tr - s.transit[i])
		s.transit[i] = tr
		if d > jitterResetSec {
			continue
		}
		j := s.jit[i] + (d-s.jit[i])*(1.0/16)
		s.jit[i] = j
		s.jSum[i] += j
		if j > s.jMax[i] {
			s.jMax[i] = j
		}
	}
}

// snapRates are the clock rates an estimated rate is snapped to.
var snapRates = [...]int{8000, 16000, 32000, 44100, 48000, 90000}

// estimateRate returns the candidateRates index for a stream whose clock rate
// is unknown: timestamp progression over arrival time progression, snapped
// (on a log scale) to the nearest of snapRates. Defaults to 8000.
func (s *stream) estimateRate() int {
	dur := float64(s.jLastNs-s.jFirstNs) * 1e-9
	if dur <= 0 || s.tsExt <= 0 {
		return 0
	}
	est := float64(s.tsExt) / dur
	best, bestD := snapRates[0], math.Inf(1)
	for _, r := range snapRates {
		if d := math.Abs(math.Log(est / float64(r))); d < bestD {
			best, bestD = r, d
		}
	}
	return rateIndex(best)
}
