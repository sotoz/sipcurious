package rtp

import (
	"cmp"
	"encoding/binary"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/sotoz/sipcurious/internal/capture"
)

// Tunables. They are constants (documented here, not hidden) so behaviour is
// reproducible.
const (
	// defaultMinPackets is the number of packets with plausible sequence
	// numbers a flow needs before it is reported as a stream. Four or fewer
	// RTP packets are indistinguishable from random UDP that happens to start
	// with 0x80..0xbf, so they are never reported (RFC 3550 A.1 uses 2; we
	// have no SDP to confirm the flow, hence 5).
	defaultMinPackets = 5
	// defaultMaxCandidates bounds the flows under probation: two generations
	// of at most half of it each (see Handler). Worst case memory is
	// MaxCandidates x ~0.7 KB = ~3 MB per file handler.
	defaultMaxCandidates = 4096
	// maxRTCPObs bounds the number of (SSRC, address, kind) RTCP summaries
	// kept. Observations beyond it are dropped (a legitimate capture has two
	// per stream).
	maxRTCPObs = 1 << 16
)

// Format is a payload type hint, typically taken from SDP rtpmap lines.
type Format struct {
	Name      string // encoding name, e.g. "opus", "telephone-event"
	ClockRate int    // RTP clock rate in Hz, 0 if unknown
}

// HandlerOptions configures NewHandler. The zero value is usable.
type HandlerOptions struct {
	// MinPackets is the number of plausibly continuous packets a flow needs
	// before it is reported (default 5).
	MinPackets int
	// MaxCandidates bounds the memory spent on flows that have not reached
	// MinPackets yet (default 4096). When it is exceeded the least recently
	// seen half is forgotten, so a capture full of random UDP stays bounded
	// while a real stream (at least one packet per few seconds) survives.
	MaxCandidates int
	// Formats is the initial payload type -> codec hint table, see SetFormats.
	Formats map[uint8]Format
}

// ckey is the compact comparable map key of a flow; hashing it avoids the
// netip.Addr zone pointers.
type ckey struct {
	src, dst     [16]byte
	sport, dport uint16
	ssrc         uint32
}

// fmtHint is the per-payload-type hint table entry.
type fmtHint struct {
	name  string
	rate  int
	event bool // telephone-event
	cn    bool // comfort noise
	set   bool
}

// Handler is the capture.Handler that detects RTP and RTCP on UDP and
// tracks streams. It is not safe for concurrent use (capture runs one
// goroutine per file). Create one per file with NewHandler.
//
// Detection state is bounded: flows under probation live in two generations
// of at most MaxCandidates/2 entries; when the young generation is full the
// old one is dropped and the young one becomes the old one (a flow that
// keeps sending is promoted back to the young generation each time it is
// seen). Validated streams are kept for the whole file: one per
// (src, dst, SSRC), at about 0.7 KB each.
type Handler struct {
	file    string
	minPkts int
	half    int
	fmts    [128]fmtHint

	streams  map[ckey]*stream
	young    map[ckey]*stream
	old      map[ckey]*stream
	free     []*stream
	order    []*stream // validated streams in promotion order
	rtcp     map[uint32][]*rtcpObs
	rtcpObsN int
}

// NewHandler returns the factory of RTP/RTCP handlers, one per capture file,
// to be registered after the SIP handler: it consumes UDP datagrams that look
// like RTP or RTCP and returns false for everything else.
//
// A datagram is RTP-like when it has version 2, a plausible payload type
// (RFC 3551 static 0-18 and 25-34, dynamic 96-127), a consistent CSRC list
// and header extension, and a second byte outside 192..223 (RTCP, RFC 5761).
// STUN (first byte 0..3) and DTLS (20..63) cannot pass version 2 and are
// therefore never consumed. A flow keyed by (src, dst, SSRC) is reported once
// it has sent MinPackets (default 5) packets with plausibly continuous
// sequence numbers (each step forward at most 100). A change of SSRC on the
// same 4-tuple starts a new stream.
func NewHandler(opt HandlerOptions) capture.Factory {
	return func(file string) capture.Handler {
		return newHandler(file, opt)
	}
}

func newHandler(file string, opt HandlerOptions) *Handler {
	h := &Handler{file: file, minPkts: opt.MinPackets}
	if h.minPkts <= 0 {
		h.minPkts = defaultMinPackets
	}
	maxCand := opt.MaxCandidates
	if maxCand <= 0 {
		maxCand = defaultMaxCandidates
	}
	h.half = max(maxCand/2, 1)
	h.streams = make(map[ckey]*stream)
	h.young = make(map[ckey]*stream)
	h.old = make(map[ckey]*stream)
	h.rtcp = make(map[uint32][]*rtcpObs)
	h.SetFormats(opt.Formats)
	return h
}

// SetFormats replaces the payload type hint table (PT -> codec name and
// clock rate, typically collected from the SDP of the calls in the capture).
// Hints are global to the handler, not per call: pass only the mappings that
// are unambiguous in the capture. They are consulted when results are read
// (Streams): codec name, the jitter clock rate, and which payload types are
// telephone-event or comfort noise when choosing the stream's payload type.
// A telephone-event hint set BEFORE the packets are handled additionally
// classifies those packets exactly (no jitter or media accounting); without
// it the handler infers telephone-event packets (see classify).
func (h *Handler) SetFormats(f map[uint8]Format) {
	h.fmts = [128]fmtHint{}
	for pt, v := range f {
		if pt > 127 {
			continue
		}
		h.fmts[pt] = fmtHint{
			name:  v.Name,
			rate:  v.ClockRate,
			event: strings.EqualFold(v.Name, "telephone-event"),
			cn:    strings.EqualFold(v.Name, "CN"),
			set:   true,
		}
	}
}

func makeKey(p *capture.Packet, ssrc uint32) ckey {
	return ckey{src: p.Src.As16(), dst: p.Dst.As16(), sport: p.SrcPort, dport: p.DstPort, ssrc: ssrc}
}

// Handle implements capture.Handler. It consumes UDP datagrams that are RTP
// or RTCP by the rules described at NewHandler. Datagrams of flows that have
// not (yet) proven to be streams are consumed too: RTP-looking datagrams are
// never anything else this tool understands.
func (h *Handler) Handle(p *capture.Packet) bool {
	if p.Transport != "UDP" {
		return false
	}
	b := p.Payload
	if len(b) < 8 || b[0]>>6 != 2 {
		return false
	}
	if b[1]-192 < 32 { // 192..223
		if !IsRTCP(b) {
			return false
		}
		h.handleRTCP(p)
		return true
	}
	hd, ok := ParseHeader(b)
	if !ok || !plausiblePT(hd.PayloadType) {
		return false
	}
	k := makeKey(p, hd.SSRC)
	s := h.streams[k]
	if s == nil {
		s = h.candidate(k, p)
	}
	s.add(h, &hd, p)
	if !s.reported && s.valid >= h.minPkts {
		h.promote(k, s)
	}
	return true
}

// candidate finds or creates the probation state of flow k.
func (h *Handler) candidate(k ckey, p *capture.Packet) *stream {
	if s := h.young[k]; s != nil {
		return s
	}
	if s := h.old[k]; s != nil {
		delete(h.old, k)
		h.young[k] = s
		return s
	}
	if len(h.young) >= h.half {
		// Drop the old generation; recycle its states.
		for _, s := range h.old {
			if len(h.free) < 2*h.half {
				h.free = append(h.free, s)
			}
		}
		clear(h.old)
		h.old, h.young = h.young, h.old
	}
	var s *stream
	if n := len(h.free); n > 0 {
		s = h.free[n-1]
		h.free = h.free[:n-1]
		*s = stream{}
	} else {
		s = new(stream)
	}
	s.key = Key{
		Src:  netip.AddrPortFrom(p.Src, p.SrcPort),
		Dst:  netip.AddrPortFrom(p.Dst, p.DstPort),
		SSRC: binary.BigEndian.Uint32(p.Payload[8:]),
	}
	s.firstIndex = p.Index
	h.young[k] = s
	return s
}

// promote moves a validated candidate into the reported streams.
func (h *Handler) promote(k ckey, s *stream) {
	delete(h.young, k)
	delete(h.old, k)
	s.reported = true
	h.streams[k] = s
	h.order = append(h.order, s)
}

// Streams returns the validated streams seen so far, ordered by start time
// (then first packet number, then SSRC). It does not change the handler; it
// can be called again after more packets. RFactor and MOS are computed here
// with [Quality] from LossPct, JitterMean and Codec; they stay 0 for a
// stream that carried telephone-event packets only.
//
// Definitions:
//
//   - Packets counts every RTP packet of the stream including duplicates and
//     telephone-event packets; Bytes is the payload (header, CSRC list,
//     extension and padding excluded).
//   - Expected, Lost, Duplicates, Reordered follow RFC 3550 appendix A.3 on
//     the extended sequence numbers. A sender restart (two in-sequence
//     packets after a jump of 100 to 65436 positions backwards or more than
//     3000 forward) closes the current sequence segment and opens a new one
//     (the jump itself is neither loss nor expected); an isolated packet
//     with a wild sequence number counts as one expected and one received
//     packet. DTX / comfort noise gaps do not move sequence numbers, so they
//     are not loss; they show in MaxGap.
//   - JitterMean/JitterMax are the RFC 3550 A.8 interarrival jitter in time,
//     using the clock rate of PayloadType (SetFormats hint, else the static
//     table, G722 always 8000 as RFC 3551 prescribes, else estimated from the
//     timestamp and arrival progression and snapped to the nearest of 8000,
//     16000, 32000, 44100, 48000, 90000). Telephone-event packets,
//     duplicates and stray packets are excluded; a transit time step above
//     2 s (sender re-based its timestamps) re-baselines instead of counting.
//   - PayloadType is the most frequent payload type that is not
//     telephone-event or comfort noise (those only when nothing else exists).
func (h *Handler) Streams() []Stream {
	out := make([]Stream, 0, len(h.order))
	for _, s := range h.order {
		out = append(out, h.snapshot(s))
	}
	slices.SortStableFunc(out, func(a, b Stream) int {
		if c := a.Start.Compare(b.Start); c != 0 {
			return c
		}
		if c := cmp.Compare(a.FirstIndex, b.FirstIndex); c != 0 {
			return c
		}
		return cmp.Compare(a.SSRC, b.SSRC)
	})
	return out
}

// dominantPT picks the stream's payload type and reports whether it is a
// media type (false: only telephone-event or comfort noise was seen).
func (h *Handler) dominantPT(s *stream) (pt uint8, media bool) {
	best, bestRank := ptSlot{}, -1
	for _, sl := range s.pts {
		if sl.n == 0 {
			continue
		}
		rank := 2
		if f := h.fmts[sl.pt&127]; f.event || (s.hasEvt && sl.pt == s.evtPT) {
			rank = 0
		} else if f.cn || sl.pt == payloadTypeCN {
			rank = 1
		}
		if rank > bestRank || (rank == bestRank && (sl.n > best.n || (sl.n == best.n && sl.pt < best.pt))) {
			best, bestRank = sl, rank
		}
	}
	if bestRank < 0 && s.hasEvt {
		return s.evtPT, false
	}
	return best.pt, bestRank == 2
}

// snapshot converts the mutable stream state into the public summary.
func (h *Handler) snapshot(s *stream) Stream {
	st := Stream{
		Key:        s.key,
		File:       h.file,
		FirstIndex: s.firstIndex,
		Start:      time.Unix(0, s.startNs).UTC(),
		End:        time.Unix(0, s.endNs).UTC(),
		Packets:    s.packets,
		Bytes:      s.bytes,
		Duplicates: s.dups,
		Reordered:  s.reorders,
		MaxGap:     time.Duration(s.maxGap),
		DTMFEvents: s.events,
	}
	st.Expected = s.expAcc + uint64(s.maxExt-s.baseExt) + 1 + s.stray
	st.Lost = int64(st.Expected) - int64(st.Packets)
	if st.Lost > 0 {
		st.LossPct = 100 * float64(st.Lost) / float64(st.Expected)
	}

	pt, media := h.dominantPT(s)
	st.PayloadType = pt
	hint := h.fmts[pt&127]
	st.Codec, st.ClockRate = CodecName(pt)
	if hint.name != "" {
		st.Codec = hint.name
	}
	if hint.rate > 0 {
		st.ClockRate = hint.rate
	}
	if strings.EqualFold(st.Codec, "G722") {
		st.ClockRate = 8000 // RFC 3551 4.5.2: the RTP clock of G.722 is 8 kHz
	}
	ri := rateIndex(st.ClockRate)
	if ri < 0 {
		ri = s.estimateRate()
		st.ClockRate = candidateRates[ri]
	}
	if s.jN > 0 {
		st.JitterMean = secs(s.jSum[ri] / float64(s.jN))
		st.JitterMax = secs(s.jMax[ri])
	}
	if media {
		st.RFactor, st.MOS = Quality(st.Codec, st.LossPct, st.JitterMean)
	}

	for _, o := range h.rtcp[s.key.SSRC] {
		switch {
		case o.sender && o.from == s.key.Src.Addr():
			st.RTCP.Reports += o.reports
		case !o.sender && o.from == s.key.Dst.Addr():
			st.RTCP.Reports += o.reports
			st.RTCP.MaxFractionLost = max(st.RTCP.MaxFractionLost, o.maxFrac)
			st.RTCP.MaxJitter = max(st.RTCP.MaxJitter, secs(float64(o.maxJit)/float64(st.ClockRate)))
			st.RTCP.PacketsLost = o.lastLost
		}
	}
	return st
}

// secs converts seconds to a Duration without overflow for sane values.
func secs(f float64) time.Duration { return time.Duration(f * float64(time.Second)) }
