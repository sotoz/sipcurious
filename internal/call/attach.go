package call

import (
	"net/netip"
	"slices"
	"time"

	"github.com/sotoz/sipcurious/internal/rtp"
)

// AttachSlack widens a call's media window on both sides: RTP starts a little
// before the 200 OK is captured (early media, media before ACK) and a little
// before/after the BYE.
const AttachSlack = 5 * time.Second

// Match quality, best last.
const (
	matchSrc  = 1 // stream source equals an announced endpoint
	matchDst  = 2 // stream destination equals an announced endpoint
	matchBoth = 3 // source and destination are the two announced endpoints
)

// ref says that endpoint ep is announced in call by the given side and that
// the other side announced other.
type ref struct {
	call   int32
	callee bool
	other  netip.AddrPort
}

type window struct {
	from, to time.Time
	open     bool // no BYE/failure captured: the media may run past the last message
}

func (w window) width() time.Duration {
	if w.open {
		return 1 << 62
	}
	return w.to.Sub(w.from)
}

// Attach correlates RTP streams to calls and fills Call.Streams. The input
// slice is not modified: Call.Streams receives copies with CallID and Leg set,
// ordered by Start (ties keep their order in streams). Call.Streams of calls
// that match nothing are set to nil.
//
// A stream matches a call when its source or destination is an RTP endpoint
// announced in the call's SDP (Call.Media, any time) and its time span overlaps
// the call's media window: from the first SDP description minus AttachSlack to
// the last message of the call plus AttachSlack (unbounded for calls that were
// answered without a BYE being captured). Quality of a match, best first:
// both ends are the two announced endpoints (either direction); the
// destination is an announced endpoint (the receiving side told us where it
// listens; the source may be NATed or asymmetric); the source is an announced
// endpoint. A stream is attached to at most one call: the best match quality
// wins, then the largest time overlap, then the narrowest window, then the
// window starting closest to the stream, then the earliest call. This keeps
// consecutive calls that reuse the same gateway ports apart.
//
// Leg is "caller->callee" when the stream flows from the caller's media endpoint
// toward the callee's, else "callee->caller".
func Attach(calls []Call, streams []rtp.Stream) {
	for i := range calls {
		calls[i].Streams = nil
	}
	if len(calls) == 0 || len(streams) == 0 {
		return
	}

	index := make(map[netip.AddrPort][]ref)
	wins := make([]window, len(calls))
	for i := range calls {
		c := &calls[i]
		if len(c.Media) == 0 {
			continue
		}
		first := c.Media[0].Time
		for _, m := range c.Media {
			if m.Time.Before(first) {
				first = m.Time
			}
			add := func(ep, other netip.AddrPort, callee bool) {
				if !ep.IsValid() {
					return
				}
				for _, r := range index[ep] {
					if r.call == int32(i) && r.callee == callee && r.other == other {
						return
					}
				}
				index[ep] = append(index[ep], ref{int32(i), callee, other})
			}
			add(m.Caller, m.Callee, false)
			add(m.Callee, m.Caller, true)
		}
		w := window{from: first.Add(-AttachSlack), to: c.End.Add(AttachSlack)}
		w.open = c.State == StateAnswered || c.State == StateInSetup
		wins[i] = w
	}
	if len(index) == 0 {
		return
	}

	attached := make([][]int32, len(calls)) // stream indexes per call
	legs := make([]string, len(streams))
	var cands []candidate
	for si := range streams {
		s := &streams[si]
		cands = cands[:0]
		consider := func(r ref, level int, srcSide bool) {
			w := wins[r.call]
			ov, ok := overlap(s, w)
			if !ok {
				return
			}
			// Which side's endpoint was matched, and in which direction the
			// stream flows relative to it.
			toCallee := r.callee != srcSide // dst==callee or src==caller
			leg := "caller->callee"
			if !toCallee {
				leg = "callee->caller"
			}
			cand := candidate{level: level, overlap: ov, width: w.width(), dist: absDur(s.Start.Sub(w.from)), call: r.call, leg: leg}
			for k := range cands {
				if cands[k].call == r.call {
					if better(cand, cands[k]) {
						cands[k] = cand
					}
					return
				}
			}
			cands = append(cands, cand)
		}
		for _, r := range index[s.Dst] {
			level := matchDst
			if r.other == s.Src {
				level = matchBoth
			}
			consider(r, level, false)
		}
		for _, r := range index[s.Src] {
			level := matchSrc
			if r.other == s.Dst {
				level = matchBoth
			}
			consider(r, level, true)
		}
		if len(cands) == 0 {
			continue
		}
		win := cands[0]
		for _, c := range cands[1:] {
			if better(c, win) {
				win = c
			}
		}
		attached[win.call] = append(attached[win.call], int32(si))
		legs[si] = win.leg
	}

	for i, list := range attached {
		if len(list) == 0 {
			continue
		}
		out := make([]rtp.Stream, len(list))
		for n, si := range list {
			out[n] = streams[si]
			out[n].CallID = calls[i].CallID
			out[n].Leg = legs[si]
		}
		slices.SortStableFunc(out, func(a, b rtp.Stream) int { return a.Start.Compare(b.Start) })
		calls[i].Streams = out
	}
}

// candidate is one call a stream could belong to.
type candidate struct {
	level   int           // matchSrc, matchDst or matchBoth
	overlap time.Duration // time the stream overlaps the call's media window
	width   time.Duration // width of that window
	dist    time.Duration // |stream start - window start|
	call    int32
	leg     string
}

// better reports whether a is a stronger match than b: higher match level,
// then longer overlap, narrower window, closer window start, earlier call.
func better(a, b candidate) bool {
	switch {
	case a.level != b.level:
		return a.level > b.level
	case a.overlap != b.overlap:
		return a.overlap > b.overlap
	case a.width != b.width:
		return a.width < b.width
	case a.dist != b.dist:
		return a.dist < b.dist
	}
	return a.call < b.call
}

// overlap returns how long stream s overlaps window w; ok is false if they are disjoint.
func overlap(s *rtp.Stream, w window) (time.Duration, bool) {
	lo := s.Start
	if w.from.After(lo) {
		lo = w.from
	}
	hi := s.End
	if !w.open && w.to.Before(hi) {
		hi = w.to
	}
	if hi.Before(lo) {
		return 0, false
	}
	return hi.Sub(lo), true
}

func absDur(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}
