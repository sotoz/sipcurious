package stats

import (
	"cmp"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/sotoz/sipcurious/internal/call"
	"github.com/sotoz/sipcurious/internal/rtp"
	"github.com/sotoz/sipcurious/internal/trace"
)

const (
	topN      = 10 // length of the "top" lists
	worstN    = 5  // length of the worst-stream lists
	maxStatus = 700
)

// Compute derives the Summary of in. It does not modify the input and is
// safe for empty input (every list is empty, every number zero).
func Compute(in Input) Summary {
	s := Summary{
		Files:   append([]string{}, in.Files...),
		Packets: in.Packets,
		Skipped: in.Skipped,
	}
	span := span{}
	computeSIP(&s.SIP, in.Messages, &span)
	computeCalls(&s.Calls, in.Calls, &s.SIP)
	computeRTP(&s.RTP, in.Streams, in.Calls, &span)
	s.Start, s.End = span.first, span.last
	if !s.Start.IsZero() {
		s.Duration = s.End.Sub(s.Start)
	}
	return s
}

// span tracks the earliest and latest timestamp.
type span struct{ first, last time.Time }

func (p *span) add(t time.Time) {
	if t.IsZero() {
		return
	}
	if p.first.IsZero() || t.Before(p.first) {
		p.first = t
	}
	if t.After(p.last) {
		p.last = t
	}
}

type hostCount struct{ sent, recv int }

func computeSIP(out *SIPStats, msgs []trace.Message, sp *span) {
	out.Messages = len(msgs)
	var (
		methods    = map[string]*int{}
		transports = map[string]*int{}
		hosts      = map[netip.Addr]*hostCount{}
		endpoints  = map[netip.AddrPort]struct{}{}
		codes      [maxStatus]int
		reasons    [maxStatus]string

		lastMethod, lastTransport string
		lastMethodN, lastTransN   *int
		lastSrc, lastDst          netip.Addr
		lastSrcH, lastDstH        *hostCount
		lastSrcEP, lastDstEP      netip.AddrPort
	)
	host := func(a netip.Addr) *hostCount {
		h := hosts[a]
		if h == nil {
			h = new(hostCount)
			hosts[a] = h
		}
		return h
	}
	for i := range msgs {
		m := &msgs[i]
		sp.add(m.Time)
		if m.IsRequest {
			out.Requests++
			if lastMethodN == nil || m.Method != lastMethod {
				n := methods[m.Method]
				if n == nil {
					n = new(int)
					methods[strings.Clone(m.Method)] = n
				}
				lastMethod, lastMethodN = m.Method, n
			}
			*lastMethodN++
		} else {
			out.Responses++
			if c := m.StatusCode; c >= 100 && c < maxStatus {
				if codes[c] == 0 {
					reasons[c] = strings.Clone(m.Reason)
				}
				codes[c]++
			}
		}
		if lastTransN == nil || m.Transport != lastTransport {
			n := transports[m.Transport]
			if n == nil {
				n = new(int)
				transports[strings.Clone(m.Transport)] = n
			}
			lastTransport, lastTransN = m.Transport, n
		}
		*lastTransN++

		if lastSrcH == nil || m.Src != lastSrc {
			lastSrc, lastSrcH = m.Src, host(m.Src)
		}
		lastSrcH.sent++
		if lastDstH == nil || m.Dst != lastDst {
			lastDst, lastDstH = m.Dst, host(m.Dst)
		}
		lastDstH.recv++
		if sa := m.SrcAddr(); sa != lastSrcEP {
			lastSrcEP = sa
			endpoints[sa] = struct{}{}
		}
		if da := m.DstAddr(); da != lastDstEP {
			lastDstEP = da
			endpoints[da] = struct{}{}
		}
	}

	out.Methods = sortedCounts(methods)
	out.Transports = sortedCounts(transports)
	out.Hosts, out.Endpoints = len(hosts), len(endpoints)

	out.Statuses = []StatusCount{}
	out.Classes = make([]Count, 6)
	for c := range out.Classes {
		out.Classes[c].Key = string(rune('1'+c)) + "xx"
	}
	for c := 100; c < maxStatus; c++ {
		if codes[c] == 0 {
			continue
		}
		out.Statuses = append(out.Statuses, StatusCount{Code: c, Reason: reasons[c], Count: codes[c]})
		out.Classes[c/100-1].Count += codes[c]
	}

	type hostRow struct {
		addr netip.Addr
		n    int
	}
	top := func(count func(*hostCount) int) []Count {
		rows := make([]hostRow, 0, len(hosts))
		for a, h := range hosts {
			if n := count(h); n > 0 {
				rows = append(rows, hostRow{a, n})
			}
		}
		slices.SortFunc(rows, func(x, y hostRow) int {
			return cmp.Or(cmp.Compare(y.n, x.n), x.addr.Compare(y.addr))
		})
		if len(rows) > topN {
			rows = rows[:topN]
		}
		res := make([]Count, len(rows))
		for i, r := range rows {
			res[i] = Count{Key: r.addr.String(), Count: r.n}
		}
		return res
	}
	out.TopSources = top(func(h *hostCount) int { return h.sent })
	out.TopDestinations = top(func(h *hostCount) int { return h.recv })
}

// sortedCounts turns a counter map into a slice ordered by count descending,
// then key.
func sortedCounts(m map[string]*int) []Count {
	res := make([]Count, 0, len(m))
	for k, n := range m {
		res = append(res, Count{Key: k, Count: *n})
	}
	sortCounts(res)
	return res
}

func sortCounts(c []Count) {
	slices.SortFunc(c, func(a, b Count) int {
		return cmp.Or(cmp.Compare(b.Count, a.Count), cmp.Compare(a.Key, b.Key))
	})
}

func topCounts(m map[string]int, n int) []Count {
	res := make([]Count, 0, len(m))
	for k, v := range m {
		res = append(res, Count{Key: k, Count: v})
	}
	sortCounts(res)
	if len(res) > n {
		res = res[:n]
	}
	return res
}

type failKey struct {
	kind  call.Kind
	state call.State
	code  int
}

type failGroup struct {
	n      int
	sample *call.Call
}

type numberCount struct{ calls, answered int }

func isAnswered(c *call.Call) bool {
	return c.State == call.StateAnswered || c.State == call.StateCompleted
}

// userCaused reports the final responses that mean "the called party said
// no" rather than "the network failed".
func userCaused(code int) bool {
	switch code {
	case 486, 480, 404, 603:
		return true
	}
	return false
}

// isFailure reports the states that make it into the failure histogram.
func isFailure(s call.State) bool {
	return s == call.StateFailed || s == call.StateNoResponse || s == call.StateInSetup
}

var kindRank = map[call.Kind]int{
	call.KindCall: 0, call.KindRegistration: 1, call.KindSubscription: 2,
	call.KindMessage: 3, call.KindOptions: 4, call.KindOther: 5,
}

func computeCalls(out *CallStats, calls []call.Call, sip *SIPStats) {
	out.Total = len(calls)
	var (
		kinds   = map[string]int{}
		states  = map[[2]string]int{}
		fails   = map[failKey]*failGroup{}
		uas     = map[string]int{}
		calling = map[string]*numberCount{}
		called  = map[string]*numberCount{}
		codecs  = map[string]int{}

		attemptStarts []int64
		media         []interval
		pdd, setup    []time.Duration
		ring, talk    []time.Duration
		talkSum       time.Duration
	)
	for i := range calls {
		c := &calls[i]
		sip.Retransmissions += c.Retransmissions
		kinds[string(c.Kind)]++
		states[[2]string{string(c.Kind), string(c.State)}]++
		for _, ua := range c.UserAgents {
			uas[ua]++
		}
		if isFailure(c.State) {
			k := failKey{c.Kind, c.State, c.FinalCode}
			g := fails[k]
			if g == nil {
				g = &failGroup{sample: c}
				fails[k] = g
			} else if c.Start.Before(g.sample.Start) {
				g.sample = c
			}
			g.n++
		}
		if c.Kind != call.KindCall {
			continue
		}
		answered := isAnswered(c)
		if answered && !c.Answered.IsZero() {
			media = append(media, interval{c.Answered.UnixNano(), endOf(c).UnixNano()})
		}
		if c.State == call.StateCompleted && !c.Answered.IsZero() {
			out.Completed++
			talk = append(talk, c.TalkTime)
			talkSum += c.TalkTime
		}
		if answered && len(c.Streams) == 0 {
			out.NoMedia++
		}
		if answered {
			if name := negotiated(c); name != "" {
				codecs[name]++
			}
		}
		if !c.Caller.IsValid() {
			continue // captured mid-dialog: not an attempt
		}
		out.Attempts++
		attemptStarts = append(attemptStarts, c.Start.UnixNano())
		bump(calling, c.FromUser, answered)
		bump(called, c.ToUser, answered)
		if answered {
			out.Answered++
			if c.PDD > 0 {
				pdd = append(pdd, c.PDD)
			}
			if c.SetupTime > 0 {
				setup = append(setup, c.SetupTime)
			}
			if c.RingTime > 0 {
				ring = append(ring, c.RingTime)
			}
		} else if c.State == call.StateFailed && userCaused(c.FinalCode) {
			out.UserCaused++
		}
	}

	out.Kinds = topCounts(kinds, len(kinds))
	out.States = make([]KindState, 0, len(states))
	for k, n := range states {
		out.States = append(out.States, KindState{Kind: call.Kind(k[0]), State: call.State(k[1]), Count: n})
	}
	slices.SortFunc(out.States, func(a, b KindState) int {
		return cmp.Or(
			cmp.Compare(rankOf(a.Kind), rankOf(b.Kind)), cmp.Compare(a.Kind, b.Kind),
			cmp.Compare(b.Count, a.Count), cmp.Compare(a.State, b.State))
	})

	out.ASR = percent(out.Answered, out.Attempts)
	out.AdjustedASR = percent(out.Answered, out.Attempts-out.UserCaused)
	if out.Completed > 0 {
		out.ACD = talkSum / time.Duration(out.Completed)
	}
	out.PeakConcurrent = peakConcurrent(media)
	out.PeakAttemptRate = peakRate(attemptStarts, time.Second)
	out.PDD, out.Setup, out.Ring, out.Talk = dist(pdd), dist(setup), dist(ring), dist(talk)

	out.FailureGroups = len(fails)
	out.Failures = make([]Failure, 0, len(fails))
	for k, g := range fails {
		out.Failures = append(out.Failures, Failure{
			Kind: k.kind, State: k.state, Code: k.code, Reason: g.sample.FinalReason,
			Count: g.n, SampleCallID: g.sample.CallID,
		})
	}
	slices.SortFunc(out.Failures, func(a, b Failure) int {
		return cmp.Or(cmp.Compare(b.Count, a.Count),
			cmp.Compare(rankOf(a.Kind), rankOf(b.Kind)), cmp.Compare(a.Kind, b.Kind),
			cmp.Compare(a.State, b.State), cmp.Compare(a.Code, b.Code))
	})
	if len(out.Failures) > topN {
		out.Failures = out.Failures[:topN]
	}

	out.UserAgents = topCounts(uas, topN)
	out.TopCalling = topNumbers(calling)
	out.TopCalled = topNumbers(called)
	out.NegotiatedCodecs = topCounts(codecs, len(codecs))
}

func rankOf(k call.Kind) int {
	if r, ok := kindRank[k]; ok {
		return r
	}
	return len(kindRank)
}

func bump(m map[string]*numberCount, number string, answered bool) {
	if number == "" {
		return
	}
	n := m[number]
	if n == nil {
		n = new(numberCount)
		m[strings.Clone(number)] = n
	}
	n.calls++
	if answered {
		n.answered++
	}
}

func topNumbers(m map[string]*numberCount) []Number {
	res := make([]Number, 0, len(m))
	for k, n := range m {
		res = append(res, Number{Number: k, Calls: n.calls, Answered: n.answered})
	}
	slices.SortFunc(res, func(a, b Number) int {
		return cmp.Or(cmp.Compare(b.Calls, a.Calls), cmp.Compare(a.Number, b.Number))
	})
	if len(res) > topN {
		res = res[:topN]
	}
	return res
}

// negotiated returns the first real codec of the first enabled audio media.
func negotiated(c *call.Call) string {
	for i := range c.Media {
		m := &c.Media[i]
		if m.Disabled || (m.Type != "" && m.Type != "audio") {
			continue
		}
		for _, name := range m.Codecs {
			switch strings.ToLower(name) {
			case "telephone-event", "cn", "":
				continue
			}
			return name
		}
	}
	return ""
}

// endOf is the end of the media phase of an answered call: its first BYE or,
// when none was captured, its last message.
func endOf(c *call.Call) time.Time {
	if !c.Ended.IsZero() && !c.Ended.Before(c.Answered) {
		return c.Ended
	}
	if c.End.Before(c.Answered) {
		return c.Answered
	}
	return c.End
}

func percent(n, d int) float64 {
	if d <= 0 {
		return 0
	}
	return 100 * float64(n) / float64(d)
}

// interval is [start, end) in Unix nanoseconds.
type interval struct{ start, end int64 }

// peakConcurrent is the maximum overlap of half-open intervals and the first
// instant it was reached. Zero-length intervals last one nanosecond.
func peakConcurrent(iv []interval) Peak {
	if len(iv) == 0 {
		return Peak{}
	}
	starts := make([]int64, len(iv))
	ends := make([]int64, len(iv))
	for i, v := range iv {
		if v.end <= v.start {
			v.end = v.start + 1
		}
		starts[i], ends[i] = v.start, v.end
	}
	slices.Sort(starts)
	slices.Sort(ends)
	var best, cur int
	var at int64
	j := 0
	for _, s := range starts {
		// Only intervals that started before s can have ended by s, so j < len(ends).
		for ends[j] <= s {
			j++
			cur--
		}
		cur++
		if cur > best {
			best, at = cur, s
		}
	}
	return Peak{Value: best, At: time.Unix(0, at).UTC()}
}

// peakRate is the most events in any window [t, t+w) starting at an event,
// and the start of the first such window.
func peakRate(ts []int64, w time.Duration) Peak {
	if len(ts) == 0 {
		return Peak{}
	}
	slices.Sort(ts)
	var best int
	var at int64
	j := 0
	for i, t := range ts {
		if j < i {
			j = i
		}
		for j < len(ts) && ts[j]-t < int64(w) {
			j++
		}
		if n := j - i; n > best {
			best, at = n, t
		}
	}
	return Peak{Value: best, At: time.Unix(0, at).UTC()}
}

// rank returns the 0-based index of the p-th percentile (nearest rank) in a
// sorted slice of n > 0 values: ceil(p*n/100) - 1.
func rank(n, p int) int {
	r := (p*n + 99) / 100
	if r < 1 {
		r = 1
	}
	if r > n {
		r = n
	}
	return r - 1
}

// dist sorts v (in place) and summarises it.
func dist(v []time.Duration) Dist {
	if len(v) == 0 {
		return Dist{}
	}
	slices.Sort(v)
	var sum time.Duration
	for _, d := range v {
		sum += d
	}
	n := len(v)
	return Dist{
		N: n, Min: v[0], Mean: sum / time.Duration(n),
		P50: v[rank(n, 50)], P90: v[rank(n, 90)], P95: v[rank(n, 95)], P99: v[rank(n, 99)],
		Max: v[n-1],
	}
}

type callLeg struct{ id, leg string }

func computeRTP(out *RTPStats, streams []rtp.Stream, calls []call.Call, sp *span) {
	out.Streams = len(streams)
	out.WorstLoss, out.WorstJitter = []StreamRef{}, []StreamRef{}
	codecs := map[string]int{}
	var mos []float64
	var mosSum float64
	var lossy, jittery []int
	for i := range streams {
		st := &streams[i]
		sp.add(st.Start)
		sp.add(st.End)
		out.Packets += st.Packets
		name := st.Codec
		if name == "" {
			name = "unknown"
		}
		codecs[name]++
		if st.MOS > 0 {
			mos = append(mos, st.MOS)
			mosSum += st.MOS
		}
		if st.LossPct > 0 {
			lossy = append(lossy, i)
		}
		if st.JitterMean > 0 {
			jittery = append(jittery, i)
		}
	}
	out.Codecs = topCounts(codecs, len(codecs))
	if n := len(mos); n > 0 {
		slices.Sort(mos)
		out.MOSStreams = n
		out.MOSMin = mos[0]
		out.MOSP5 = mos[rank(n, 5)]
		out.MOSMean = mosSum / float64(n)
	}
	if len(lossy) == 0 && len(jittery) == 0 {
		return
	}
	// Streams not yet tagged by call.Attach may still be attached to a call
	// as copies: look them up by key.
	var byKey map[rtp.Key]callLeg
	for i := range calls {
		for j := range calls[i].Streams {
			st := &calls[i].Streams[j]
			if byKey == nil {
				byKey = map[rtp.Key]callLeg{}
			}
			byKey[st.Key] = callLeg{calls[i].CallID, st.Leg}
		}
	}
	worst := func(idx []int, metric func(*rtp.Stream) float64) []StreamRef {
		less := func(a, b int) int {
			x, y := &streams[a], &streams[b]
			return cmp.Or(cmp.Compare(metric(y), metric(x)), cmp.Compare(y.Packets, x.Packets),
				x.Start.Compare(y.Start), cmp.Compare(x.SSRC, y.SSRC),
				x.Src.Compare(y.Src), x.Dst.Compare(y.Dst))
		}
		slices.SortFunc(idx, less)
		if len(idx) > worstN {
			idx = idx[:worstN]
		}
		res := make([]StreamRef, len(idx))
		for i, k := range idx {
			st := &streams[k]
			ref := StreamRef{
				CallID: st.CallID, Leg: st.Leg, Src: st.Src.String(), Dst: st.Dst.String(), SSRC: st.SSRC,
				Codec: st.Codec, Packets: st.Packets, LossPct: st.LossPct,
				JitterMean: st.JitterMean, JitterMax: st.JitterMax, MOS: st.MOS,
			}
			if ref.CallID == "" {
				if cl, ok := byKey[st.Key]; ok {
					ref.CallID, ref.Leg = cl.id, cl.leg
				}
			}
			res[i] = ref
		}
		return res
	}
	out.WorstLoss = worst(lossy, func(s *rtp.Stream) float64 { return s.LossPct })
	out.WorstJitter = worst(jittery, func(s *rtp.Stream) float64 { return float64(s.JitterMean) })
}
