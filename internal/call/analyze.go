package call

import (
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/sotoz/sipcurious/internal/trace"
)

const (
	maxEndpoints = 64
	maxUAs       = 16
	linearKeys   = 24 // retransmission detection scans linearly below this many messages
	linearTx     = 16 // transaction lookup scans linearly below this many transactions
)

// tx is one transaction of the call's primary method (see Build).
type tx struct {
	cseq    int
	ftag    string // From tag: both ends of a dialog use independent CSeq spaces
	hasReq  bool
	initial bool // INVITE without To tag (always true for other methods)
	anyResp bool
	req     int32 // index of the first request, -1 if none captured
	ok      int32 // index of the first 2xx
	fail    int32 // index of the last response >= 300
	ring    int32 // index of the first 101-199 response
}

type txKey struct {
	cseq int
	ftag string
}

// msgKey identifies a message for retransmission detection.
type msgKey struct {
	code     int
	method   string
	cseq     string
	branch   string
	toTag    string
	rseq     string
	src, dst netip.AddrPort
}

// worker holds the scratch memory reused between calls. One per goroutine.
type worker struct {
	txs    []tx
	txMap  map[txKey]int32
	keys   []msgKey
	keyMap map[msgKey]struct{}
	eps    []netip.AddrPort
	uas    []string
	tags   []string
	dups   []int // CSeq of INVITE transactions whose 2xx was retransmitted
	media  mediaBuilder
}

func newWorker() *worker { return &worker{} }

func (w *worker) reset() {
	w.txs = w.txs[:0]
	if len(w.txMap) > 0 {
		clear(w.txMap)
	}
	w.keys = w.keys[:0]
	if len(w.keyMap) > 0 {
		clear(w.keyMap)
	}
	w.eps = w.eps[:0]
	w.uas = w.uas[:0]
	w.dups = w.dups[:0]
}

func (w *worker) addEndpoint(ep netip.AddrPort) {
	if len(w.eps) >= maxEndpoints || slices.Contains(w.eps, ep) {
		return
	}
	w.eps = append(w.eps, ep)
}

func (w *worker) addUA(ua string) {
	if len(w.uas) >= maxUAs || slices.Contains(w.uas, ua) {
		return
	}
	w.uas = append(w.uas, ua)
}

// retransmitted reports whether message i repeats an earlier message of the call.
func (w *worker) retransmitted(m *trace.Message, i int) bool {
	k := msgKey{
		method: m.Method,
		cseq:   m.CSeq,
		branch: m.Branch(),
		src:    m.SrcAddr(),
		dst:    m.DstAddr(),
	}
	if !m.IsRequest {
		k.code = m.StatusCode
		k.toTag = m.ToTag()
		if m.StatusCode > 100 && m.StatusCode < 200 {
			k.rseq = rawHeader(m, "rseq")
		}
	}
	if i < linearKeys {
		if slices.Contains(w.keys, k) {
			w.keys = append(w.keys, k)
			return true
		}
		w.keys = append(w.keys, k)
		return false
	}
	if len(w.keyMap) == 0 {
		if w.keyMap == nil {
			w.keyMap = make(map[msgKey]struct{}, 64)
		}
		for _, o := range w.keys {
			w.keyMap[o] = struct{}{}
		}
	}
	if _, dup := w.keyMap[k]; dup {
		return true
	}
	w.keyMap[k] = struct{}{}
	return false
}

// findTx returns the index of the transaction (cseq, ftag), or -1.
func (w *worker) findTx(cseq int, ftag string) int {
	if len(w.txs) > linearTx {
		if i, ok := w.txMap[txKey{cseq, ftag}]; ok {
			return int(i)
		}
		return -1
	}
	for i := len(w.txs) - 1; i >= 0; i-- {
		if t := &w.txs[i]; t.cseq == cseq && t.ftag == ftag {
			return i
		}
	}
	return -1
}

// txFor returns the index of transaction (cseq, ftag), creating it if needed.
func (w *worker) txFor(cseq int, ftag string) int {
	if i := w.findTx(cseq, ftag); i >= 0 {
		return i
	}
	w.txs = append(w.txs, tx{cseq: cseq, ftag: ftag, req: -1, ok: -1, fail: -1, ring: -1, initial: true})
	n := len(w.txs)
	if n > linearTx {
		if w.txMap == nil {
			w.txMap = make(map[txKey]int32, 64)
		}
		if n == linearTx+1 {
			for j := range w.txs[:n-1] {
				w.txMap[txKey{w.txs[j].cseq, w.txs[j].ftag}] = int32(j)
			}
		}
		w.txMap[txKey{cseq, ftag}] = int32(n - 1)
	}
	return n - 1
}

func kindOf(method string) Kind {
	switch strings.ToUpper(method) {
	case "INVITE", "ACK", "BYE", "CANCEL", "PRACK", "UPDATE", "INFO":
		return KindCall
	case "REGISTER":
		return KindRegistration
	case "SUBSCRIBE", "NOTIFY", "REFER":
		return KindSubscription
	case "MESSAGE":
		return KindMessage
	case "OPTIONS":
		return KindOptions
	}
	return KindOther
}

// Sides of a dialog.
const (
	sideUnknown = 0
	sideCaller  = 1
	sideCallee  = 2
)

// callerTag returns the From tag of the dialog's caller: that of the initial
// INVITE, else of the first response to an INVITE or ACK (both echo/send the caller's From).
func callerTag(msgs []trace.Message, invite int) string {
	if invite >= 0 {
		return msgs[invite].FromTag()
	}
	for i := range msgs {
		m := &msgs[i]
		if (m.IsRequest && isMethod(m, "ACK")) || (!m.IsRequest && isMethod(m, "INVITE")) {
			return m.FromTag()
		}
	}
	return ""
}

// senderSide decides whether the sender of a request carrying m's From/To
// headers is the caller or the callee of the dialog. Tags come first, since
// addresses lie behind proxies, SBCs and NAT. src is the address the request
// was sent from (the destination for a response).
func senderSide(m *trace.Message, ctag string, src, caller, callee netip.AddrPort) int {
	if ctag != "" {
		ft := m.FromTag()
		switch {
		case ft == ctag:
			return sideCaller
		case m.ToTag() == ctag:
			return sideCallee
		case ft != "":
			return sideCallee
		}
	}
	if caller.IsValid() {
		switch {
		case src == caller:
			return sideCaller
		case src == callee:
			return sideCallee
		case src.Addr() == caller.Addr() && src.Addr() != callee.Addr():
			return sideCaller
		case src.Addr() == callee.Addr() && src.Addr() != caller.Addr():
			return sideCallee
		}
	}
	return sideUnknown
}

// analyze derives every field of c from its messages.
func (w *worker) analyze(c *Call, _ *Options) {
	w.reset()
	msgs := c.Messages
	if !slices.IsSortedFunc(msgs, cmpTime) {
		slices.SortStableFunc(msgs, cmpTime)
	}
	c.Start, c.End = msgs[0].Time, msgs[len(msgs)-1].Time

	firstReq := -1
	for i := range msgs {
		if msgs[i].IsRequest {
			firstReq = i
			break
		}
	}
	var prim string
	if firstReq >= 0 {
		c.Method = msgs[firstReq].Method
		c.Kind = kindOf(c.Method)
		prim = primaryMethod(c.Kind, c.Method)
	} else {
		c.Kind = kindOf(msgs[0].Method)
		prim = primaryMethod(c.Kind, msgs[0].Method)
	}
	isCall := c.Kind == KindCall

	var (
		bye, byeResp, cancel = -1, -1, -1
		anyBody              bool
	)
	for i := range msgs {
		m := &msgs[i]
		w.addEndpoint(m.SrcAddr())
		w.addEndpoint(m.DstAddr())
		if ua := userAgent(m); ua != "" {
			w.addUA(ua)
		}
		if w.retransmitted(m, i) {
			c.Retransmissions++
			if !m.IsRequest && m.StatusCode >= 200 && m.StatusCode < 300 && isMethod(m, "INVITE") {
				w.dups = append(w.dups, cseqNum(m.CSeq))
			}
		}
		if m.HeaderEnd > 0 && m.HeaderEnd < len(m.Raw) {
			anyBody = true
		}

		if m.IsRequest {
			switch {
			case bye < 0 && isMethod(m, "BYE"):
				bye = i
			case cancel < 0 && isMethod(m, "CANCEL"):
				cancel = i
			}
			if prim != "" && isMethod(m, prim) {
				ti := w.txFor(cseqNum(m.CSeq), m.FromTag())
				t := &w.txs[ti]
				if !t.hasReq {
					t.hasReq, t.req = true, int32(i)
					t.initial = prim != "INVITE" || m.ToTag() == ""
				}
			}
			continue
		}

		if byeResp < 0 && m.StatusCode >= 200 && m.StatusCode < 300 && isMethod(m, "BYE") {
			byeResp = i
		}
		if prim == "" || !isMethod(m, prim) {
			continue
		}
		t := &w.txs[w.txFor(cseqNum(m.CSeq), m.FromTag())]
		t.anyResp = true
		switch code := m.StatusCode; {
		case code >= 300:
			t.fail = int32(i)
		case code >= 200:
			if t.ok < 0 {
				t.ok = int32(i)
			}
		case code > 100:
			if t.ring < 0 {
				t.ring = int32(i)
			}
		}
	}

	// Primary transactions, in order of first appearance.
	anyInitialReq := false
	for i := range w.txs {
		if w.txs[i].hasReq && w.txs[i].initial {
			anyInitialReq = true
			break
		}
	}
	prims := make([]int32, 0, 4)[:0]
	for i := range w.txs {
		t := &w.txs[i]
		if (t.hasReq && t.initial) || (!t.hasReq && !anyInitialReq) {
			prims = append(prims, int32(i))
		}
	}
	c.Attempts = len(prims)

	// From/To: of the first primary request, else the first request, else the first message.
	headMsg := &msgs[0]
	invite := -1
	for _, pi := range prims {
		if t := &w.txs[pi]; t.hasReq {
			invite = int(t.req)
			break
		}
	}
	switch {
	case invite >= 0:
		headMsg = &msgs[invite]
	case firstReq >= 0:
		headMsg = &msgs[firstReq]
	}
	c.From, c.To = headMsg.From, headMsg.To
	c.FromUser, c.ToUser = headMsg.FromUser(), headMsg.ToUser()
	if invite >= 0 || (!isCall && firstReq >= 0) {
		src, dst := invite, invite
		if invite < 0 {
			src, dst = firstReq, firstReq
		}
		c.Caller, c.Callee = msgs[src].SrcAddr(), msgs[dst].DstAddr()
	}

	if isCall {
		w.finishCall(c, prims, invite, bye, byeResp, cancel)
	} else {
		w.finishPlain(c, prims)
	}

	if len(w.eps) > 0 {
		c.Endpoints = slices.Clone(w.eps)
	}
	if len(w.uas) > 0 {
		c.UserAgents = slices.Clone(w.uas)
	}
	if anyBody {
		w.buildMedia(c, invite)
	}
}

func primaryMethod(k Kind, method string) string {
	if k == KindCall {
		return "INVITE"
	}
	return strings.ToUpper(method)
}

// finishPlain decides the state of a non-INVITE Call-ID: that of the latest
// transaction of the method of its first request.
func (w *worker) finishPlain(c *Call, prims []int32) {
	c.State = StateNoResponse
	if len(prims) == 0 {
		return
	}
	t := &w.txs[prims[0]]
	for j := len(prims) - 1; j > 0; j-- {
		if w.txs[prims[j]].anyResp {
			t = &w.txs[prims[j]]
			break
		}
	}
	idx := t.ok
	if idx < 0 {
		idx = t.fail
	}
	if idx < 0 {
		return
	}
	fm := &c.Messages[idx]
	c.FinalCode, c.FinalReason, c.Result = fm.StatusCode, fm.Reason, fm.Info()
	switch {
	case fm.StatusCode < 300:
		c.State = StateOK
	case fm.StatusCode < 400:
		c.State = StateRedirected
		c.Reason = reasonHeader(fm)
	default:
		c.State = StateFailed
		c.Reason = reasonHeader(fm)
	}
}

// finishCall implements the INVITE state machine, timings and end attribution.
func (w *worker) finishCall(c *Call, prims []int32, invite, bye, byeResp, cancel int) {
	msgs := c.Messages

	okIdx, ringIdx := int32(-1), int32(-1)
	var okTx *tx
	for _, pi := range prims {
		t := &w.txs[pi]
		if t.ok >= 0 && (okIdx < 0 || t.ok < okIdx) {
			okIdx, okTx = t.ok, t
		}
		if t.ring >= 0 && (ringIdx < 0 || t.ring < ringIdx) {
			ringIdx = t.ring
		}
	}
	// The deciding transaction is the latest initial one that got any response:
	// an unanswered retry after an auth challenge must not hide the challenge
	// (the call ends as "failed 401/407", not as "no-response").
	var decide *tx
	for j := len(prims) - 1; j >= 0; j-- {
		if t := &w.txs[prims[j]]; t.anyResp || j == 0 {
			decide = t
			break
		}
	}

	byeIdx := bye
	if byeIdx < 0 || (byeResp >= 0 && byeResp < byeIdx) {
		byeIdx = byeResp
	}

	var final int32 = -1 // message that decided the outcome (first 2xx, else the last failure)
	switch {
	case okIdx >= 0:
		final = okIdx
		c.State = StateAnswered
		if byeIdx >= 0 {
			c.State = StateCompleted
		}
	case decide == nil:
		switch {
		case byeIdx >= 0:
			c.State = StateCompleted
		case cancel >= 0:
			c.State = StateCancelled
		default:
			c.State = StateAnswered // mid-dialog capture: re-INVITE/UPDATE/INFO traffic only
		}
	case decide.fail < 0 && decide.hasReq && ackedWithoutFinal(msgs, decide):
		c.State = StateAnswered // 2xx lost, but the caller's ACK proves the answer
		if byeIdx >= 0 {
			c.State = StateCompleted
		}
	case decide.fail >= 0:
		final = decide.fail
		code := msgs[final].StatusCode
		switch {
		case code >= 300 && code < 400:
			c.State = StateRedirected
		case code == 487 && cancel >= 0:
			c.State = StateCancelled
		default:
			c.State = StateFailed
		}
	case byeIdx >= 0:
		c.State = StateCompleted // BYE proves the call was up even though the 2xx was not captured
	case cancel >= 0:
		c.State = StateCancelled
	case decide.anyResp:
		c.State = StateInSetup
	default:
		c.State = StateNoResponse
	}

	var fm *trace.Message
	if final >= 0 {
		fm = &msgs[final]
		c.FinalCode, c.FinalReason, c.Result = fm.StatusCode, fm.Reason, fm.Info()
	}

	// Timings.
	var t0 = msgs[0].Time
	haveT0 := invite >= 0
	if haveT0 {
		t0 = msgs[invite].Time
	}
	if fm != nil && okIdx >= 0 {
		c.Answered = fm.Time
		if haveT0 {
			c.SetupTime = clampPos(fm.Time.Sub(t0))
		}
	}
	if haveT0 {
		switch {
		case ringIdx >= 0 && (fm == nil || !msgs[ringIdx].Time.After(fm.Time)):
			c.PDD = clampPos(msgs[ringIdx].Time.Sub(t0))
		case fm != nil:
			c.PDD = clampPos(fm.Time.Sub(t0))
		}
	}
	if ringIdx >= 0 && fm != nil && !fm.Time.Before(msgs[ringIdx].Time) {
		c.RingTime = fm.Time.Sub(msgs[ringIdx].Time)
	}

	// How the call ended.
	switch c.State {
	case StateCompleted:
		c.EndMethod = "BYE"
		c.Ended = msgs[byeIdx].Time
		if !c.Answered.IsZero() {
			c.TalkTime = clampPos(c.Ended.Sub(c.Answered))
		}
		if bye >= 0 {
			c.Reason = reasonHeader(&msgs[bye])
		}
		c.EndedBy = w.byeSide(c, invite, byeIdx, bye >= 0)
	case StateCancelled:
		c.EndMethod = "CANCEL"
		c.EndedBy = "caller"
		if cancel >= 0 {
			c.Ended = msgs[cancel].Time
			c.Reason = reasonHeader(&msgs[cancel])
		}
		if c.Reason == "" && fm != nil {
			c.Reason = reasonHeader(fm)
		}
	case StateFailed, StateRedirected:
		if fm != nil {
			c.Reason = reasonHeader(fm)
		}
	}

	// Forks: distinct To tags in the 1xx/2xx responses of the deciding INVITE.
	var rel *tx
	if okTx != nil {
		rel = okTx
	} else {
		rel = decide
	}
	if rel != nil {
		w.tags = w.tags[:0]
		for i := range msgs {
			m := &msgs[i]
			if m.IsRequest || m.StatusCode <= 100 || m.StatusCode >= 300 || !isMethod(m, "INVITE") {
				continue
			}
			if cseqNum(m.CSeq) != rel.cseq || m.FromTag() != rel.ftag {
				continue
			}
			if tag := m.ToTag(); tag != "" && !slices.Contains(w.tags, tag) {
				w.tags = append(w.tags, tag)
			}
		}
		c.Forks = len(w.tags)
	}

	if okTx != nil && slices.Contains(w.dups, okTx.cseq) && !hasACK(msgs, okTx) {
		c.MissingACK = true
	}
}

func clampPos(d time.Duration) time.Duration {
	if d < 0 {
		return 0
	}
	return d
}

// byeSide attributes the BYE at index idx (a request if isReq) to the caller or callee.
func (w *worker) byeSide(c *Call, invite, idx int, isReq bool) string {
	msgs := c.Messages
	m := &msgs[idx]
	src := m.SrcAddr()
	if !isReq {
		src = m.DstAddr() // the BYE went the other way
	}
	switch senderSide(m, callerTag(msgs, invite), src, c.Caller, c.Callee) {
	case sideCaller:
		return "caller"
	case sideCallee:
		return "callee"
	}
	return ""
}

// hasACK reports whether an ACK for the INVITE transaction t was captured.
func hasACK(msgs []trace.Message, t *tx) bool {
	for i := range msgs {
		m := &msgs[i]
		if m.IsRequest && isMethod(m, "ACK") && cseqNum(m.CSeq) == t.cseq && m.FromTag() == t.ftag {
			return true
		}
	}
	return false
}

// ackedWithoutFinal reports whether an ACK carrying a Via branch that no
// INVITE of t used was captured: such an ACK belongs to a 2xx (an ACK for a
// non-2xx reuses the INVITE's branch).
func ackedWithoutFinal(msgs []trace.Message, t *tx) bool {
	for i := range msgs {
		a := &msgs[i]
		if !a.IsRequest || !isMethod(a, "ACK") || cseqNum(a.CSeq) != t.cseq || a.FromTag() != t.ftag {
			continue
		}
		br := a.Branch()
		if br == "" {
			continue
		}
		same := false
		for j := range msgs {
			r := &msgs[j]
			if r.IsRequest && isMethod(r, "INVITE") && cseqNum(r.CSeq) == t.cseq && r.Branch() == br {
				same = true
				break
			}
		}
		if !same {
			return true
		}
	}
	return false
}
