package pcaptest

import (
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// Topology selects the signalling path of a call.
type Topology int

const (
	// Direct is caller <-> callee, one Call-ID.
	Direct Topology = iota
	// Proxy is caller <-> stateful proxy <-> callee: one Call-ID, an extra
	// Via and Record-Route/Route, no media relay.
	Proxy
	// B2BUA is caller <-> SBC <-> callee: two Call-IDs (and two dialogs)
	// that share an X-CID header, with the SBC relaying the media (new SSRC
	// and ports on each leg).
	B2BUA
)

// Outcome is how a call ends.
type Outcome int

const (
	// Answered is INVITE, 100, 180, 200, ACK, media, BYE, 200.
	Answered Outcome = iota
	// Busy is a 486 from the callee (or from the proxy with AtProxy).
	Busy
	// Rejected is a final failure with CallOptions.RejectCode (default 603).
	Rejected
	// Cancelled is a CANCEL sent by the caller after RingTime (default 3 s)
	// of ringing: CANCEL, 200, 487, ACK.
	Cancelled
	// NoAnswer rings (180) and the caller gives up with CANCEL after
	// RingTime (default 30 s).
	NoAnswer
	// Unreachable is an INVITE that gets no answer from the far end:
	// retransmitted per timer A (Retransmits times, default the full 6).
	// With a Proxy or SBC the proxy answers 100 Trying and generates a 408
	// after 32 s; with Direct a 408 is only sent when Timeout408 is set.
	Unreachable
	// ServerError is a 503 (or CallOptions.RejectCode) with Retry-After.
	ServerError
)

// CallOptions configures one call. Zero values are replaced by realistic
// defaults; every field is optional.
type CallOptions struct {
	// Start is the time of the first INVITE (default: the Builder start).
	Start time.Time
	// Caller, Callee and Proxy are the signalling endpoints. Proxy is the
	// proxy / SBC for the Proxy and B2BUA topologies.
	Caller, Callee, Proxy netip.AddrPort
	// From and To are the user parts (defaults alice, bob).
	From, To string
	// Domain is the SIP domain of the From/To URIs (default example.com).
	Domain string
	// Transport is "UDP" (default) or "TCP".
	Transport string
	// Codec is "PCMU" (default), "PCMA", "G729" or "opus".
	Codec string
	// Topology is Direct (default), Proxy or B2BUA.
	Topology Topology
	// Outcome defaults to Answered.
	Outcome Outcome
	// RejectCode is the final status for Rejected (default 603) and
	// ServerError (default 503).
	RejectCode int
	// AtProxy makes a Busy/Rejected/ServerError response come from the
	// proxy / SBC (To tag of its own, Server header of the proxy) instead of
	// the callee. Ignored for Direct.
	AtProxy bool
	// Timeout408 makes an Unreachable Direct call end with a 408 from the
	// callee side after 32 s. Always done with a Proxy or SBC.
	Timeout408 bool
	// Auth, when 401 or 407, makes the first INVITE draw that challenge from
	// the first server element, followed by an authenticated INVITE with a
	// new CSeq and branch.
	Auth int
	// Hold makes the caller put the call on hold at HoldAt after the ACK
	// (re-INVITE a=sendonly) and resume HoldFor later (re-INVITE a=sendrecv).
	Hold bool
	// HoldZeroIP puts c=0.0.0.0 in the hold offer.
	HoldZeroIP bool
	// ReInvite sends one session refresh re-INVITE (same SDP) at HoldAt.
	ReInvite bool
	// HoldAt (default 2 s) and HoldFor (default 2 s). TalkTime is raised
	// to cover them plus 2 s.
	HoldAt, HoldFor time.Duration
	// EarlyMedia sends a 183 with SDP instead of a 180 and early RTP from
	// the callee until the answer.
	EarlyMedia bool
	// RingTime is the time from the first INVITE reaching the callee to
	// the answer (Answered) or the CANCEL (Cancelled/NoAnswer). Defaults
	// 2 s, 3 s and 30 s. For Busy/Rejected, a non-zero value adds a 180
	// first.
	RingTime time.Duration
	// TalkTime is the time between the ACK and the BYE (default 5 s).
	TalkTime time.Duration
	// MissingACK withholds the ACK: the callee retransmits the 200 per timer
	// (OKRetransmits times, default all, 10) and sends BYE after 32 s. No
	// RTP is generated.
	MissingACK bool
	// OKRetransmits limits the 200 retransmissions of MissingACK.
	OKRetransmits int
	// NATed makes the caller advertise NATPrivate in Via, Contact and SDP
	// while its packets come from the public Caller address; the callee
	// sends its RTP to the unroutable private address.
	NATed bool
	// NATPrivate defaults to 192.168.1.50.
	NATPrivate netip.Addr
	// HangUpBy is "caller" (default) or "callee".
	HangUpBy string
	// Reason is the Reason header of BYE and CANCEL, e.g.
	// "Q.850;cause=16".
	Reason string
	// DelayedOffer sends the INVITE without SDP: the offer is in the 200
	// and the answer in the ACK.
	DelayedOffer bool
	// Retransmits is the number of INVITE retransmissions on the caller's
	// hop before the first response (Unreachable: default 6, the whole timer
	// A schedule up to 32 s).
	Retransmits int
	// CallerRTP and CalleeRTP shape the media each side sends.
	CallerRTP, CalleeRTP RTPOptions
	// CallerUA, CalleeUA, ProxyUA are User-Agent / Server values (defaults
	// are realistic products).
	CallerUA, CalleeUA, ProxyUA string
	// XCID is the X-CID header shared by both B2BUA legs (default random).
	XCID string
	// Latency is the one way delay per hop (default 3 ms).
	Latency time.Duration
	// Compact drops optional headers (Allow, Supported, Session-Expires) and
	// the SDP extras (ptime, fmtp, telephone-event, second codec) to keep
	// large generated captures small. The result is still valid SIP/SDP.
	Compact bool
	// TCPSplit (TCP only) sends the first INVITE of the call in two TCP
	// segments, cut inside the headers.
	TCPSplit bool
	// TCPCoalesce (TCP only) puts a 100 Trying and the following response
	// of the same hop into one TCP segment (two SIP messages in one segment).
	TCPCoalesce bool
	// CallID overrides the caller leg Call-ID.
	CallID string
}

type addrs struct {
	caller, callee, proxy netip.AddrPort
}

func (b *Builder) defaultAddrs(o CallOptions) addrs {
	a := addrs{o.Caller, o.Callee, o.Proxy}
	v6 := b.link.IPv6
	pick := func(v4, v6s string, port uint16) netip.AddrPort {
		if v6 {
			return netip.AddrPortFrom(netip.MustParseAddr(v6s), port)
		}
		return netip.AddrPortFrom(netip.MustParseAddr(v4), port)
	}
	if !a.caller.IsValid() {
		if o.NATed && !v6 {
			a.caller = pick("203.0.113.10", "", 5060)
		} else {
			a.caller = pick("10.0.1.10", "2001:db8:1::10", 5060)
		}
	}
	if !a.callee.IsValid() {
		a.callee = pick("10.0.2.20", "2001:db8:2::20", 5060)
	}
	if !a.proxy.IsValid() {
		a.proxy = pick("10.0.0.1", "2001:db8::1", 5060)
	}
	return a
}

func titleName(u string) string {
	if u == "" {
		return ""
	}
	return strings.ToUpper(u[:1]) + u[1:]
}

// callPlan is the resolved state of one call under construction.
type callPlan struct {
	o       CallOptions
	s       *scn
	last    int
	codec   codecInfo
	inv     *txn
	pps     [2]int // packets per second each side sends
	ssrc    [2]uint32
	relay   bool
	sbcSSRC [2]uint32
}

// Call adds one call and returns the Call-ID of the caller leg. With the
// B2BUA topology the callee leg Call-ID is available from LegCallIDs.
func (b *Builder) Call(o CallOptions) string {
	if o.Start.IsZero() {
		o.Start = b.start
	}
	o.Start = o.Start.UTC()
	if o.From == "" {
		o.From = "alice"
	}
	if o.To == "" {
		o.To = "bob"
	}
	if o.Domain == "" {
		o.Domain = "example.com"
	}
	if o.Transport == "" {
		o.Transport = "UDP"
	}
	if o.Latency == 0 {
		o.Latency = 3 * time.Millisecond
	}
	if o.CallerUA == "" {
		o.CallerUA = "Yealink SIP-T46S 66.85.0.5"
	}
	if o.CalleeUA == "" {
		o.CalleeUA = "Asterisk PBX 20.5.0"
	}
	if o.ProxyUA == "" {
		if o.Topology == B2BUA {
			o.ProxyUA = "Ribbon SBC 12.1.1"
		} else {
			o.ProxyUA = "Kamailio (5.7.2)"
		}
	}
	if !o.NATPrivate.IsValid() {
		o.NATPrivate = netip.MustParseAddr("192.168.1.50")
	}
	if o.HoldAt <= 0 {
		o.HoldAt = 2 * time.Second
	}
	if o.HoldFor <= 0 {
		o.HoldFor = 2 * time.Second
	}
	if o.TalkTime <= 0 {
		o.TalkTime = 5 * time.Second
	}
	if (o.Hold || o.ReInvite) && o.TalkTime < o.HoldAt+o.HoldFor+2*time.Second {
		o.TalkTime = o.HoldAt + o.HoldFor + 2*time.Second
	}
	if o.RingTime == 0 {
		switch o.Outcome {
		case Answered:
			o.RingTime = 2 * time.Second
		case Cancelled:
			o.RingTime = 3 * time.Second
		case NoAnswer:
			o.RingTime = 30 * time.Second
		}
	}
	if o.RejectCode == 0 {
		if o.Outcome == ServerError {
			o.RejectCode = 503
		} else {
			o.RejectCode = 603
		}
	}
	if o.Outcome == Busy {
		o.RejectCode = 486
	}
	if o.Outcome == Unreachable && o.Retransmits == 0 {
		o.Retransmits = len(timerSchedule(false))
	}
	codec := lookupCodec(o.Codec)

	cp := &callPlan{o: o, codec: codec}
	cp.s = b.buildScn(&o, cp)
	cp.last = len(cp.s.hops) - 1
	cp.pps[0], cp.pps[1] = orPPS(o.CallerRTP.PacketsPerSecond), orPPS(o.CalleeRTP.PacketsPerSecond)
	for i, ro := range []RTPOptions{o.CallerRTP, o.CalleeRTP} {
		cp.ssrc[i] = ro.SSRC
		if cp.ssrc[i] == 0 {
			cp.ssrc[i] = b.rng.Uint32()
		}
		cp.sbcSSRC[i] = b.rng.Uint32()
	}
	cp.o = o
	cp.s.compact = o.Compact
	cp.s.coalesce = o.TCPCoalesce
	cp.s.split = o.TCPSplit
	cp.run(b)
	cp.s.flush(o.Start)
	ids := []string{cp.s.hops[0].d.callID}
	if o.Topology == B2BUA {
		ids = append(ids, cp.s.hops[1].d.callID)
	}
	b.legs[ids[0]] = ids
	return ids[0]
}

func orPPS(p int) int {
	if p <= 0 {
		return 50
	}
	return p
}

// buildScn resolves addresses, dialogs and hops for the call.
func (b *Builder) buildScn(o *CallOptions, cp *callPlan) *scn {
	a := b.defaultAddrs(*o)
	tcp := o.Transport == "TCP"
	s := &scn{b: b, topo: o.Topology, tcp: tcp, domain: o.Domain, toUser: o.To, midTag: b.newTag(),
		proxyUA: o.ProxyUA}
	eph := func() uint16 { return uint16(32768 + b.rng.IntN(28000)) }
	if tcp {
		a.caller = netip.AddrPortFrom(a.caller.Addr(), eph())
		if o.Topology != Direct {
			// proxy -> callee hop uses its own ephemeral port on the proxy
			_ = a.proxy
		}
	}
	callerPriv := a.caller
	if o.NATed {
		callerPriv = netip.AddrPortFrom(o.NATPrivate, a.caller.Port())
	}
	fromURI := "sip:" + o.From + "@" + o.Domain
	toURI := "sip:" + o.To + "@" + o.Domain
	callerContact := fmt.Sprintf("sip:%s@%s", o.From, hostPort(callerPriv))
	calleeContact := fmt.Sprintf("sip:%s@%s", o.To, hostPort(a.callee))
	if o.Transport == "TCP" {
		callerContact += ";transport=tcp"
		calleeContact += ";transport=tcp"
	}
	newDlg := func(id string) *dlg {
		d := &dlg{callID: id, lTag: b.newTag(), rTag: b.newTag(),
			lName: titleName(o.From), rName: titleName(o.To), lURI: fromURI, rURI: toURI}
		d.cseq[sideL] = 1 + b.rng.IntN(2000)
		d.cseq[sideR] = 0
		d.sess[sideL] = uint64(b.rng.Uint32()) + 1_700_000_000
		d.sess[sideR] = uint64(b.rng.Uint32()) + 1_700_000_000
		return d
	}
	callID := o.CallID
	if callID == "" {
		callID = b.newCallID(hostOnly(callerPriv.Addr()))
	}
	port := func(p uint16) uint16 {
		if p != 0 {
			return p
		}
		return uint16(10000 + 2*b.rng.IntN(25000))
	}
	callerMedia := netip.AddrPortFrom(a.caller.Addr(), port(o.CallerRTP.Port))
	calleeMedia := netip.AddrPortFrom(a.callee.Addr(), port(o.CalleeRTP.Port))
	callerAdv := callerMedia
	if o.NATed {
		callerAdv = netip.AddrPortFrom(o.NATPrivate, callerMedia.Port())
	}
	sdpU := [2]string{"-", "root"}
	switch o.Topology {
	case Direct:
		d := newDlg(callID)
		h := &hop{l: a.caller, r: a.callee, lat: o.Latency, d: d,
			contact: [2]string{callerContact, calleeContact},
			ua:      [2]string{o.CallerUA, o.CalleeUA},
			via:     [2]string{hostPort(callerPriv), hostPort(a.callee)},
			adv:     [2]netip.AddrPort{callerAdv, calleeMedia},
			real:    [2]netip.AddrPort{callerMedia, calleeMedia},
			sdpUser: sdpU,
			uriHost: [2]string{hostPort(callerPriv), hostPort(a.callee)}}
		s.hops = []*hop{h}
	case Proxy:
		d := newDlg(callID)
		s.rr = fmt.Sprintf("sip:%s;lr", hostPort(a.proxy))
		pc := fmt.Sprintf("sip:%s", hostPort(a.proxy))
		pOut := a.proxy
		if tcp {
			pOut = netip.AddrPortFrom(a.proxy.Addr(), eph())
		}
		h0 := &hop{l: a.caller, r: a.proxy, lat: o.Latency, d: d,
			contact: [2]string{callerContact, calleeContact},
			ua:      [2]string{o.CallerUA, o.CalleeUA},
			via:     [2]string{hostPort(callerPriv), hostPort(a.proxy)},
			adv:     [2]netip.AddrPort{callerAdv, calleeMedia},
			real:    [2]netip.AddrPort{callerMedia, calleeMedia},
			sdpUser: sdpU,
			uriHost: [2]string{hostPort(callerPriv), o.Domain}}
		h1 := &hop{l: pOut, r: a.callee, lat: o.Latency, d: d,
			contact: [2]string{callerContact, calleeContact},
			ua:      [2]string{o.CallerUA, o.CalleeUA},
			via:     [2]string{hostPort(pOut), hostPort(a.callee)},
			adv:     h0.adv, real: h0.real, sdpUser: sdpU,
			uriHost: [2]string{hostPort(callerPriv), hostPort(a.callee)}}
		_ = pc
		s.hops = []*hop{h0, h1}
	case B2BUA:
		d0 := newDlg(callID)
		d1 := newDlg(b.newCallID(hostOnly(a.proxy.Addr())))
		pOut := a.proxy
		if tcp {
			pOut = netip.AddrPortFrom(a.proxy.Addr(), eph())
		}
		sbcC := fmt.Sprintf("sip:%s@%s", o.From, hostPort(a.proxy))
		sbcC2 := fmt.Sprintf("sip:%s@%s", o.From, hostPort(pOut))
		sbcCallee := fmt.Sprintf("sip:%s@%s", o.To, hostPort(a.proxy))
		sbcM1 := netip.AddrPortFrom(a.proxy.Addr(), port(0))
		sbcM2 := netip.AddrPortFrom(a.proxy.Addr(), port(0))
		for sbcM2.Port() == sbcM1.Port() {
			sbcM2 = netip.AddrPortFrom(a.proxy.Addr(), port(0))
		}
		cp.relay = true
		h0 := &hop{l: a.caller, r: a.proxy, lat: o.Latency, d: d0,
			contact: [2]string{callerContact, sbcCallee},
			ua:      [2]string{o.CallerUA, o.ProxyUA},
			via:     [2]string{hostPort(callerPriv), hostPort(a.proxy)},
			adv:     [2]netip.AddrPort{callerAdv, sbcM1},
			real:    [2]netip.AddrPort{callerMedia, sbcM1},
			sdpUser: sdpU,
			uriHost: [2]string{hostPort(callerPriv), o.Domain}}
		h1 := &hop{l: pOut, r: a.callee, lat: o.Latency, d: d1,
			contact: [2]string{sbcC2, calleeContact},
			ua:      [2]string{o.ProxyUA, o.CalleeUA},
			via:     [2]string{hostPort(pOut), hostPort(a.callee)},
			adv:     [2]netip.AddrPort{sbcM2, calleeMedia},
			real:    [2]netip.AddrPort{sbcM2, calleeMedia},
			sdpUser: [2]string{"-", "root"},
			uriHost: [2]string{hostPort(pOut), hostPort(a.callee)}}
		_ = sbcC
		s.hops = []*hop{h0, h1}
		s.xcid = o.XCID
		if s.xcid == "" {
			s.xcid = b.token(12, hexch)
		}
	}
	if o.XCID != "" {
		s.xcid = o.XCID
	}
	return s
}

// sdpAt renders the SDP one side presents on hop hi.
func (cp *callPlan) sdpAt(hi int, sd side, dir string, zero, bump bool) string {
	h := cp.s.hops[hi]
	d := h.d
	if bump {
		d.ver[sd]++
	}
	codecs := []codecInfo{cp.codec}
	if sd == sideL && !cp.o.Compact {
		for _, n := range []string{"PCMU", "PCMA"} {
			if n != cp.codec.name {
				codecs = append(codecs, codecTable[n])
				break
			}
		}
	}
	name := "-"
	if sd == sideR && strings.HasPrefix(h.ua[sideR], "Asterisk") {
		name = "Asterisk PBX 20.5.0"
	}
	return sdpMedia{compact: cp.o.Compact, addr: h.adv[sd], codecs: codecs, dir: dir, zeroIP: zero, pps: cp.pps[sd],
		sessID: d.sess[sd], version: d.ver[sd], name: name, user: h.sdpUser[sd], dtmf: true}.String()
}

func (cp *callPlan) bodies(sd side, dir string, zero, bump bool) []string {
	out := make([]string, len(cp.s.hops))
	for hi := range out {
		out[hi] = cp.sdpAt(hi, sd, dir, zero, bump)
	}
	return out
}

func (cp *callPlan) reasonExtra() [][2]string {
	if cp.o.Reason == "" {
		return nil
	}
	return [][2]string{{"Reason", cp.o.Reason}}
}

// run emits every packet of the call.
func (cp *callPlan) run(b *Builder) {
	o, s := cp.o, cp.s
	last := cp.last
	t := o.Start
	inv := s.newTxn("INVITE", true, nil, nil)
	inv.initial, inv.user, inv.contact = true, o.To, true
	if !o.Compact {
		inv.extra = [][2]string{{"Session-Expires", "1800;refresher=uac"}}
	}
	s.splitCSeq = inv.cseq[0]
	var offerBody []string
	if !o.DelayedOffer {
		offerBody = cp.bodies(sideL, "sendrecv", false, false)
		inv.body = offerBody
	}
	cp.inv = inv

	// authentication round on the first hop
	if o.Auth == 401 || o.Auth == 407 {
		t = cp.authRound(inv, t)
		inv = s.newTxn("INVITE", true, nil, nil)
		inv.initial, inv.user, inv.contact = true, o.To, true
		if !o.Compact {
			inv.extra = [][2]string{{"Session-Expires", "1800;refresher=uac"}}
		}
		inv.body = offerBody
		hn := "Proxy-Authorization"
		if o.Auth == 401 {
			hn = "Authorization"
		}
		inv.first = [][2]string{{hn, cp.digest(inv, o.Auth)}}
		cp.inv = inv
		t = t.Add(20 * time.Millisecond)
	}

	// Unreachable
	if o.Outcome == Unreachable {
		cp.unreachable(inv, t)
		return
	}

	// INVITE with retransmissions on the caller's hop
	var extra time.Duration
	if o.Retransmits > 0 {
		sched := timerSchedule(false)
		n := min(o.Retransmits, len(sched))
		for i := 0; i < n; i++ {
			s.emit(s.hops[0], sideL, s.buildReq(inv, 0), t.Add(sched[i]))
		}
		extra = sched[n-1] + 2*time.Millisecond
	}
	stop := last
	if s.topo != Direct && o.AtProxy && (o.Outcome == Busy || o.Outcome == Rejected || o.Outcome == ServerError) {
		stop = 0
	}
	arr := s.reqUpTo(inv, stop, t, extra)

	// 100 Trying from every element that has seen the INVITE
	for pos := 0; pos <= stop; pos++ {
		s.resp(inv, pos, 100, "", respOpts{gen: pos < last}, arr[pos].Add(s.proc()/2))
	}
	tNext := arr[stop].Add(s.proc())

	// failures
	switch o.Outcome {
	case Busy, Rejected, ServerError:
		cp.failure(inv, arr, tNext)
		return
	}

	// provisional: 180 or 183 with early media
	tRing := tNext.Add(time.Duration(40+b.rng.IntN(80)) * time.Millisecond)
	ringArr := tRing
	var earlyFrom time.Time
	var early183 []string
	if o.EarlyMedia {
		early183 = cp.bodies(sideR, "sendrecv", false, false)
		ringArr = s.respDown(inv, last, 0, 183, tagDlg, respOpts{contact: true, rr: true, body: early183,
			extra: [][2]string{{"Require", "100rel"}}}, tRing)
		earlyFrom = tRing.Add(10 * time.Millisecond)
	} else {
		ringArr = s.respDown(inv, last, 0, 180, tagDlg, respOpts{contact: true, rr: true}, tRing)
	}
	_ = ringArr
	tDecision := arr[last].Add(o.RingTime)
	if tDecision.Before(tRing.Add(100 * time.Millisecond)) {
		tDecision = tRing.Add(100 * time.Millisecond)
	}

	switch o.Outcome {
	case Cancelled, NoAnswer:
		cp.cancel(inv, tDecision, earlyFrom)
		return
	}

	// answered
	var ansBody []string
	if o.DelayedOffer {
		ansBody = cp.bodies(sideR, "sendrecv", false, false)
	} else if early183 != nil {
		ansBody = early183
	} else {
		ansBody = cp.bodies(sideR, "sendrecv", false, false)
	}
	ro200 := respOpts{contact: true, rr: true, body: ansBody}
	callerGot := s.respDown(inv, last, 0, 200, tagDlg, ro200, tDecision)
	tAck := callerGot.Add(time.Duration(1+b.rng.IntN(4)) * time.Millisecond)

	if o.MissingACK {
		cp.missingACK(inv, ro200, tDecision)
		return
	}
	ack := s.newTxn("ACK", true, inv, nil)
	ack.est, ack.contact, ack.route = true, true, true
	if o.DelayedOffer {
		ack.body = cp.bodies(sideL, "sendrecv", false, false)
	}
	s.reqUpTo(ack, last, tAck, 0)
	ackDone := tAck

	// media windows
	callerStart := ackDone.Add(10 * time.Millisecond)
	calleeStart := tDecision.Add(10 * time.Millisecond)
	if !earlyFrom.IsZero() {
		calleeStart = earlyFrom
	}
	tBye := ackDone.Add(o.TalkTime)
	var callerSeg, calleeSeg [][2]time.Time
	callerSeg = [][2]time.Time{{callerStart, tBye}}
	calleeSeg = [][2]time.Time{{calleeStart, tBye}}
	if o.Hold || o.ReInvite {
		hAt := ackDone.Add(o.HoldAt)
		if o.Hold {
			tHeld, tRes := cp.holdResume(inv, hAt)
			// callee stops sending while held; caller sends MoH unless zero IP
			calleeSeg = [][2]time.Time{{calleeStart, tHeld}, {tRes, tBye}}
			if o.HoldZeroIP {
				callerSeg = [][2]time.Time{{callerStart, tHeld}, {tRes, tBye}}
			}
		} else {
			cp.reinviteOnly(inv, hAt)
		}
	}
	cp.media(callerSeg, calleeSeg)

	// hang up
	cp.bye(tBye)
}

func (cp *callPlan) digest(x *txn, code int) string {
	b := cp.s.b
	h := cp.s.hops[0]
	user := cp.o.From
	realm := cp.o.Domain
	return fmt.Sprintf(`Digest username=%s, realm=%s, nonce=%s, uri=%s, response=%s, algorithm=MD5, cnonce=%s, qop=auth, nc=00000001`,
		quoted(user), quoted(realm), quoted(cp.s.nonce), quoted("sip:"+cp.o.To+"@"+h.uriHost[sideR]), quoted(digestResponse(b)), quoted(b.token(8, hexch)))
}

// authRound plays INVITE -> 401/407 -> ACK on the first hop and returns the
// time the caller received the challenge.
func (cp *callPlan) authRound(inv *txn, t time.Time) time.Time {
	s := cp.s
	b := s.b
	s.nonce = b.token(24, hexch)
	arr := s.reqUpTo(inv, 0, t, 0)
	s.resp(inv, 0, 100, "", respOpts{gen: s.topo != Direct}, arr[0].Add(s.proc()/2))
	hn := "Proxy-Authenticate"
	if cp.o.Auth == 401 {
		hn = "WWW-Authenticate"
	}
	chal := fmt.Sprintf(`Digest realm=%s, nonce=%s, algorithm=MD5, qop="auth"`, quoted(cp.o.Domain), quoted(s.nonce))
	tag := s.midTag
	gen := s.topo != Direct
	if !gen {
		tag = b.newTag()
		s.hops[0].d.rTag = b.newTag() // the real dialog tag of the authenticated attempt
	}
	back := s.failInvite(inv, 0, cp.o.Auth, tag, respOpts{gen: gen, extra: [][2]string{{hn, chal}}}, arr[0].Add(s.proc()))
	return back
}

// failure emits the final failure response and ACKs.
func (cp *callPlan) failure(inv *txn, arr []time.Time, t time.Time) {
	o, s := cp.o, cp.s
	k := cp.last
	tag := tagDlg
	gen := false
	if o.AtProxy && s.topo != Direct {
		k, tag, gen = 0, s.midTag, true
	}
	t = t.Add(40 * time.Millisecond)
	if o.RingTime > 0 && k == cp.last && o.Outcome != ServerError {
		ring := s.respDown(inv, k, 0, 180, tagDlg, respOpts{contact: true, rr: true}, t)
		_ = ring
		t = arr[cp.last].Add(o.RingTime)
	}
	ro := respOpts{gen: gen}
	if o.Outcome == ServerError {
		ro.extra = [][2]string{{"Retry-After", "120"}}
	}
	s.failInvite(inv, k, o.RejectCode, tag, ro, t)
}

// unreachable plays an INVITE the far end never answers.
func (cp *callPlan) unreachable(inv *txn, t time.Time) {
	o, s := cp.o, cp.s
	last := cp.last
	// positions before the dead hop answer 100 Trying
	arr := s.reqUpTo(inv, last, t, 0)
	// Re-do: the loop above emitted the INVITE on every hop once.
	for pos := 0; pos < last; pos++ {
		s.resp(inv, pos, 100, "", respOpts{gen: true}, arr[pos].Add(s.proc()/2))
	}
	sched := timerSchedule(false)
	n := min(o.Retransmits, len(sched))
	// the retransmitting element is the sender on the last hop
	for i := 0; i < n; i++ {
		s.emit(s.hops[last], sideL, s.buildReq(inv, last), s.emitAt[last].Add(sched[i]))
	}
	if last == 0 && !o.Timeout408 {
		return
	}
	t408 := s.emitAt[last].Add(32 * time.Second)
	k := 0
	tag := tagDlg
	gen := false
	if last > 0 {
		k, tag, gen = last-1, s.midTag, true
	}
	s.failInvite(inv, k, 408, tag, respOpts{gen: gen}, t408)
}

// cancel plays CANCEL / 200 / 487 / ACK at time at.
func (cp *callPlan) cancel(inv *txn, at time.Time, earlyFrom time.Time) {
	o, s := cp.o, cp.s
	last := cp.last
	cx := s.newTxn("CANCEL", true, inv, inv)
	cx.initial, cx.user = true, o.To
	cx.extra = cp.reasonExtra()
	t := at
	var lastArr time.Time
	for pos := 0; pos <= last; pos++ {
		arr := s.req(cx, pos, t)
		s.resp(cx, pos, 200, "", respOpts{gen: true}, arr.Add(s.proc()/2))
		t = arr.Add(s.proc())
		lastArr = arr
	}
	t487 := lastArr.Add(time.Duration(2+s.b.rng.IntN(5)) * time.Millisecond)
	s.failInvite(inv, last, 487, tagDlg, respOpts{}, t487)
	if !earlyFrom.IsZero() {
		cp.media([][2]time.Time{}, [][2]time.Time{{earlyFrom, t487}})
	}
}

// missingACK retransmits the 200 and finally hangs up from the callee.
func (cp *callPlan) missingACK(inv *txn, ro respOpts, first time.Time) {
	o, s := cp.o, cp.s
	sched := timerSchedule(true)
	n := len(sched)
	if o.OKRetransmits > 0 && o.OKRetransmits < n {
		n = o.OKRetransmits
	}
	for i := 0; i < n; i++ {
		s.respDown(inv, cp.last, 0, 200, tagDlg, ro, first.Add(sched[i]))
	}
	tBye := first.Add(32 * time.Second)
	bye := s.newTxn("BYE", false, nil, nil)
	bye.est, bye.route = true, true
	bye.extra = cp.reasonExtra()
	s.reqUpTo(bye, cp.last, tBye, 0)
	s.respDown(bye, cp.last, 0, 200, "", respOpts{}, tBye.Add(time.Duration(20+s.b.rng.IntN(20))*time.Millisecond))
}

// reinvite plays a re-INVITE from the caller with the given offer/answer
// attributes and returns the time of the ACK on the caller's hop.
func (cp *callPlan) reinvite(at time.Time, offerDir, answerDir string, zero bool) (tDone time.Time) {
	s := cp.s
	last := cp.last
	x := s.newTxn("INVITE", true, nil, nil)
	x.est, x.contact, x.route = true, true, true
	x.body = cp.bodies(sideL, offerDir, zero, true)
	arr := s.reqUpTo(x, last, at, 0)
	got := s.respDown(x, last, 0, 200, "", respOpts{contact: true, body: cp.bodies(sideR, answerDir, false, true)},
		arr[last].Add(s.proc()))
	ack := s.newTxn("ACK", true, x, nil)
	ack.est, ack.contact, ack.route = true, true, true
	ackAt := got.Add(time.Millisecond)
	s.reqUpTo(ack, last, ackAt, 0)
	return ackAt
}

// holdResume plays the hold and resume re-INVITEs and returns the time the
// callee stopped sending and the time it resumed.
func (cp *callPlan) holdResume(inv *txn, at time.Time) (held, resumed time.Time) {
	o := cp.o
	held = cp.reinvite(at, "sendonly", "recvonly", o.HoldZeroIP)
	resumed = cp.reinvite(at.Add(o.HoldFor), "sendrecv", "sendrecv", false)
	return held, resumed.Add(10 * time.Millisecond)
}

func (cp *callPlan) reinviteOnly(inv *txn, at time.Time) {
	cp.reinvite(at, "sendrecv", "sendrecv", false)
}

// bye hangs the call up at time at (the BYE sender is CallOptions.HangUpBy).
func (cp *callPlan) bye(at time.Time) {
	o, s := cp.o, cp.s
	fwd := o.HangUpBy != "callee"
	x := s.newTxn("BYE", fwd, nil, nil)
	x.est, x.route = true, true
	x.extra = cp.reasonExtra()
	arr := s.reqUpTo(x, cp.last, at, 0)
	s.respDown(x, cp.last, 0, 200, "", respOpts{}, arr[cp.last].Add(s.proc()))
}

// media generates the RTP of both directions over the given active windows.
func (cp *callPlan) media(callerSeg, calleeSeg [][2]time.Time) {
	o, s := cp.o, cp.s
	b := s.b
	if o.MissingACK {
		return
	}
	h0, hl := s.hops[0], s.hops[cp.last]
	dtmf := true
	callerRTP, calleeRTP := o.CallerRTP, o.CalleeRTP
	if calleeRTP.OneWay {
		callerRTP.Silent = true
	}
	if callerRTP.OneWay {
		calleeRTP.Silent = true
	}
	planA := rtpPlan{src: hl.real[sideL], dst: hl.adv[sideR], codec: cp.codec, o: callerRTP, ssrc: cp.ssrc[0],
		intervals: mergeIntervals(callerSeg), dtmf: dtmf}
	planB := rtpPlan{src: hl.real[sideR], dst: hl.adv[sideL], codec: cp.codec, o: calleeRTP, ssrc: cp.ssrc[1],
		intervals: mergeIntervals(calleeSeg), dtmf: dtmf}
	if cp.relay {
		// first leg: caller <-> SBC, second leg: SBC <-> callee
		planA.src, planA.dst = h0.real[sideL], h0.adv[sideR]
		planB.src, planB.dst = hl.real[sideR], hl.adv[sideL]
	}
	stA := b.genRTP(planA)
	stB := b.genRTP(planB)
	cname := o.From + "@" + o.Domain
	if cp.relay {
		b.relay(stA, hl.real[sideL], hl.adv[sideR], cp.sbcSSRC[0], 2*time.Millisecond)
		b.relay(stB, h0.real[sideR], h0.adv[sideL], cp.sbcSSRC[1], 2*time.Millisecond)
	}
	b.genRTCP(planA, stA, planB, stB, cname)
	b.genRTCP(planB, stB, planA, stA, o.To+"@"+o.Domain)
}
