package call

import (
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/sotoz/sipcurious/internal/sdp"
	"github.com/sotoz/sipcurious/internal/trace"
)

// mediaBuilder is the scratch state of one call's offer/answer tracking.
type mediaBuilder struct {
	last []Media // last emitted description per m-line index
}

// exchange is one SDP offer/answer round.
type exchange struct {
	method   string // method of the request that opened the transaction carrying the offer
	cseq     int
	ftag     string // From tag of the transaction (CSeq spaces are per direction)
	side     int    // who sent the offer (sideCaller/sideCallee)
	offer    sdp.Session
	offerAt  time.Time
	answered bool
	final    bool // answered by a 2xx
	answer   sdp.Session
	answerAt time.Time
	early    bool // the latest answer was in a provisional response
}

func flip(side int) int {
	switch side {
	case sideCaller:
		return sideCallee
	case sideCallee:
		return sideCaller
	}
	return sideUnknown
}

// sdpMethod reports whether SDP carried by the message takes part in
// offer/answer (RFC 3264): INVITE, UPDATE, PRACK and ACK requests and 1xx/2xx
// responses to INVITE, UPDATE and PRACK.
func sdpMethod(m *trace.Message) bool {
	switch {
	case m.IsRequest:
		return isMethod(m, "INVITE") || isMethod(m, "UPDATE") || isMethod(m, "PRACK") || isMethod(m, "ACK")
	case m.StatusCode > 100 && m.StatusCode < 300:
		return isMethod(m, "INVITE") || isMethod(m, "UPDATE") || isMethod(m, "PRACK")
	}
	return false
}

// buildMedia fills c.Media from the SDP bodies of c.Messages.
func (w *worker) buildMedia(c *Call, invite int) {
	mb := &w.media
	mb.last = mb.last[:0]
	var (
		msgs = c.Messages
		ctag = callerTag(msgs, invite)
		cur  exchange
		have bool
		out  []Media
	)
	emit := func(e *exchange) {
		out = mb.emit(out, e)
	}
	for i := range msgs {
		m := &msgs[i]
		if m.HeaderEnd <= 0 || m.HeaderEnd >= len(m.Raw) || !sdpMethod(m) {
			continue
		}
		text := sdpText(m)
		if text == "" {
			continue
		}
		sess, err := sdp.Parse(text)
		if err != nil || len(sess.Media) == 0 {
			continue
		}

		cseq := cseqNum(m.CSeq)
		side := messageSide(m, ctag, c, have, &cur)
		sameTx := have && cur.cseq == cseq && cur.ftag == m.FromTag() && isMethod(m, cur.method)

		switch {
		case m.IsRequest && isMethod(m, "ACK"):
			// An ACK only matters as the answer to a delayed offer; an ACK
			// repeating the answer that was already given is noise.
			if have && !cur.answered && cur.side != side {
				answer(&cur, sess, m)
				emit(&cur)
			}

		case have && !cur.answered && cur.side != side:
			answer(&cur, sess, m)
			emit(&cur)

		case have && !cur.answered && cur.side == side:
			// A repeated or changed offer (retransmission, later provisional
			// response, retry after an auth challenge) replaces the pending one.
			cur.offer, cur.offerAt, cur.cseq, cur.ftag, cur.method = sess, m.Time, cseq, m.FromTag(), txMethod(m)

		case sameTx && cur.answered && !m.IsRequest && cur.side != side && !cur.final:
			// Another answer to the same transaction (183 then 200, or a
			// different fork): the first 2xx is authoritative, later ones ignored.
			answer(&cur, sess, m)
			emit(&cur)

		case sameTx && cur.answered:
			// Retransmission or repeat of a settled exchange.

		default:
			cur = exchange{method: txMethod(m), cseq: cseq, ftag: m.FromTag(), side: side, offer: sess, offerAt: m.Time}
			have = true
		}
	}
	if have && !cur.answered {
		emit(&cur)
	}
	if len(out) > 0 {
		c.Media = out
	}
}

func txMethod(m *trace.Message) string { return strings.ToUpper(m.Method) }

// answer completes e with the answer carried by m.
func answer(e *exchange, sess sdp.Session, m *trace.Message) {
	e.early = !m.IsRequest && m.StatusCode < 200
	e.answered = true
	e.final = !m.IsRequest && m.StatusCode >= 200
	e.answer, e.answerAt = sess, m.Time
}

// messageSide returns which side of the dialog sent m.
func messageSide(m *trace.Message, ctag string, c *Call, have bool, cur *exchange) int {
	var s int
	if m.IsRequest {
		s = senderSide(m, ctag, m.SrcAddr(), c.Caller, c.Callee)
	} else {
		s = flip(senderSide(m, ctag, m.DstAddr(), c.Caller, c.Callee))
	}
	if s != sideUnknown {
		return s
	}
	switch {
	case m.IsRequest && isMethod(m, "INVITE") && m.ToTag() == "":
		return sideCaller
	case !m.IsRequest && isMethod(m, "INVITE") && m.StatusCode < 300:
		return sideCallee
	case have && !cur.answered:
		return flip(cur.side)
	}
	return sideCaller
}

// emit appends one Media per m-line of e that differs from the previous description.
func (mb *mediaBuilder) emit(out []Media, e *exchange) []Media {
	for k := range e.offer.Media {
		off := &e.offer.Media[k]
		var ans *sdp.Media
		if e.answered && k < len(e.answer.Media) {
			ans = &e.answer.Media[k]
		}
		if e.answered && ans == nil {
			continue // answer has fewer m-lines than the offer: nothing to say about this one
		}
		md := describe(e, off, ans)
		if k < len(mb.last) && sameMedia(&mb.last[k], &md) {
			continue
		}
		for len(mb.last) <= k {
			mb.last = append(mb.last, Media{})
		}
		mb.last[k] = md
		out = append(out, md)
	}
	return out
}

// describe builds the Media entry of one m-line.
func describe(e *exchange, off, ans *sdp.Media) Media {
	offEp := endpoint(off)
	var ansEp netip.AddrPort
	md := Media{
		Type:      off.Type,
		Offered:   off.Codecs(),
		Direction: off.Direction,
		PTime:     off.PTime,
		Secure:    off.Secure,
		Disabled:  off.Port == 0,
		Time:      e.offerAt,
	}
	md.Hold = off.OnHold()
	md.Codecs = slices.Clone(md.Offered)
	if ans != nil {
		ansEp = endpoint(ans)
		md.Time = e.answerAt
		md.Codecs = resolve(ans, off)
		md.Direction = ans.Direction
		if ans.PTime > 0 {
			md.PTime = ans.PTime
		}
		md.Secure = ans.Secure
		md.Disabled = ans.Port == 0
		md.Early = e.early
		// A sendonly answer in early media is an announcement/ringback server, not a hold.
		md.Hold = md.Hold || (ans.OnHold() && (e.final || !e.early))
	}
	if md.Disabled {
		md.Hold = false
	}
	if e.side == sideCallee {
		md.Caller, md.Callee = ansEp, offEp
	} else {
		md.Caller, md.Callee = offEp, ansEp
	}
	md.Codecs = negotiatedFirst(md.Codecs)
	return md
}

// endpoint returns the RTP endpoint of m, zero if disabled, hostname-only or
// the unspecified address of a legacy hold.
func endpoint(m *sdp.Media) netip.AddrPort {
	ep, ok := m.Endpoint()
	if !ok || ep.Addr().IsUnspecified() {
		return netip.AddrPort{}
	}
	return ep
}

// resolve returns the codec names of m; a dynamic payload type that m does not
// map is looked up in ref (the other side of the exchange).
func resolve(m, ref *sdp.Media) []string {
	if len(m.Formats) == 0 {
		return nil
	}
	out := make([]string, len(m.Formats))
	for i, f := range m.Formats {
		if f.Name == "" && f.PT >= 0 {
			for _, r := range ref.Formats {
				if r.PT == f.PT && r.Name != "" {
					f.Name = r.Name
					break
				}
			}
		}
		out[i] = f.String()
	}
	return out
}

// negotiatedFirst moves the first real codec (neither telephone-event nor
// comfort noise) to the front, keeping the relative order of the others, so
// Codecs[0] is the codec the call is expected to use.
func negotiatedFirst(names []string) []string {
	j := slices.IndexFunc(names, func(n string) bool {
		return !strings.EqualFold(n, "telephone-event") && !strings.EqualFold(n, "CN")
	})
	if j <= 0 {
		return names
	}
	first := names[j]
	copy(names[1:j+1], names[:j])
	names[0] = first
	return names
}

func sameMedia(a, b *Media) bool {
	return a.Type == b.Type && a.Caller == b.Caller && a.Callee == b.Callee &&
		a.Direction == b.Direction && a.PTime == b.PTime && a.Secure == b.Secure &&
		a.Disabled == b.Disabled && a.Hold == b.Hold &&
		slices.Equal(a.Codecs, b.Codecs) && slices.Equal(a.Offered, b.Offered)
}

// sdpText returns the SDP body of m. The common case, a plain application/sdp
// body, avoids trace.Message.SDP (which lowercases every header name it walks);
// multipart bodies go through it.
func sdpText(m *trace.Message) string {
	ct := rawHeader(m, "content-type")
	if ct == "" {
		ct = rawHeader(m, "c")
	}
	switch {
	case len(ct) >= 15 && eqFold(ct[:15], "application/sdp"):
		return m.Body()
	case len(ct) >= 10 && eqFold(ct[:10], "multipart/"):
		return m.SDP()
	}
	return ""
}
