// Package flow renders SIP call flows as ladder (sequence) diagrams: plain
// ASCII for terminals, Mermaid for Markdown/GitHub and a self-contained SVG
// for HTML reports. All three share one model (participants, arrows, header
// block, RTP footer), so they always tell the same story.
//
// Participants are the distinct signalling endpoints (address and port) of a
// call in order of first appearance, each with a role guessed from the
// User-Agent/Server header of the messages it sent. Every message is an arrow
// labelled with Info() and its time; a message that repeats an earlier one
// (same branch, CSeq, method, direction) is marked "(retrans)"; responses of
// 400 and above are drawn distinctly. All captured text (Call-ID, headers,
// reasons, User-Agent, SDP) is sanitised for every output format: control
// characters, bidi overrides and invalid UTF-8 never reach the output.
package flow

import (
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/sotoz/sipcurious/internal/call"
	"github.com/sotoz/sipcurious/internal/report"
	"github.com/sotoz/sipcurious/internal/rtp"
	"github.com/sotoz/sipcurious/internal/sdp"
	"github.com/sotoz/sipcurious/internal/trace"
)

// Options selects what a diagram shows.
type Options struct {
	UTC      bool // render absolute times in UTC instead of the local zone
	SDP      bool // annotate messages carrying SDP with codecs and media address
	Media    bool // add the correlated RTP streams (arrows and footer table)
	Absolute bool // label arrows with the time of day instead of the offset from the call start
	MaxLabel int  // longest arrow label in runes (default 48)
}

const (
	defaultMaxLabel = 48
	gapThreshold    = time.Second // a pause longer than this before a message is highlighted
	maxCodecs       = 5           // codecs listed in an SDP annotation before "+N"
	maxNote         = 64          // longest SDP annotation in runes
	maxRole         = 16          // longest role name in a participant header
	maxStreamRows   = 64          // RTP streams listed per call
)

func (o Options) maxLabel() int {
	if o.MaxLabel <= 0 {
		return defaultMaxLabel
	}
	return o.MaxLabel
}

// endpoint is one lifeline.
type endpoint struct {
	addr  netip.AddrPort
	label string // cleaned address:port
	role  string // guessed product name, "" if unknown
}

// title is the participant text on one line: "10.0.0.1:5060 (Asterisk)".
func (e endpoint) title() string {
	if e.role == "" {
		return e.label
	}
	return e.label + " (" + e.role + ")"
}

// row is one arrow of the diagram: a SIP message or an RTP stream.
type row struct {
	rtp      bool
	src, dst int    // lane indexes
	label    string // arrow text, cleaned and truncated
	note     string // optional second line (SDP annotation), cleaned
	at       time.Time
	offset   time.Duration // from the call start
	gap      time.Duration // pause since the previous message when above gapThreshold, else 0
	fail     bool          // final response >= 400
	retrans  bool
	response bool
}

// stream is one RTP stream as shown in the footer table.
type stream struct {
	leg, codec, packets, loss, jitter, mos, flow string
}

// model is a call prepared for rendering.
type model struct {
	call    call.Call
	eps     []endpoint
	rows    []row
	header  []string // header block lines
	streams []stream
	media   bool   // Options.Media was set
	none    string // footer text when media was requested but no stream is correlated
}

// retransKey identifies a message for retransmission detection; it mirrors
// the definition used by call.Build.
type retransKey struct {
	method, cseq, branch, toTag, rseq string
	code                              int
	src, dst                          netip.AddrPort
}

func newModel(c call.Call, o Options) *model {
	m := &model{call: c, media: o.Media}
	start := c.Start
	if start.IsZero() && len(c.Messages) > 0 {
		start = c.Messages[0].Time
	}
	maxLabel := o.maxLabel()

	// Lanes.
	lane := make(map[netip.AddrPort]int, 8)
	add := func(a netip.AddrPort) int {
		if i, ok := lane[a]; ok {
			return i
		}
		i := len(m.eps)
		lane[a] = i
		label := "?"
		if a.IsValid() {
			label = text(a.String(), 64)
		}
		m.eps = append(m.eps, endpoint{addr: a, label: label})
		return i
	}

	seen := make(map[retransKey]struct{}, len(c.Messages))
	m.rows = make([]row, 0, len(c.Messages)+len(c.Streams))
	var prev time.Time
	for i := range c.Messages {
		msg := &c.Messages[i]
		r := row{
			src:      add(msg.SrcAddr()),
			dst:      add(msg.DstAddr()),
			at:       msg.Time,
			offset:   msg.Time.Sub(start),
			response: !msg.IsRequest,
			fail:     !msg.IsRequest && msg.StatusCode >= 400,
		}
		r.label = text(msg.Info(), maxLabel)
		k := retransKey{method: msg.Method, cseq: msg.CSeq, branch: msg.Branch(), src: msg.SrcAddr(), dst: msg.DstAddr()}
		if !msg.IsRequest {
			k.code, k.toTag = msg.StatusCode, msg.ToTag()
			if msg.StatusCode > 100 && msg.StatusCode < 200 {
				k.rseq = msg.Header("rseq")
			}
		}
		if _, dup := seen[k]; dup {
			r.retrans = true
			r.label += " (retrans)"
		} else {
			seen[k] = struct{}{}
		}
		if i > 0 {
			if d := msg.Time.Sub(prev); d > gapThreshold {
				r.gap = d
			}
		}
		prev = msg.Time
		if o.SDP {
			r.note = sdpNote(msg)
		}
		m.rows = append(m.rows, r)
	}
	m.guessRoles(c.Messages, lane)
	if o.Media {
		m.addStreams(c, start)
	}
	m.buildHeader(start, o)
	return m
}

// guessRoles names each endpoint after the first User-Agent (requests) or
// Server (responses) header of a message it sent.
func (m *model) guessRoles(msgs []trace.Message, lane map[netip.AddrPort]int) {
	missing := len(m.eps)
	for i := range msgs {
		if missing == 0 {
			return
		}
		msg := &msgs[i]
		e := &m.eps[lane[msg.SrcAddr()]]
		if e.role != "" {
			continue
		}
		primary, other := "user-agent", "server"
		if !msg.IsRequest {
			primary, other = other, primary
		}
		ua := msg.Header(primary)
		if ua == "" {
			ua = msg.Header(other)
		}
		if e.role = roleOf(ua); e.role != "" {
			missing--
		}
	}
}

// roleOf shortens a User-Agent value to its product token ("Asterisk PBX
// 18.1" -> "Asterisk", "Linphone/4.5" -> "Linphone").
func roleOf(ua string) string {
	ua = strings.TrimSpace(clean(ua))
	if i := strings.IndexAny(ua, " /(;,"); i >= 0 {
		ua = ua[:i]
	}
	if ua == "" {
		return ""
	}
	return report.Truncate(ua, maxRole)
}

// sdpNote summarises the SDP of msg: "audio PCMU,PCMA @10.0.0.1:20000".
func sdpNote(msg *trace.Message) string {
	body := msg.SDP()
	if body == "" {
		return ""
	}
	sess, _ := sdp.Parse(body)
	var b strings.Builder
	for i, md := range sess.Media {
		if i > 0 {
			b.WriteString("; ")
		}
		b.WriteString(md.Type)
		if md.Port == 0 {
			b.WriteString(" rejected")
			continue
		}
		names := md.Codecs()
		if len(names) > maxCodecs {
			names = append(names[:maxCodecs:maxCodecs], "+"+strconv.Itoa(len(names)-maxCodecs))
		}
		if len(names) > 0 {
			b.WriteByte(' ')
			b.WriteString(strings.Join(names, ","))
		}
		if ep, ok := md.Endpoint(); ok {
			b.WriteString(" @")
			b.WriteString(ep.String())
		} else if md.Addr.IsValid() {
			b.WriteString(" @")
			b.WriteString(md.Addr.String())
		}
		if md.OnHold() {
			b.WriteString(" hold")
		} else if md.Direction != "" && md.Direction != sdp.DirSendRecv {
			b.WriteString(" " + md.Direction)
		}
	}
	if b.Len() == 0 {
		return ""
	}
	s := strings.TrimSpace(clean(b.String()))
	if s == "" {
		return ""
	}
	return report.Truncate(s, maxNote)
}

// addStreams inserts one RTP row per correlated stream at the time the stream
// started and fills the footer table. A stream becomes an arrow only when
// both of its addresses match a lane (by IP address).
func (m *model) addStreams(c call.Call, start time.Time) {
	if len(c.Streams) == 0 {
		m.none = "RTP: no streams correlated"
		return
	}
	byIP := make(map[netip.Addr]int, len(m.eps))
	for i, e := range m.eps {
		if _, ok := byIP[e.addr.Addr()]; !ok {
			byIP[e.addr.Addr()] = i
		}
	}
	streams := slices.Clone(c.Streams)
	slices.SortStableFunc(streams, func(a, b rtp.Stream) int { return a.Start.Compare(b.Start) })
	if len(streams) > maxStreamRows {
		streams = streams[:maxStreamRows]
	}
	for _, s := range streams {
		st := stream{
			leg:     text(s.Leg, 32),
			codec:   text(s.Codec, 16),
			packets: strconv.FormatUint(s.Packets, 10),
			loss:    strconv.FormatFloat(s.LossPct, 'f', 1, 64) + "%",
			jitter:  report.FormatDuration(s.JitterMean),
			mos:     "-",
			flow:    text(s.Src.String()+" -> "+s.Dst.String(), 96),
		}
		if s.Leg == "" {
			st.leg = "-"
		}
		if s.Codec == "" {
			st.codec = "?"
		}
		if s.MOS > 0 {
			st.mos = strconv.FormatFloat(s.MOS, 'f', 2, 64)
		}
		m.streams = append(m.streams, st)

		a, okA := byIP[s.Src.Addr()]
		b, okB := byIP[s.Dst.Addr()]
		if !okA || !okB {
			continue
		}
		r := row{
			rtp: true, src: a, dst: b, at: s.Start, offset: s.Start.Sub(start),
			label: "RTP " + st.codec + " " + st.packets + " pkts, loss " + st.loss,
		}
		if s.MOS > 0 {
			r.label += ", MOS " + st.mos
		}
		// Chronological position: after the last row that is not later.
		pos, _ := slices.BinarySearchFunc(m.rows, s.Start, func(r row, t time.Time) int {
			if r.at.After(t) {
				return 1
			}
			return -1
		})
		m.rows = slices.Insert(m.rows, pos, r)
	}
}

// buildHeader fills the header block shown above the diagram.
func (m *model) buildHeader(start time.Time, o Options) {
	c := m.call
	add := func(s string) { m.header = append(m.header, s) }
	add("Call-ID: " + text(c.CallID, 160))
	add("From: " + text(c.From, 80) + " -> To: " + text(c.To, 80))

	t := "Time: " + fmtStamp(start, o.UTC) + "  duration " + fmtDur(c.Duration()) +
		"  " + strconv.Itoa(len(c.Messages)) + " msgs"
	if c.Retransmissions > 0 {
		t += ", " + strconv.Itoa(c.Retransmissions) + " retrans"
	}
	add(t)

	var parts []string
	if c.State != "" {
		parts = append(parts, "State: "+text(string(c.State), 32))
	}
	if c.Result != "" {
		parts = append(parts, "Result: "+text(c.Result, 64))
	}
	for _, d := range []struct {
		name string
		v    time.Duration
	}{{"PDD", c.PDD}, {"setup", c.SetupTime}, {"talk", c.TalkTime}} {
		if d.v > 0 {
			parts = append(parts, d.name+" "+fmtDur(d.v))
		}
	}
	if c.EndedBy != "" {
		e := "ended by " + text(c.EndedBy, 16)
		if c.EndMethod != "" {
			e += " (" + text(c.EndMethod, 16) + ")"
		}
		parts = append(parts, e)
	}
	if len(parts) > 0 {
		add(strings.Join(parts, "  "))
	}
	if c.Reason != "" {
		add("Reason: " + text(c.Reason, 160))
	}
	if len(c.UserAgents) > 0 {
		uas := make([]string, 0, len(c.UserAgents))
		for _, ua := range c.UserAgents {
			uas = append(uas, text(ua, 64))
		}
		add("UA: " + strings.Join(uas, "; "))
	}
}

// fmtStamp renders the call start for the header.
func fmtStamp(t time.Time, utc bool) string {
	if t.IsZero() {
		return "?"
	}
	if utc {
		t = t.UTC()
	} else {
		t = t.Local()
	}
	return t.Format("2006-01-02T15:04:05.000Z07:00")
}

// when is the time column of a row.
func (r row) when(o Options) string {
	if o.Absolute {
		return fmtClock(r.at, o.UTC)
	}
	return fmtOffset(r.offset)
}
