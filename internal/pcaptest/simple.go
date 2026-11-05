package pcaptest

import (
	"fmt"
	"net/netip"
	"strconv"
	"time"
)

// simpleEnv holds what the non-INVITE scenarios share.
type simpleEnv struct {
	s      *scn
	h      *hop
	start  time.Time
	client netip.AddrPort
	server netip.AddrPort
	domain string
}

// newSimple builds a one hop scenario client <-> server.
func (b *Builder) newSimple(start time.Time, client, server netip.AddrPort, transport, domain, clientUA, serverUA, user, peerUser string, latency time.Duration) *simpleEnv {
	if start.IsZero() {
		start = b.start
	}
	start = start.UTC()
	if domain == "" {
		domain = "example.com"
	}
	if latency == 0 {
		latency = 3 * time.Millisecond
	}
	if !client.IsValid() {
		if b.link.IPv6 {
			client = netip.MustParseAddrPort("[2001:db8:1::10]:5060")
		} else {
			client = netip.MustParseAddrPort("10.0.1.10:5060")
		}
	}
	if !server.IsValid() {
		if b.link.IPv6 {
			server = netip.MustParseAddrPort("[2001:db8::1]:5060")
		} else {
			server = netip.MustParseAddrPort("10.0.0.1:5060")
		}
	}
	tcp := transport == "TCP"
	if tcp {
		client = netip.AddrPortFrom(client.Addr(), uint16(32768+b.rng.IntN(28000)))
	}
	if clientUA == "" {
		clientUA = "Yealink SIP-T46S 66.85.0.5"
	}
	if serverUA == "" {
		serverUA = "Kamailio (5.7.2)"
	}
	d := &dlg{callID: b.newCallID(hostOnly(client.Addr())), lTag: b.newTag(), rTag: b.newTag(),
		lURI: "sip:" + user + "@" + domain, rURI: "sip:" + peerUser + "@" + domain}
	d.cseq[sideL] = 1 + b.rng.IntN(500)
	h := &hop{l: client, r: server, lat: latency, d: d,
		contact: [2]string{"sip:" + user + "@" + hostPort(client), "sip:" + peerUser + "@" + hostPort(server)},
		ua:      [2]string{clientUA, serverUA},
		via:     [2]string{hostPort(client), hostPort(server)},
		uriHost: [2]string{hostPort(client), hostPort(server)}}
	s := &scn{b: b, hops: []*hop{h}, tcp: tcp, domain: domain}
	return &simpleEnv{s: s, h: h, start: start, client: client, server: server, domain: domain}
}

// roundTrip sends the request x and the final response code after the server
// processing delay; with noResp the request is retransmitted per timer E and
// never answered. It returns the time the client got the response (or the
// time of the last retransmission).
func (e *simpleEnv) roundTrip(x *txn, at time.Time, code int, tag string, ro respOpts, noResp bool, retrans int) time.Time {
	s := e.s
	arr := s.req(x, 0, at)
	if noResp {
		sched := timerSchedule(true)
		last := at
		for i := 0; i < len(sched) && i < retrans; i++ {
			s.req(x, 0, at.Add(sched[i]))
			last = at.Add(sched[i])
		}
		return last
	}
	return s.resp(x, 0, code, tag, ro, arr.Add(s.proc()+time.Duration(1+s.b.rng.IntN(3))*time.Millisecond))
}

// RegisterOptions configures a registration scenario. Zero values pick realistic defaults.
type RegisterOptions struct {
	// Start is the time of the first REGISTER (default Builder start).
	Start time.Time
	// Client is the phone, Server the registrar.
	Client, Server netip.AddrPort
	// User and Domain default to alice and example.com.
	User, Domain string
	// Transport is "UDP" (default) or "TCP".
	Transport string
	// Expires is the requested registration time (default 3600).
	Expires int
	// NoAuth skips the 401 challenge (open registrar).
	NoAuth bool
	// Attempts is the number of REGISTER rounds (default 1). Each round is
	// REGISTER, 401 (unless NoAuth), authenticated REGISTER, final response.
	// All rounds share the Call-ID and the CSeq keeps increasing.
	Attempts int
	// FailCode, if non-zero, is the final status of every round instead of
	// 200 (typically 403).
	FailCode int
	// Interval is the pause between rounds (default 1 s for failures, 30 min
	// for successful refreshes).
	Interval time.Duration
	// NoResponse makes the registrar silent: each round is the REGISTER
	// retransmitted Retransmits times (default 6).
	NoResponse  bool
	Retransmits int
	// ClientUA and ServerUA default to a Yealink phone and Kamailio.
	ClientUA, ServerUA string
}

// Register adds a registration scenario and returns its Call-ID.
func (b *Builder) Register(o RegisterOptions) string {
	if o.User == "" {
		o.User = "alice"
	}
	if o.Expires == 0 {
		o.Expires = 3600
	}
	if o.Attempts == 0 {
		o.Attempts = 1
	}
	if o.Interval == 0 {
		if o.FailCode != 0 {
			o.Interval = time.Second
		} else {
			o.Interval = 30 * time.Minute
		}
	}
	if o.Retransmits == 0 {
		o.Retransmits = 6
	}
	e := b.newSimple(o.Start, o.Client, o.Server, o.Transport, o.Domain, o.ClientUA, o.ServerUA, o.User, o.User, 0)
	e.h.d.rURI = e.h.d.lURI // To: the address of record
	e.h.d.rName, e.h.d.lName = "", ""
	s := e.s
	t := e.start
	for round := 0; round < o.Attempts; round++ {
		mk := func(auth string) *txn {
			x := s.newTxn("REGISTER", true, nil, nil)
			x.uri = "sip:" + e.domain
			x.contact = true
			x.extra = [][2]string{{"Expires", strconv.Itoa(o.Expires)}}
			if auth != "" {
				x.first = [][2]string{{"Authorization", auth}}
			}
			return x
		}
		tag := b.newTag()
		var back time.Time
		if o.NoResponse {
			x := mk("")
			e.roundTrip(x, t, 0, "", respOpts{}, true, o.Retransmits)
			t = t.Add(timerSchedule(true)[min(o.Retransmits, len(timerSchedule(true)))-1] + o.Interval)
			continue
		}
		if !o.NoAuth {
			x := mk("")
			nonce := b.token(24, hexch)
			chal := fmt.Sprintf(`Digest realm=%s, nonce=%s, algorithm=MD5, qop="auth"`, quoted(e.domain), quoted(nonce))
			back = e.roundTrip(x, t, 401, tag, respOpts{extra: [][2]string{{"WWW-Authenticate", chal}}}, false, 0)
			t = back.Add(time.Duration(10+b.rng.IntN(20)) * time.Millisecond)
			auth := fmt.Sprintf(`Digest username=%s, realm=%s, nonce=%s, uri=%s, response=%s, algorithm=MD5, cnonce=%s, qop=auth, nc=00000001`,
				quoted(o.User), quoted(e.domain), quoted(nonce), quoted("sip:"+e.domain), quoted(digestResponse(b)), quoted(b.token(8, hexch)))
			tag = b.newTag()
			x = mk(auth)
			back = cp2(e, x, t, o, tag)
		} else {
			back = cp2(e, mk(""), t, o, tag)
		}
		t = back.Add(o.Interval)
	}
	id := e.h.d.callID
	b.legs[id] = []string{id}
	return id
}

func cp2(e *simpleEnv, x *txn, t time.Time, o RegisterOptions, tag string) time.Time {
	code := 200
	if o.FailCode != 0 {
		code = o.FailCode
	}
	ro := respOpts{}
	if code == 200 {
		ro.hdrs = func(_ int, m *msg) {
			m.add("Contact", fmt.Sprintf("<%s>;expires=%d", e.h.contact[sideL], o.Expires))
			m.add("Date", t.UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT"))
		}
	}
	return e.roundTrip(x, t, code, tag, ro, false, 0)
}

// OptionsOptions configures an OPTIONS keep-alive scenario.
type OptionsOptions struct {
	// Start is the time of the first OPTIONS (default Builder start).
	Start time.Time
	// Client sends, Server answers.
	Client, Server netip.AddrPort
	// Domain defaults to example.com.
	Domain string
	// Transport is "UDP" (default) or "TCP".
	Transport string
	// Count pings are sent Interval apart (defaults 1 and 30 s), all with
	// the same Call-ID and increasing CSeq.
	Count    int
	Interval time.Duration
	// Status is the response code (default 200).
	Status int
	// NoResponse makes the server silent: each ping is retransmitted
	// Retransmits times (default 6).
	NoResponse  bool
	Retransmits int
	// ClientUA and ServerUA default to Kamailio and Asterisk.
	ClientUA, ServerUA string
}

// Options adds OPTIONS pings and returns their (shared) Call-ID.
func (b *Builder) Options(o OptionsOptions) string {
	if o.Count == 0 {
		o.Count = 1
	}
	if o.Interval == 0 {
		o.Interval = 30 * time.Second
	}
	if o.Status == 0 {
		o.Status = 200
	}
	if o.Retransmits == 0 {
		o.Retransmits = 6
	}
	if o.ClientUA == "" {
		o.ClientUA = "Kamailio (5.7.2)"
	}
	if o.ServerUA == "" {
		o.ServerUA = "Asterisk PBX 20.5.0"
	}
	e := b.newSimple(o.Start, o.Client, o.Server, o.Transport, o.Domain, o.ClientUA, o.ServerUA, "ping", "ping", 0)
	e.h.d.lURI = "sip:ping@" + hostPort(e.client)
	e.h.d.rURI = "sip:" + hostPort(e.server)
	t := e.start
	for i := 0; i < o.Count; i++ {
		x := e.s.newTxn("OPTIONS", true, nil, nil)
		x.uri = e.h.d.rURI
		x.accept = "application/sdp"
		var back time.Time
		ro := respOpts{hdrs: func(_ int, m *msg) { m.add("Accept", "application/sdp") }}
		back = e.roundTrip(x, t, o.Status, b.newTag(), ro, o.NoResponse, o.Retransmits)
		if o.NoResponse {
			back = back.Add(32 * time.Second)
		}
		t = t.Add(o.Interval)
		_ = back
	}
	id := e.h.d.callID
	b.legs[id] = []string{id}
	return id
}

// SubscribeOptions configures a SUBSCRIBE / NOTIFY dialog.
type SubscribeOptions struct {
	// Start is the time of the SUBSCRIBE (default Builder start).
	Start time.Time
	// Client subscribes, Server notifies.
	Client, Server netip.AddrPort
	// User (the watcher) and Target (the watched resource) default to alice and bob.
	User, Target string
	// Domain defaults to example.com.
	Domain string
	// Transport is "UDP" (default) or "TCP".
	Transport string
	// Event is the event package (default "presence"; "message-summary" gives an MWI body).
	Event string
	// Expires defaults to 3600.
	Expires int
	// Notifies is the number of NOTIFYs after the SUBSCRIBE 200 (default 2,
	// 5 s apart). The last one has Subscription-State: terminated when
	// Terminate is set.
	Notifies  int
	Terminate bool
	// Status is the SUBSCRIBE response (default 200). With a non-2xx
	// status no NOTIFY is sent.
	Status int
}

// Subscribe adds a SUBSCRIBE dialog with NOTIFYs and returns its Call-ID.
func (b *Builder) Subscribe(o SubscribeOptions) string {
	if o.User == "" {
		o.User = "alice"
	}
	if o.Target == "" {
		o.Target = "bob"
	}
	if o.Event == "" {
		o.Event = "presence"
	}
	if o.Expires == 0 {
		o.Expires = 3600
	}
	if o.Notifies == 0 {
		o.Notifies = 2
	}
	if o.Status == 0 {
		o.Status = 200
	}
	e := b.newSimple(o.Start, o.Client, o.Server, o.Transport, o.Domain, "Yealink SIP-T46S 66.85.0.5", "Asterisk PBX 20.5.0", o.User, o.Target, 0)
	s := e.s
	t := e.start
	sub := s.newTxn("SUBSCRIBE", true, nil, nil)
	sub.initial, sub.user, sub.contact = true, o.Target, true
	sub.extra = [][2]string{{"Event", o.Event}, {"Expires", strconv.Itoa(o.Expires)}}
	sub.accept = "application/pidf+xml, application/simple-message-summary"
	back := e.roundTrip(sub, t, o.Status, e.h.d.rTag, respOpts{contact: true,
		hdrs: func(_ int, m *msg) { m.add("Expires", strconv.Itoa(o.Expires)) }}, false, 0)
	if o.Status >= 300 {
		id := e.h.d.callID
		b.legs[id] = []string{id}
		return id
	}
	t = back.Add(50 * time.Millisecond)
	for i := 0; i < o.Notifies; i++ {
		n := s.newTxn("NOTIFY", false, nil, nil)
		n.est, n.contact, n.route = true, true, false
		state := fmt.Sprintf("active;expires=%d", o.Expires)
		if o.Terminate && i == o.Notifies-1 {
			state = "terminated;reason=timeout"
		}
		n.extra = [][2]string{{"Event", o.Event}, {"Subscription-State", state}}
		if o.Event == "message-summary" {
			n.ctype = "application/simple-message-summary"
			n.body = []string{"Messages-Waiting: yes\r\nMessage-Account: sip:" + o.Target + "@" + e.domain + "\r\nVoice-Message: 2/0 (0/0)\r\n"}
		} else {
			n.ctype = "application/pidf+xml"
			n.body = []string{fmt.Sprintf("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n<presence xmlns=\"urn:ietf:params:xml:ns:pidf\" entity=\"sip:%s@%s\"><tuple id=\"t1\"><status><basic>open</basic></status></tuple></presence>\r\n", o.Target, e.domain)}
		}
		back = e.roundTrip(n, t, 200, "", respOpts{}, false, 0)
		t = back.Add(5 * time.Second)
	}
	id := e.h.d.callID
	b.legs[id] = []string{id}
	return id
}

// MessageOptions configures a SIP MESSAGE (instant message).
type MessageOptions struct {
	// Start is the time of the MESSAGE (default Builder start).
	Start time.Time
	// Client sends, Server answers (a proxy or the recipient).
	Client, Server netip.AddrPort
	// From and To are user parts (defaults alice, bob).
	From, To string
	// Domain defaults to example.com.
	Domain string
	// Transport is "UDP" (default) or "TCP".
	Transport string
	// Text is the message body (default "Hello from pcaptest").
	Text string
	// Status is the response (default 200; 202 and 404 are typical).
	Status int
}

// Message adds a SIP MESSAGE and returns its Call-ID.
func (b *Builder) Message(o MessageOptions) string {
	if o.From == "" {
		o.From = "alice"
	}
	if o.To == "" {
		o.To = "bob"
	}
	if o.Text == "" {
		o.Text = "Hello from pcaptest"
	}
	if o.Status == 0 {
		o.Status = 200
	}
	e := b.newSimple(o.Start, o.Client, o.Server, o.Transport, o.Domain, "", "", o.From, o.To, 0)
	x := e.s.newTxn("MESSAGE", true, nil, nil)
	x.initial, x.user = true, o.To
	x.ctype = "text/plain"
	x.body = []string{o.Text}
	e.roundTrip(x, e.start, o.Status, b.newTag(), respOpts{}, false, 0)
	id := e.h.d.callID
	b.legs[id] = []string{id}
	return id
}
