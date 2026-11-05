package query

import (
	"fmt"
	"math/rand/v2"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/sotoz/sipcurious/internal/call"
	"github.com/sotoz/sipcurious/internal/trace"
)

// refLeaf is a condition with an independent, brute-force implementation.
type refLeaf struct {
	src  string
	msg  func(m *trace.Message) bool // message-field condition
	call func(c *call.Call) bool     // call-field condition
}

var refLeaves = []refLeaf{
	{src: "method = INVITE", msg: func(m *trace.Message) bool { return strings.EqualFold(m.Method, "INVITE") }},
	{src: "method in (bye, cancel)", msg: func(m *trace.Message) bool {
		return strings.EqualFold(m.Method, "bye") || strings.EqualFold(m.Method, "cancel")
	}},
	{src: "status >= 400", msg: func(m *trace.Message) bool { return !m.IsRequest && m.StatusCode >= 400 }},
	{src: "status = 2xx", msg: func(m *trace.Message) bool { return !m.IsRequest && m.StatusCode/100 == 2 }},
	{src: "status != 180", msg: func(m *trace.Message) bool { return m.IsRequest || m.StatusCode != 180 }},
	{src: "from ~ alice", msg: func(m *trace.Message) bool { return strings.Contains(strings.ToLower(m.From), "alice") }},
	{src: "from_user = BOB", msg: func(m *trace.Message) bool { return strings.EqualFold(trace.URIUser(m.From), "bob") }},
	{src: "to !~ carol", msg: func(m *trace.Message) bool { return !strings.Contains(strings.ToLower(m.To), "carol") }},
	{src: "src in 10.0.0.0/8", msg: func(m *trace.Message) bool {
		return netip.MustParsePrefix("10.0.0.0/8").Contains(m.Src)
	}},
	{src: "dst = 192.168.1.7", msg: func(m *trace.Message) bool { return m.Dst == netip.MustParseAddr("192.168.1.7") }},
	{src: "src not in (10.1.0.0/16, 2001:db8::/32)", msg: func(m *trace.Message) bool {
		return !netip.MustParsePrefix("10.1.0.0/16").Contains(m.Src) && !netip.MustParsePrefix("2001:db8::/32").Contains(m.Src)
	}},
	{src: "dport in 5060..5061", msg: func(m *trace.Message) bool { return m.DstPort == 5060 || m.DstPort == 5061 }},
	{src: "transport = tcp", msg: func(m *trace.Message) bool { return strings.EqualFold(m.Transport, "tcp") }},
	{src: "is_request", msg: func(m *trace.Message) bool { return m.IsRequest }},
	{src: "has_sdp", msg: func(m *trace.Message) bool { return m.SDP() != "" }},
	{src: "ua ~ cisco", msg: func(m *trace.Message) bool {
		v := m.Header("User-Agent")
		if v == "" {
			v = m.Header("Server")
		}
		return strings.Contains(strings.ToLower(v), "cisco")
	}},
	{src: "h.subject = urgent", msg: func(m *trace.Message) bool { return strings.EqualFold(m.Header("Subject"), "urgent") }},
	{src: "header.X-Tag", msg: func(m *trace.Message) bool { return m.Header("X-Tag") != "" }},
	{src: "time >= 12:00:30", msg: func(m *trace.Message) bool {
		return m.Time.Sub(m.Time.Truncate(24*time.Hour)) >= 12*time.Hour+30*time.Second
	}},
	{src: "time < 2026-03-01T12:00:10Z", msg: func(m *trace.Message) bool {
		return m.Time.Before(time.Date(2026, 3, 1, 12, 0, 10, 0, time.UTC))
	}},
	{src: "index in (2, 3, 5)", msg: func(m *trace.Message) bool { return m.Index == 2 || m.Index == 3 || m.Index == 5 }},
	{src: "\"a=sendonly\"", msg: func(m *trace.Message) bool { return strings.Contains(strings.ToLower(m.Raw), "a=sendonly") }},
	{src: "raw =~ 'cseq: [0-9]+ bye'", msg: func(m *trace.Message) bool {
		l := strings.ToLower(m.Raw)
		i := strings.Index(l, "cseq: ")
		if i < 0 {
			return false
		}
		return strings.HasSuffix(strings.SplitN(l[i:], "\r\n", 2)[0], " bye") && strings.Contains(l, "cseq: 1 bye")
	}},
	{src: "state = failed", call: func(c *call.Call) bool { return c.State == call.StateFailed }},
	{src: "duration > 5s", call: func(c *call.Call) bool { return c.End.Sub(c.Start) > 5*time.Second }},
	{src: "msgs <= 3", call: func(c *call.Call) bool { return len(c.Messages) <= 3 }},
	{src: "has_media", call: func(c *call.Call) bool { return len(c.Streams) > 0 }},
}

// refNode is a random expression tree with its source text and reference semantics.
type refNode struct {
	kind  byte // 'l' leaf, '&', '|', '!'
	leaf  *refLeaf
	kids  []*refNode
	paren bool
}

func genTree(r *rand.Rand, depth int) *refNode {
	if depth == 0 || r.IntN(4) == 0 {
		return &refNode{kind: 'l', leaf: &refLeaves[r.IntN(len(refLeaves))]}
	}
	switch r.IntN(5) {
	case 0:
		return &refNode{kind: '!', kids: []*refNode{genTree(r, depth-1)}}
	case 1, 2:
		return &refNode{kind: '&', kids: []*refNode{genTree(r, depth-1), genTree(r, depth-1)}}
	default:
		return &refNode{kind: '|', kids: []*refNode{genTree(r, depth-1), genTree(r, depth-1)}}
	}
}

// text renders the tree with precedence-aware parentheses, sometimes adding redundant ones.
func (n *refNode) text(r *rand.Rand, ctx int) string {
	switch n.kind {
	case 'l':
		return n.leaf.src
	case '!':
		kw := []string{"not ", "!", "NOT "}[r.IntN(3)]
		return kw + n.kids[0].text(r, 2)
	}
	prec, sep := 1, []string{" and ", " && ", " AND "}[r.IntN(3)]
	if n.kind == '|' {
		prec, sep = 0, []string{" or ", " || ", " Or "}[r.IntN(3)]
	}
	s := n.kids[0].text(r, prec) + sep + n.kids[1].text(r, prec+1)
	if ctx > prec || r.IntN(6) == 0 {
		return "(" + s + ")"
	}
	return s
}

func (n *refNode) evalMsg(m *trace.Message, c *call.Call) bool {
	switch n.kind {
	case 'l':
		if n.leaf.call != nil {
			return c != nil && n.leaf.call(c)
		}
		return n.leaf.msg(m)
	case '!':
		return !n.kids[0].evalMsg(m, c)
	case '&':
		return n.kids[0].evalMsg(m, c) && n.kids[1].evalMsg(m, c)
	}
	return n.kids[0].evalMsg(m, c) || n.kids[1].evalMsg(m, c)
}

func (n *refNode) evalCall(c *call.Call) bool {
	switch n.kind {
	case 'l':
		if n.leaf.call != nil {
			return n.leaf.call(c)
		}
		for i := range c.Messages {
			if n.leaf.msg(&c.Messages[i]) {
				return true
			}
		}
		return false
	case '!':
		return !n.kids[0].evalCall(c)
	case '&':
		return n.kids[0].evalCall(c) && n.kids[1].evalCall(c)
	}
	return n.kids[0].evalCall(c) || n.kids[1].evalCall(c)
}

func randomMessage(r *rand.Rand, idx int) trace.Message {
	users := []string{"alice", "Bob", "carol", "ALICE-2"}
	srcs := []string{"10.0.0.1:5060", "10.1.2.3:5070", "192.168.1.7:5060", "[2001:db8::5]:5061", "172.16.0.9:5060"}
	dsts := []string{"10.0.0.2:5060", "192.168.1.7:5061", "[2001:db8::9]:5060", "8.8.8.8:5060"}
	s := sm{
		at:     time.Duration(r.IntN(60)) * time.Second,
		src:    srcs[r.IntN(len(srcs))],
		dst:    dsts[r.IntN(len(dsts))],
		from:   users[r.IntN(len(users))],
		to:     users[r.IntN(len(users))],
		transp: []string{"UDP", "TCP", "UDP"}[r.IntN(3)],
	}
	switch r.IntN(4) {
	case 0:
		s.method, s.cseqM = []string{"INVITE", "BYE", "CANCEL", "ACK", "OPTIONS"}[r.IntN(5)], ""
	default:
		s.code = []int{100, 180, 200, 404, 486, 503}[r.IntN(6)]
		s.cseqM = []string{"INVITE", "BYE", "REGISTER"}[r.IntN(3)]
	}
	if r.IntN(3) == 0 {
		s.ua = []string{"Cisco-SIPGateway", "Yealink", "CISCO/9"}[r.IntN(3)]
	}
	if r.IntN(4) == 0 {
		s.server = "Cisco-Server"
	}
	if r.IntN(4) == 0 {
		s.extra = append(s.extra, "Subject: "+[]string{"urgent", "Urgent", "later"}[r.IntN(3)])
	}
	if r.IntN(4) == 0 {
		s.extra = append(s.extra, "X-Tag: t")
	}
	if r.IntN(4) == 0 {
		s.sdp = sdpPCMA
	}
	m := s.msg(idx)
	if r.IntN(8) == 0 {
		m.Raw = strings.Replace(m.Raw, "CSeq: 1 ", "CSeq: 1 ", 1)
	}
	return m
}

func randomCall(r *rand.Rand) *call.Call {
	n := r.IntN(6)
	c := &call.Call{State: []call.State{call.StateFailed, call.StateCompleted, call.StateAnswered}[r.IntN(3)]}
	for i := range n {
		c.Messages = append(c.Messages, randomMessage(r, i+1))
	}
	if n > 0 {
		c.Start = c.Messages[0].Time
		c.End = c.Start.Add(time.Duration(r.IntN(12)) * time.Second)
	}
	return c
}

func TestPropertyAgainstReference(t *testing.T) {
	r := rand.New(rand.NewPCG(20260301, 1))
	for _, cs := range []bool{false} {
		for iter := range 600 {
			tree := genTree(r, 4)
			src := tree.text(r, 0)
			q, err := Parse(src, Options{CaseSensitive: cs})
			if err != nil {
				t.Fatalf("iter %d: Parse(%q): %v", iter, src, err)
			}
			q2, err := Parse(q.String(), Options{})
			if err != nil {
				t.Fatalf("iter %d: re-Parse(%q) of %q: %v", iter, q.String(), src, err)
			}
			if q2.String() != q.String() {
				t.Fatalf("iter %d: String not a fixed point: %q -> %q", iter, q.String(), q2.String())
			}
			for k := range 25 {
				c := randomCall(r)
				if want, got := tree.evalCall(c), q.MatchCall(c); got != want {
					t.Fatalf("iter %d/%d: MatchCall(%q) = %v, reference %v", iter, k, src, got, want)
				}
				if got := q2.MatchCall(c); got != tree.evalCall(c) {
					t.Fatalf("iter %d/%d: normal form %q of %q disagrees", iter, k, q.String(), src)
				}
				for i := range c.Messages {
					m := c.Messages[i]
					if want, got := tree.evalMsg(&m, c), q.MatchMessage(m, c); got != want {
						t.Fatalf("iter %d/%d: MatchMessage(%q) = %v, reference %v\n%s", iter, k, src, got, want, m.Raw)
					}
					if tree.evalMsg(&m, nil) != q2.MatchMessage(m, nil) {
						t.Fatalf("iter %d/%d: nil-call MatchMessage(%q) disagrees", iter, k, src)
					}
				}
			}
		}
	}
}

func FuzzParse(f *testing.F) {
	seeds := []string{
		"", "status >= 500", "a and (b or c)", "not not a", `from ~ "x y"`, "src in (10.0.0.0/8, ::1)", "time > 10:30",
		"duration > 1m30s", `uri =~ "^sip:(\d+)@"`, "h.Subject ~ x", "status in (404, 4xx, 500..599)", "((((", "))))", `"unterminated`,
		"a && || b", "= = =", "status = 4xx or", "ТЕЛЕФОН", "a\x00b", "src = 1.2.3.4/33", "mos in 1..2", "state = fail",
		"time > 2026-03-01 12:00:01", "x" + strings.Repeat("(", 300), strings.Repeat("not ", 300) + "a",
	}
	for _, s := range seeds {
		f.Add(s, false)
		f.Add(s, true)
	}
	msg := sm{method: "INVITE", sdp: sdpPCMA, ua: "Cisco"}.msg(1)
	c := &call.Call{Messages: []trace.Message{msg}, Start: msg.Time, End: msg.Time.Add(time.Second)}
	f.Fuzz(func(t *testing.T, src string, cs bool) {
		q, err := Parse(src, Options{CaseSensitive: cs})
		if err != nil {
			se, ok := err.(*SyntaxError)
			if !ok {
				t.Fatalf("error is %T", err)
			}
			if se.Pos < 0 || se.Pos > len(src) {
				t.Fatalf("Pos %d out of range for %q", se.Pos, src)
			}
			_ = se.Pretty()
			_ = se.Error()
			return
		}
		norm := q.String()
		q2, err := Parse(norm, Options{CaseSensitive: cs})
		if err != nil {
			t.Fatalf("String() %q of %q does not re-parse: %v", norm, src, err)
		}
		if q2.String() != norm {
			t.Fatalf("String not a fixed point: %q -> %q (from %q)", norm, q2.String(), src)
		}
		if q.MatchMessage(msg, c) != q2.MatchMessage(msg, c) || q.MatchCall(c) != q2.MatchCall(c) {
			t.Fatalf("normal form %q behaves differently from %q", norm, src)
		}
	})
}

func benchMessages(n int) []trace.Message {
	r := rand.New(rand.NewPCG(1, 2))
	pool := make([]trace.Message, 4096)
	for i := range pool {
		pool[i] = randomMessage(r, i+1)
	}
	out := make([]trace.Message, n)
	for i := range out {
		out[i] = pool[i%len(pool)]
	}
	return out
}

// BenchmarkMatchMessage1M filters one million messages with a 4-term expression.
func BenchmarkMatchMessage1M(b *testing.B) {
	msgs := benchMessages(1_000_000)
	q, err := Parse("method = INVITE and from ~ alice and src in 10.0.0.0/8 and status != 503", Options{})
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	n := 0
	for range b.N {
		n = 0
		for i := range msgs {
			if q.MatchMessage(msgs[i], nil) {
				n++
			}
		}
	}
	b.ReportMetric(float64(len(msgs))*float64(b.N)/b.Elapsed().Seconds()/1e6, "Mmsg/s")
	_ = n
}

// BenchmarkMatchMessageText is a 4-term expression made of text conditions only.
func BenchmarkMatchMessageText(b *testing.B) {
	msgs := benchMessages(100_000)
	q, err := Parse("ua ~ cisco or h.subject = urgent or callid ~ zzz or \"a=sendonly\"", Options{})
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		for i := range msgs {
			q.MatchMessage(msgs[i], nil)
		}
	}
}

func BenchmarkParse(b *testing.B) {
	b.ReportAllocs()
	for range b.N {
		if _, err := Parse("method in (INVITE, BYE) and from ~ alice and (status >= 500 or src in 10.0.0.0/8) and not has_sdp", Options{}); err != nil {
			b.Fatal(err)
		}
	}
}

// TestMatchMessageDoesNotAllocate pins the zero-allocation promise for common fields.
func TestMatchMessageDoesNotAllocate(t *testing.T) {
	msgs := benchMessages(2000)
	for _, src := range []string{
		"method = INVITE and from ~ alice and src in 10.0.0.0/8 and status != 503",
		"status >= 400 or callid ~ abc or dst = 192.168.1.7 or sport = 5060",
		"from_user = bob and to_tag ~ x and branch ~ z9 and transport = tcp",
		"ua ~ cisco or h.subject = urgent or has_sdp or h.i ~ call",
		"time >= 12:00:30 and time < 2026-03-01T12:00:50Z and index > 1",
		"(src in (10.0.0.0/8, 192.168.0.0/16) or dst in 2001:db8::/32) and not is_request",
		`"a=sendonly" or uri ~ bob or via ~ udp or contact ~ 10.`,
	} {
		q := mustParse(t, src, false)
		allocs := testing.AllocsPerRun(5, func() {
			for i := range msgs {
				q.MatchMessage(msgs[i], nil)
			}
		})
		if allocs != 0 {
			t.Errorf("%q: %v allocations per run of %d messages", src, allocs, len(msgs))
		}
	}
	_ = fmt.Sprint
}
