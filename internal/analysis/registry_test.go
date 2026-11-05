package analysis

import (
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sotoz/sipcurious/internal/call"
	"github.com/sotoz/sipcurious/internal/report"
	"github.com/sotoz/sipcurious/internal/rtp"
	"github.com/sotoz/sipcurious/internal/trace"
)

var wantRules = []string{
	"auth-failures", "call-failed", "codec-change", "forking", "hold-resume", "long-call", "loop-or-hops",
	"media-quality", "missing-ack", "nat-suspected", "no-media", "no-provisional", "no-response",
	"one-way-media", "orphan-messages", "register-flapping", "sdp-mismatch", "sip-retransmissions",
	"slow-answer", "slow-setup", "stuck-call",
}

func TestRegistryComplete(t *testing.T) {
	rs := Rules()
	if got := IDs(); !slices.Equal(got, wantRules) {
		t.Fatalf("rules = %v\nwant     %v", got, wantRules)
	}
	titles := map[string]string{}
	docs := map[string]string{}
	for _, r := range rs {
		id := r.ID()
		if strings.ToLower(id) != id || strings.ContainsAny(id, " _") {
			t.Errorf("%s: ID not kebab-case", id)
		}
		title := r.Title()
		if title == "" || strings.ContainsAny(title, "\n") {
			t.Errorf("%s: title %q must be one non-empty line", id, title)
		}
		if other, dup := titles[title]; dup {
			t.Errorf("%s and %s share the title %q", id, other, title)
		}
		titles[title] = id
		d, ok := r.(Documented)
		if !ok || len(strings.TrimSpace(d.Doc())) < 80 {
			t.Errorf("%s: missing or too short Doc()", id)
			continue
		}
		if other, dup := docs[d.Doc()]; dup {
			t.Errorf("%s and %s share a Doc()", id, other)
		}
		docs[d.Doc()] = id
		if l, ok := Lookup(id); !ok || l.ID() != id {
			t.Errorf("Lookup(%q) failed", id)
		}
	}
	if _, ok := Lookup("nope"); ok {
		t.Error("Lookup of unknown ID succeeded")
	}
	docsMD := RuleDocs()
	for _, id := range wantRules {
		if !strings.Contains(docsMD, "## `"+id+"`") {
			t.Errorf("RuleDocs misses %s", id)
		}
	}
}

func TestRegisterPanics(t *testing.T) {
	for name, r := range map[string]Rule{"nil": nil, "empty": rule{}, "duplicate": rule{id: "no-response"}} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: no panic", name)
				}
			}()
			Register(r)
		}()
	}
}

func TestConfigDefaults(t *testing.T) {
	if got := (Config{}).WithDefaults(); got != DefaultConfig() {
		t.Errorf("zero config -> %+v, want %+v", got, DefaultConfig())
	}
	d := DefaultConfig()
	if d.SlowPDD != 3*time.Second || d.SlowSetup != 10*time.Second || d.MinRetransmits != 2 || d.MinMOS != 3.6 ||
		d.MaxLossPct != 1 || d.MaxJitter != 30*time.Millisecond || d.MaxMediaGap != time.Second || d.LongCall != 0 {
		t.Errorf("DefaultConfig = %+v", d)
	}
	c := Config{SlowPDD: time.Second, MinMOS: 4, LongCall: time.Hour}.WithDefaults()
	if c.SlowPDD != time.Second || c.MinMOS != 4 || c.LongCall != time.Hour || c.MaxLossPct != 1 {
		t.Errorf("explicit values lost: %+v", c)
	}
	if (Config{LongCall: -1}).WithDefaults().LongCall != 0 {
		t.Error("negative LongCall not cleared")
	}
}

func TestRunOptions(t *testing.T) {
	in := &Input{}
	msgs := newScenario("x").invite(0, "").messages()
	msgs = append(msgs, newScenario("y").invite(0, sdpBody("10.0.0.1", 4000, "8=PCMA/8000")).resp(10, 100, "").resp(50, 486, "").messages()...)
	in.Messages = msgs
	in.Calls = call.Build(msgs, call.Options{})

	all, err := Run(in, RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) == 0 {
		t.Fatal("expected findings")
	}
	if in.Config != (Config{}) {
		t.Error("Run modified the caller's Config")
	}
	if !slices.IsSortedFunc(all, compareFindings) {
		t.Error("findings not sorted")
	}
	for i := 1; i < len(all); i++ {
		if all[i].Severity > all[i-1].Severity {
			t.Errorf("severity order broken at %d", i)
		}
	}
	only, err := Run(in, RunOptions{Enable: []string{"call-failed"}})
	if err != nil || len(only) != 1 || only[0].Rule != "call-failed" {
		t.Errorf("Enable: %v %v", only, err)
	}
	none, err := Run(in, RunOptions{Enable: []string{"call-failed"}, Disable: []string{"call-failed"}})
	if err != nil || len(none) != 0 {
		t.Errorf("Disable: %v %v", none, err)
	}
	errs, _ := Run(in, RunOptions{MinSeverity: Error})
	for _, f := range errs {
		if f.Severity < Error {
			t.Errorf("MinSeverity leaked %v", f)
		}
	}
	for _, bad := range []RunOptions{{Enable: []string{"bogus"}}, {Disable: []string{"bogus"}}} {
		_, err := Run(in, bad)
		if err == nil || !strings.Contains(err.Error(), "bogus") || !strings.Contains(err.Error(), "call-failed") {
			t.Errorf("unknown rule error = %v", err)
		}
	}
	if _, err := Run(nil, RunOptions{}); err != nil {
		t.Errorf("nil input: %v", err)
	}
}

func TestSortOrder(t *testing.T) {
	t1, t2 := t0, t0.Add(time.Second)
	fs := []Finding{
		{Rule: "b", Severity: Info, Time: t1},
		{Rule: "a", Severity: Error, Time: t2},
		{Rule: "a", Severity: Error, Time: t1, CallID: "z"},
		{Rule: "a", Severity: Error, Time: t1, CallID: "y"},
		{Rule: "a", Severity: Error},
		{Rule: "c", Severity: Warning, Time: t1},
	}
	slices.SortStableFunc(fs, compareFindings)
	var got []string
	for _, f := range fs {
		got = append(got, f.Severity.String()+"/"+f.Rule+"/"+f.CallID+"/"+f.Time.Format("05"))
	}
	want := []string{"error/a/y/00", "error/a/z/00", "error/a//01", "error/a//00", "warning/c//00", "info/b//00"}
	if !slices.Equal(got, want) {
		t.Errorf("got %v\nwant %v", got, want)
	}
}

func TestParseSeverity(t *testing.T) {
	for in, want := range map[string]Severity{"info": Info, "WARN": Warning, "warning": Warning, " error ": Error} {
		if got, err := ParseSeverity(in); err != nil || got != want {
			t.Errorf("ParseSeverity(%q) = %v, %v", in, got, err)
		}
	}
	if _, err := ParseSeverity("fatal"); err == nil {
		t.Error("want error")
	}
}

func TestTableAndSummary(t *testing.T) {
	fs := []Finding{
		{Rule: "r1", Severity: Error, CallID: "c1", Time: t0, Title: "t1", Detail: "d", Hint: "h", Packets: []Ref{{"a.pcap", 3}, {"a.pcap", 9}}},
		{Rule: "r2", Severity: Info, Title: "t2"},
	}
	tb := Table(fs)
	if len(tb.Rows) != 2 || len(tb.Columns) != 8 {
		t.Fatalf("table = %d rows, %d cols", len(tb.Rows), len(tb.Columns))
	}
	names := []string{"Severity", "Rule", "Call-ID", "Time", "Title", "Detail", "Hint", "Packets"}
	for i, c := range tb.Columns {
		if c.Name != names[i] || c.Extra != (i >= 5) {
			t.Errorf("column %d = %+v", i, c)
		}
	}
	if tb.Columns[0].Style("error") != report.Bad || tb.Columns[0].Style("info") != report.Dim || tb.Columns[0].Style(nil) != report.None {
		t.Error("severity style")
	}
	if tb.Rows[0][7] != "a.pcap:3, a.pcap:9" {
		t.Errorf("packets cell = %v", tb.Rows[0][7])
	}
	var sb strings.Builder
	if err := report.Write(&sb, report.FormatTable, tb, report.Options{UTC: true, Extra: true}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sb.String(), "t1") {
		t.Errorf("rendered table:\n%s", sb.String())
	}
	if got := Summary(fs); got != (Counts{Errors: 1, Infos: 1}) || got.Total() != 2 || got.String() != "1 error, 0 warnings, 1 info" {
		t.Errorf("Summary = %+v %q", got, got)
	}
	if len(Table(nil).Rows) != 0 {
		t.Error("empty table")
	}
}

func TestEmptyInput(t *testing.T) {
	for _, in := range []*Input{nil, {}, {Calls: []call.Call{{}}}, {Calls: []call.Call{{Kind: call.KindCall, Messages: []trace.Message{{}}}}}} {
		if _, err := Run(in, RunOptions{}); err != nil {
			t.Error(err)
		}
	}
}

// TestHostileInput feeds seeded random garbage to every rule: nothing may panic.
func TestHostileInput(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	methods := []string{"INVITE", "ACK", "BYE", "REGISTER", "CANCEL", "OPTIONS", "", "UPDATE"}
	states := []call.State{call.StateInSetup, call.StateNoResponse, call.StateCancelled, call.StateFailed, call.StateAnswered, call.StateCompleted, call.StateOK, ""}
	kinds := []call.Kind{call.KindCall, call.KindRegistration, call.KindOptions, call.KindOther, ""}
	junk := []string{"", "Max-Forwards: x", "Via: ", "Contact: <sip:@[", "Reason: ;;;cause=", "Content-Type: application/sdp", "WWW-Authenticate: stale", "\x00\xff", "Warning: 399"}
	addr := func() netipAddrPort {
		if rng.IntN(5) == 0 {
			return netipAddrPort{}
		}
		return netipAP([]string{"10.0.0.1:5060", "8.8.8.8:5060", "[::1]:1", "100.64.1.1:9", "[2001:db8::1]:5060"}[rng.IntN(5)])
	}
	for round := 0; round < 200; round++ {
		in := &Input{Config: Config{LongCall: time.Duration(rng.IntN(3)) * time.Second}}
		for n := rng.IntN(12); n > 0; n-- {
			var raw strings.Builder
			for k := rng.IntN(5); k >= 0; k-- {
				raw.WriteString(junk[rng.IntN(len(junk))] + "\r\n")
			}
			body := ""
			if rng.IntN(2) == 0 {
				body = "v=0\r\nc=IN IP4 " + []string{"10.1.1.1", "x", "0.0.0.0", ""}[rng.IntN(4)] + "\r\nm=audio " + []string{"0", "4000", "x"}[rng.IntN(3)] + " RTP/AVP 0 8\r\n"
			}
			text := "INVITE sip:x SIP/2.0\r\n" + raw.String() + "\r\n" + body
			s, d := addr(), addr()
			m := trace.Message{
				File: "f", Index: rng.IntN(100), Time: t0.Add(time.Duration(rng.IntN(100000)) * time.Millisecond),
				Src: s.Addr(), SrcPort: s.Port(), Dst: d.Addr(), DstPort: d.Port(), IsRequest: rng.IntN(2) == 0,
				Method: methods[rng.IntN(len(methods))], StatusCode: []int{0, 100, 180, 200, 401, 407, 403, 482, 488, 500, 603, 999}[rng.IntN(12)],
				CallID: "c" + itoa(rng.IntN(4)), Via: raw.String(), Contact: raw.String(), To: raw.String(), From: raw.String(), CSeq: junk[rng.IntN(len(junk))],
				Raw: text, HeaderEnd: rng.IntN(len(text)+5) - 2,
			}
			in.Messages = append(in.Messages, m)
		}
		in.Calls = call.Build(in.Messages, call.Options{})
		// also fully random Call structs
		for n := rng.IntN(4); n > 0; n-- {
			c := call.Call{
				CallID: "r" + itoa(n), Kind: kinds[rng.IntN(len(kinds))], State: states[rng.IntN(len(states))],
				Method: methods[rng.IntN(len(methods))], FinalCode: rng.IntN(700), Forks: rng.IntN(4), MissingACK: rng.IntN(2) == 0,
				Retransmissions: rng.IntN(9), PDD: time.Duration(rng.Int64N(1e10)), SetupTime: time.Duration(rng.Int64N(2e10)),
				Start: t0, End: t0.Add(time.Duration(rng.Int64N(1e11) - 1e10)), Answered: t0.Add(time.Duration(rng.IntN(5)) * time.Second),
				Reason: junk[rng.IntN(len(junk))],
				Media:  []call.Media{{Type: "audio", Caller: addr(), Callee: addr(), Codecs: []string{"PCMU"}, Offered: []string{"x"}, Hold: rng.IntN(2) == 0}},
			}
			if len(in.Messages) > 0 {
				c.Messages = in.Messages[:rng.IntN(len(in.Messages)+1)]
			}
			in.Calls = append(in.Calls, c)
		}
		for n := rng.IntN(5); n > 0; n-- {
			s := rtp.Stream{Key: rtp.Key{Src: addr(), Dst: addr(), SSRC: rng.Uint32()}, Start: t0, End: t0.Add(time.Duration(rng.Int64N(1e11))),
				Packets: uint64(rng.IntN(500)), LossPct: rng.Float64() * 20, MOS: rng.Float64() * 5, MaxGap: time.Duration(rng.Int64N(1e10)),
				JitterMean: time.Duration(rng.Int64N(1e9)), Leg: []string{"", "caller->callee", "callee->caller"}[rng.IntN(3)]}
			in.Streams = append(in.Streams, s)
			if len(in.Calls) > 0 {
				k := rng.IntN(len(in.Calls))
				in.Calls[k].Streams = append(in.Calls[k].Streams, s)
			}
		}
		if _, err := Run(in, RunOptions{}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestStatusKnowledge(t *testing.T) {
	for code := 400; code <= 606; code++ {
		if info, ok := statusTable[code]; ok && (info.Meaning == "" || info.Causes == "" || info.Check == "") {
			t.Errorf("%d: incomplete entry %+v", code, info)
		}
	}
	for _, code := range []int{400, 401, 403, 404, 407, 408, 480, 481, 482, 483, 486, 487, 488, 491, 500, 502, 503, 504, 600, 603, 606} {
		if _, ok := statusTable[code]; !ok {
			t.Errorf("status %d missing", code)
		}
	}
	if Status(499).Meaning != "Client Error" || Status(599).Meaning != "Server Error" || Status(699).Meaning != "Global Failure" || Status(200) != (StatusInfo{}) {
		t.Error("class fallback")
	}
	for _, c := range []int{1, 16, 17, 18, 19, 21, 27, 28, 31, 34, 38, 41, 42, 102} {
		if Q850(c) == "" {
			t.Errorf("Q.850 %d unknown", c)
		}
	}
	if Q850(999) != "" {
		t.Error("Q.850 999 should be unknown")
	}
	tests := []struct {
		in    string
		proto string
		cause int
		ok    bool
	}{
		{`Q.850;cause=17;text="User busy"`, "Q.850", 17, true},
		{`SIP;cause=200;text="Call completed elsewhere", Q.850;cause=16`, "Q.850", 16, true},
		{`SIP ;cause=487`, "SIP", 487, true},
		{`Q.850;text=x`, "", 0, false},
		{``, "", 0, false},
		{`;;;cause=`, "", 0, false},
	}
	for _, tc := range tests {
		p, c, _, ok := reasonCause(tc.in)
		if ok != tc.ok || (ok && (p != tc.proto || c != tc.cause)) {
			t.Errorf("reasonCause(%q) = %q %d %v", tc.in, p, c, ok)
		}
	}
}
