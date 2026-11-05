package analysis

import (
	"testing"
	"time"
)

func offer() string {
	return sdpBody("10.0.0.1", 4000, "0=PCMU/8000 8=PCMA/8000 101=telephone-event/8000")
}
func answer() string { return sdpBody("10.0.1.2", 6000, "8=PCMA/8000 101=telephone-event/8000") }

// okCall is a normal answered call with BYE after talk ms.
func okCall(id string, talk int) *scenario {
	return newScenario(id).invite(0, offer()).resp(10, 100, "").resp(100, 180, "").resp(1100, 200, answer()).ack(1110).bye(1100+talk, true)
}

func TestRetransmissions(t *testing.T) {
	tests := []struct {
		name string
		s    *scenario
		cfg  Config
		want int
		sev  Severity
		text []string
	}{
		{"unanswered x4", newScenario("a").invite(0, "").invite(500, "").invite(1500, "").invite(3500, "").invite(7500, ""), Config{}, 1, Error, []string{"retransmitted 4 times without any response", "firewall"}},
		{"answered after loss", newScenario("a").invite(0, "").invite(500, "").invite(1500, "").resp(1600, 100, "").resp(1700, 200, answer()).ack(1710), Config{}, 1, Warning, []string{"before the first response", "2 times"}},
		{"single retransmit below default", newScenario("a").invite(0, "").invite(500, "").resp(600, 100, "").resp(700, 486, "").ack(710), Config{}, 0, 0, nil},
		{"threshold 1", newScenario("a").invite(0, "").invite(500, "").resp(600, 100, "").resp(700, 486, ""), Config{MinRetransmits: 1}, 1, Warning, []string{"1 time"}},
		{"clean call", okCall("a", 5000), Config{}, 0, 0, nil},
		{"response retransmitted", newScenario("a").invite(0, "").resp(10, 100, "").resp(100, 486, "").resp(600, 486, "").resp(1600, 486, "").resp(3600, 486, ""), Config{}, 1, Warning, []string{"486 Busy Here to INVITE retransmitted 3 times"}},
		{"2xx retransmission is missing-ack's job", newScenario("a").invite(0, offer()).resp(100, 200, answer()).resp(600, 200, answer()).resp(1600, 200, answer()).resp(3600, 200, answer()), Config{}, 0, 0, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := input(tc.s.messages())
			in.Config = tc.cfg
			fs := runRule(t, "sip-retransmissions", in)
			if len(fs) != tc.want {
				t.Fatalf("got %d findings: %+v", len(fs), fs)
			}
			if tc.want == 0 {
				return
			}
			f := mustOne(t, fs)
			if f.Severity != tc.sev {
				t.Errorf("severity = %v", f.Severity)
			}
			contains(t, "title+detail+hint", f.Title+f.Detail+f.Hint, tc.text...)
		})
	}
}

func TestRetransmissionsRefsAndTime(t *testing.T) {
	s := newScenario("a").invite(0, "").invite(500, "").invite(1500, "")
	f := mustOne(t, runRule(t, "sip-retransmissions", input(s.messages())))
	if len(f.Packets) != 3 || f.Packets[0] != (Ref{"t.pcap", 1}) || !f.Time.Equal(t0) || f.CallID != "a" {
		t.Errorf("finding = %+v", f)
	}
	contains(t, "detail", f.Detail, "500ms", "1s")
}

func TestNoResponse(t *testing.T) {
	reg := func(id string) *scenario {
		s := newScenario(id)
		return s.c2s(0, sg{method: "REGISTER", cseq: 1, branch: "z9hG4bK" + id}).c2s(500, sg{method: "REGISTER", cseq: 1, branch: "z9hG4bK" + id})
	}
	opt := newScenario("o").c2s(0, sg{method: "OPTIONS", cseq: 1, branch: "z9hG4bKo"})
	tests := []struct {
		name string
		msgs func() *scenario
		want int
		sev  Severity
	}{
		{"invite", func() *scenario { return newScenario("a").invite(0, "").invite(500, "").invite(1500, "") }, 1, Error},
		{"register", func() *scenario { return reg("r") }, 1, Error},
		{"options", func() *scenario { return opt }, 1, Warning},
		{"answered", func() *scenario { return okCall("a", 1000) }, 0, 0},
		{"100 trying only is in-setup", func() *scenario { return newScenario("a").invite(0, "").resp(10, 100, "") }, 0, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fs := runRule(t, "no-response", input(tc.msgs().messages()))
			if len(fs) != tc.want {
				t.Fatalf("got %+v", fs)
			}
			if tc.want == 1 {
				f := mustOne(t, fs)
				if f.Severity != tc.sev {
					t.Errorf("severity %v", f.Severity)
				}
				contains(t, "title", f.Title, "10.0.1.2:5060", "no response")
			}
		})
	}
	f := mustOne(t, runRule(t, "no-response", input(newScenario("a").invite(0, "").invite(500, "").invite(1500, "").messages())))
	contains(t, "title", f.Title, "INVITE", "3 transmissions")
	contains(t, "detail", f.Detail, "alice -> bob", "1.5s")
	if len(f.Packets) != 3 {
		t.Errorf("packets = %v", f.Packets)
	}
}

func TestCallFailed(t *testing.T) {
	fail := func(code int, extra ...string) *scenario {
		s := newScenario("a").invite(0, offer()).resp(10, 100, "")
		s.s2c(100, sg{code: code, cseq: 1, cseqM: "INVITE", branch: s.branch, toTag: s.ttag, extra: extra})
		return s.ack(110)
	}
	tests := []struct {
		name  string
		s     *scenario
		want  int
		sev   Severity
		texts []string
	}{
		{"486 busy", fail(486), 1, Warning, []string{"486 Busy Here", "callee is busy"}},
		{"503", fail(503), 1, Error, []string{"503", "Retry-After"}},
		{"403", fail(403), 1, Error, []string{"whitelisted"}},
		{"404", fail(404), 1, Warning, []string{"numbering plan"}},
		{"488", fail(488), 1, Error, []string{"codec"}},
		{"unknown 4xx class fallback", fail(499), 1, Error, []string{"Client Error"}},
		{"q850 reason", fail(480, `Reason: Q.850;cause=18;text="No user responding"`), 1, Warning, []string{"Q.850 cause 18", "did not answer the setup"}},
		{"401 is auth-failures' job", fail(401), 0, 0, nil},
		{"answered", okCall("a", 2000), 0, 0, nil},
		{"cancelled after 487", newScenario("a").invite(0, offer()).resp(10, 100, "").resp(100, 180, "").
			c2s(3000, sg{method: "CANCEL", cseq: 1, branch: "z9hG4bK-a"}).resp(3010, 487, "").ack(3020), 1, Info, []string{"cancelled by the caller", "487"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fs := runRule(t, "call-failed", input(tc.s.messages()))
			if len(fs) != tc.want {
				t.Fatalf("got %+v", fs)
			}
			if tc.want == 0 {
				return
			}
			f := mustOne(t, fs)
			if f.Severity != tc.sev {
				t.Errorf("severity %v", f.Severity)
			}
			contains(t, "text", f.Title+" "+f.Detail+" "+f.Hint, tc.texts...)
		})
	}
}

func TestCallFailedQ850(t *testing.T) {
	for _, cause := range []int{1, 16, 17, 18, 19, 21, 27, 28, 31, 34, 38, 41, 42, 102} {
		s := newScenario("a").invite(0, "").resp(10, 100, "")
		s.s2c(100, sg{code: 503, cseq: 1, cseqM: "INVITE", branch: s.branch, toTag: s.ttag, extra: []string{"Reason: Q.850;cause=" + itoa(cause)}})
		f := mustOne(t, runRule(t, "call-failed", input(s.messages())))
		contains(t, "detail", f.Detail, "Q.850 cause "+itoa(cause)+":")
	}
}

func authCall(id string, rounds int, final int, stale bool) *scenario {
	s := newScenario(id)
	for r := 0; r < rounds; r++ {
		cs := r + 1
		ex := []string(nil)
		if r > 0 {
			ex = []string{`Authorization: Digest username="alice", realm="x", nonce="n` + itoa(r) + `"`}
		}
		s.c2s(r*1000, sg{method: "REGISTER", cseq: cs, branch: "z9hG4bK" + id + itoa(r), extra: ex})
		ch := []string{`WWW-Authenticate: Digest realm="x", nonce="n` + itoa(r+1) + `"`}
		if stale {
			ch[0] += ", stale=true"
		}
		s.s2c(r*1000+50, sg{code: 401, cseq: cs, cseqM: "REGISTER", branch: "z9hG4bK" + id + itoa(r), toTag: "tt", extra: ch})
	}
	if final == 200 {
		cs := rounds + 1
		s.c2s(rounds*1000, sg{method: "REGISTER", cseq: cs, branch: "z9hG4bK" + id + "f", extra: []string{`Authorization: Digest username="alice"`}})
		s.s2c(rounds*1000+50, sg{code: 200, cseq: cs, cseqM: "REGISTER", branch: "z9hG4bK" + id + "f", toTag: "tt"})
	}
	return s
}

func TestAuthFailures(t *testing.T) {
	tests := []struct {
		name string
		s    *scenario
		want int
		sev  Severity
		text string
	}{
		{"normal challenge then 200", authCall("a", 1, 200, false), 0, 0, ""},
		{"two 401 then 200", authCall("a", 2, 200, false), 0, 0, ""},
		{"three 401 never ok", authCall("a", 3, 0, false), 1, Error, "refused 3 times (401, 401, 401)"},
		{"three 401 then ok", authCall("a", 3, 200, false), 1, Warning, "eventually accepted"},
		{"stale loop", authCall("a", 2, 0, true), 1, Error, "Stale nonce loop"},
		{"no credentials sent", func() *scenario {
			s := newScenario("a")
			for i := 0; i < 3; i++ {
				s.c2s(i*1000, sg{method: "REGISTER", cseq: i + 1, branch: "z9hG4bKr" + itoa(i)})
				s.s2c(i*1000+50, sg{code: 401, cseq: i + 1, cseqM: "REGISTER", branch: "z9hG4bKr" + itoa(i), toTag: "tt", extra: []string{`WWW-Authenticate: Digest realm="x"`}})
			}
			return s
		}(), 1, Error, "never sent credentials"},
		{"403s", func() *scenario {
			s := newScenario("a")
			for i := 0; i < 3; i++ {
				s.c2s(i*1000, sg{method: "REGISTER", cseq: i + 1, branch: "z9hG4bKr" + itoa(i)})
				s.s2c(i*1000+50, sg{code: 403, cseq: i + 1, cseqM: "REGISTER", branch: "z9hG4bKr" + itoa(i), toTag: "tt"})
			}
			return s
		}(), 1, Error, "403"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fs := runRule(t, "auth-failures", input(tc.s.messages()))
			if len(fs) != tc.want {
				t.Fatalf("got %+v", fs)
			}
			if tc.want == 0 {
				return
			}
			f := mustOne(t, fs)
			if f.Severity != tc.sev {
				t.Errorf("severity = %v", f.Severity)
			}
			contains(t, "text", f.Title+" "+f.Detail, tc.text)
		})
	}
}

func TestAuthFailuresAcrossCallIDs(t *testing.T) {
	var all = authCall("r1", 2, 0, false).messages()
	all = append(all, authCall("r2", 2, 0, false).messages()...)
	// keep order chronological per message list; Build groups by Call-ID anyway
	in := input(all)
	f := mustOne(t, runRule(t, "auth-failures", in))
	contains(t, "title", f.Title, "refused 4 times over 2 Call-IDs")
	// one of the Call-IDs eventually succeeding silences the finding
	ok := append(authCall("r1", 2, 0, false).messages(), authCall("r2", 1, 200, false).messages()...)
	if fs := runRule(t, "auth-failures", input(ok)); len(fs) != 0 {
		t.Errorf("unexpected %+v", fs)
	}
}

func TestSlowSetupAndAnswer(t *testing.T) {
	mk := func(ring, ok int) *scenario {
		return newScenario("a").invite(0, offer()).resp(20, 100, "").resp(ring, 180, "").resp(ok, 200, answer()).ack(ok+10).bye(ok+3000, true)
	}
	tests := []struct {
		name     string
		s        *scenario
		cfg      Config
		slowPDD  int
		slowAns  int
		ansSev   Severity
		pddWords string
	}{
		{"fast", mk(200, 2000), Config{}, 0, 0, 0, ""},
		{"slow pdd", mk(4500, 6000), Config{}, 1, 0, 0, "4.5s"},
		{"exactly at threshold is fine", mk(3000, 6000), Config{}, 0, 0, 0, ""},
		{"long ring only", mk(300, 15000), Config{}, 0, 1, Info, ""},
		{"long pdd and answer", mk(8000, 15000), Config{}, 1, 1, Warning, "8s"},
		{"custom thresholds", mk(1500, 4000), Config{SlowPDD: time.Second, SlowSetup: 3 * time.Second}, 1, 1, Warning, "1.5s"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := input(tc.s.messages())
			in.Config = tc.cfg
			a := runRule(t, "slow-setup", in)
			if len(a) != tc.slowPDD {
				t.Fatalf("slow-setup: %+v", a)
			}
			if tc.slowPDD == 1 {
				f := mustOne(t, a)
				contains(t, "title", f.Title, tc.pddWords)
				contains(t, "detail", f.Detail, "100 Trying after 20ms")
				if f.Severity != Warning {
					t.Error("severity")
				}
			}
			b := runRule(t, "slow-answer", in)
			if len(b) != tc.slowAns {
				t.Fatalf("slow-answer: %+v", b)
			}
			if tc.slowAns == 1 {
				if f := mustOne(t, b); f.Severity != tc.ansSev {
					t.Errorf("slow-answer severity %v", f.Severity)
				}
			}
		})
	}
}

func TestMissingACK(t *testing.T) {
	bad := newScenario("a").invite(0, offer()).resp(100, 200, answer()).resp(600, 200, answer()).resp(1600, 200, answer()).resp(3600, 200, answer())
	f := mustOne(t, runRule(t, "missing-ack", input(bad.messages())))
	contains(t, "title", f.Title, "4 times")
	contains(t, "detail", f.Detail, "3.5s")
	if f.Severity != Error || len(f.Packets) != 4 {
		t.Errorf("finding %+v", f)
	}
	good := newScenario("a").invite(0, offer()).resp(100, 200, answer()).resp(600, 200, answer()).ack(700)
	if fs := runRule(t, "missing-ack", input(good.messages())); len(fs) != 0 {
		t.Errorf("acked call reported: %+v", fs)
	}
	if fs := runRule(t, "missing-ack", input(okCall("b", 1000).messages())); len(fs) != 0 {
		t.Errorf("normal call reported: %+v", fs)
	}
	nat := newScenario("n").invite(0, offer()).s2c(100, sg{code: 200, cseq: 1, cseqM: "INVITE", branch: "z9hG4bK-n", toTag: "tt-n", sdp: answer(), extra: []string{"Contact: <sip:bob@192.168.1.5:5060>"}})
	nat.s2c(600, sg{code: 200, cseq: 1, cseqM: "INVITE", branch: "z9hG4bK-n", toTag: "tt-n", sdp: answer(), extra: []string{"Contact: <sip:bob@192.168.1.5:5060>"}})
	msgs := nat.messages()
	for i := range msgs {
		if !msgs[i].IsRequest {
			msgs[i].Contact = "<sip:bob@192.168.1.5:5060>"
		}
	}
	f = mustOne(t, runRule(t, "missing-ack", input(msgs)))
	contains(t, "hint", f.Hint, "private address")
}

func TestNoProvisional(t *testing.T) {
	slow := newScenario("a").invite(0, offer()).resp(2500, 200, answer()).ack(2510)
	f := mustOne(t, runRule(t, "no-provisional", input(slow.messages())))
	if f.Severity != Info {
		t.Errorf("severity %v", f.Severity)
	}
	contains(t, "title", f.Title, "2.5s")
	fast := newScenario("a").invite(0, offer()).resp(500, 200, answer()).ack(510)
	withTrying := newScenario("a").invite(0, offer()).resp(10, 100, "").resp(2500, 200, answer()).ack(2510)
	for name, s := range map[string]*scenario{"fast": fast, "with 100": withTrying} {
		if fs := runRule(t, "no-provisional", input(s.messages())); len(fs) != 0 {
			t.Errorf("%s: %+v", name, fs)
		}
	}
}

func TestLoopOrHops(t *testing.T) {
	s := newScenario("a").c2s(0, sg{method: "INVITE", cseq: 1, branch: "z9hG4bK-a", extra: []string{"Max-Forwards: 70"}})
	s.s2c(50, sg{code: 483, cseq: 1, cseqM: "INVITE", branch: "z9hG4bK-a", toTag: "tt", via: "SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-a, SIP/2.0/UDP 10.0.0.9:5060;branch=z9hG4bK-b"})
	f := mustOne(t, runRule(t, "loop-or-hops", input(s.messages())))
	if f.Severity != Error {
		t.Errorf("severity %v", f.Severity)
	}
	contains(t, "title", f.Title, "Routing loop")
	contains(t, "detail", f.Detail, "483 Status from", "Via chain: 10.0.0.1:5060 > 10.0.0.9:5060")

	low := newScenario("b").c2s(0, sg{method: "INVITE", cseq: 1, branch: "z9hG4bK-b", extra: []string{"Max-Forwards: 1"}})
	f = mustOne(t, runRule(t, "loop-or-hops", input(low.messages())))
	if f.Severity != Warning {
		t.Errorf("severity %v", f.Severity)
	}
	ok := newScenario("c").c2s(0, sg{method: "INVITE", cseq: 1, branch: "z9hG4bK-c", extra: []string{"Max-Forwards: 70"}})
	nomf := newScenario("d").c2s(0, sg{method: "INVITE", cseq: 1, branch: "z9hG4bK-d"})
	for _, x := range []*scenario{ok, nomf} {
		if fs := runRule(t, "loop-or-hops", input(x.messages())); len(fs) != 0 {
			t.Errorf("%+v", fs)
		}
	}
	l482 := newScenario("e").invite(0, "").resp(20, 482, "")
	f = mustOne(t, runRule(t, "loop-or-hops", input(l482.messages())))
	contains(t, "title", f.Title, "loop")
}

func TestRegisterFlapping(t *testing.T) {
	regs := func(n int, every time.Duration) []int {
		var at []int
		for i := 0; i < n; i++ {
			at = append(at, int(time.Duration(i)*every/time.Millisecond))
		}
		return at
	}
	build := func(at []int) *Input {
		var all = newScenario("x").messages()
		for i, a := range at {
			id := "reg" + itoa(i)
			s := newScenario(id)
			s.c2s(a, sg{method: "REGISTER", cseq: 1, branch: "z9hG4bK" + id, extra: []string{"Expires: 60"}})
			s.s2c(a+30, sg{code: 200, cseq: 1, cseqM: "REGISTER", branch: "z9hG4bK" + id, toTag: "tt"})
			all = append(all, s.messages()...)
		}
		return input(all)
	}
	tests := []struct {
		name string
		at   []int
		want int
	}{
		{"every 10s x6", regs(6, 10*time.Second), 1},
		{"every 10s x4", regs(4, 10*time.Second), 0},
		{"every 60s x10", regs(10, 60*time.Second), 0},
		{"every 29s x5", regs(5, 29*time.Second), 1},
		{"every 30s x6", regs(6, 30*time.Second), 0},
		{"burst then calm", append(regs(3, 5*time.Second), regs(3, 300*time.Second)[1:]...), 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fs := runRule(t, "register-flapping", build(tc.at))
			if len(fs) != tc.want {
				t.Fatalf("got %+v", fs)
			}
			if tc.want == 1 {
				f := mustOne(t, fs)
				contains(t, "detail", f.Detail, "Expires: 60", "sources: 10.0.0.1;")
				contains(t, "title", f.Title, "bob@example.com registered")
			}
		})
	}
}

func TestForkingAndHold(t *testing.T) {
	forked := newScenario("a").invite(0, offer()).resp(10, 100, "")
	forked.s2c(100, sg{code: 180, cseq: 1, cseqM: "INVITE", branch: forked.branch, toTag: "fork1"})
	forked.s2c(120, sg{code: 180, cseq: 1, cseqM: "INVITE", branch: forked.branch, toTag: "fork2"})
	forked.s2c(3000, sg{code: 200, cseq: 1, cseqM: "INVITE", branch: forked.branch, toTag: "fork2", sdp: answer()})
	forked.ack(3010)
	f := mustOne(t, runRule(t, "forking", input(forked.messages())))
	contains(t, "title", f.Title, "forked to 2 destinations")
	contains(t, "detail", f.Detail, "fork2", "[winner]", "best response 200")
	if f.Severity != Info {
		t.Error("severity")
	}
	if fs := runRule(t, "forking", input(okCall("b", 1000).messages())); len(fs) != 0 {
		t.Errorf("%+v", fs)
	}
}

func TestHoldResume(t *testing.T) {
	reinvite := func(s *scenario, at, cseq int, attr string) {
		s.c2s(at, sg{method: "INVITE", cseq: cseq, branch: "z9hG4bK-re" + itoa(cseq), toTag: s.ttag, sdp: sdpBody("10.0.0.1", 4000, "8=PCMA/8000", attr)})
		s.s2c(at+20, sg{code: 200, cseq: cseq, cseqM: "INVITE", branch: "z9hG4bK-re" + itoa(cseq), toTag: s.ttag, sdp: sdpBody("10.0.1.2", 6000, "8=PCMA/8000", map[string]string{"sendonly": "recvonly", "sendrecv": "sendrecv"}[attr])})
		s.c2s(at+30, sg{method: "ACK", cseq: cseq, branch: "z9hG4bK-ra" + itoa(cseq), toTag: s.ttag})
	}
	s := okCall("a", 20000)
	s.list = s.list[:len(s.list)-1] // drop the BYE; re-add below
	reinvite(s, 5000, 2, "sendonly")
	reinvite(s, 9000, 3, "sendrecv")
	s.bye(20000, true)
	f := mustOne(t, runRule(t, "hold-resume", input(s.messages())))
	contains(t, "detail", f.Detail, "resumed after 4s")
	contains(t, "title", f.Title, "1 time")

	open := okCall("b", 20000)
	open.list = open.list[:len(open.list)-1]
	reinvite(open, 5000, 2, "sendonly")
	f = mustOne(t, runRule(t, "hold-resume", input(open.messages())))
	contains(t, "detail", f.Detail, "never resumed")
	if fs := runRule(t, "hold-resume", input(okCall("c", 1000).messages())); len(fs) != 0 {
		t.Errorf("%+v", fs)
	}
}

func TestOrphans(t *testing.T) {
	var msgs = okCall("ok", 1000).messages()
	only := newScenario("o1").resp(0, 200, "").ack(10).bye(5000, true)
	only.list = only.list[1:] // drop the INVITE response? keep ACK+BYE only
	o2 := newScenario("o2").bye(2000, true)
	orphans := append(only.messages(), o2.messages()...)
	in := input(append(msgs, orphans...))
	f := mustOne(t, runRule(t, "orphan-messages", in))
	contains(t, "title", f.Title, "2 Call-IDs")
	contains(t, "detail", f.Detail, "BYE")
	if f.CallID != "" {
		t.Error("orphan finding must be capture-wide")
	}
	if fs := runRule(t, "orphan-messages", input(msgs)); len(fs) != 0 {
		t.Errorf("%+v", fs)
	}
	respOnly := newScenario("r").resp(0, 200, answer())
	f = mustOne(t, runRule(t, "orphan-messages", input(respOnly.messages())))
	contains(t, "detail", f.Detail, "200 OK")
}
