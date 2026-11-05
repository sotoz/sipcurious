package call

import (
	"reflect"
	"testing"
	"time"

	"github.com/sotoz/sipcurious/internal/trace"
)

const pcmuOffer = "0=PCMU 8=PCMA 101=telephone-event/8000"

func answeredCall(id string) *scenario {
	return newScenario(id).
		invite(0, sdpBody("10.0.0.1", 4000, "0=PCMU/8000 8=PCMA/8000 101=telephone-event/8000")).
		resp(10, 100, "").
		resp(100, 180, "").
		resp(2100, 200, sdpBody("10.0.1.2", 6000, "8=PCMA/8000 101=telephone-event/8000")).
		ack(2110)
}

func only(t *testing.T, calls []Call) Call {
	t.Helper()
	if len(calls) != 1 {
		t.Fatalf("got %d calls, want 1", len(calls))
	}
	return calls[0]
}

func TestStates(t *testing.T) {
	tests := []struct {
		name      string
		build     func() []trace.Message
		kind      Kind
		state     State
		code      int
		result    string
		endedBy   string
		endMethod string
	}{
		{"completed by caller", func() []trace.Message { return answeredCall("a").bye(10000, true).messages() },
			KindCall, StateCompleted, 200, "200 OK", "caller", "BYE"},
		{"completed by callee", func() []trace.Message { return answeredCall("a").bye(10000, false).messages() },
			KindCall, StateCompleted, 200, "200 OK", "callee", "BYE"},
		{"answered, no bye", func() []trace.Message { return answeredCall("a").messages() },
			KindCall, StateAnswered, 200, "200 OK", "", ""},
		{"in setup", func() []trace.Message {
			return newScenario("a").invite(0, "").resp(10, 100, "").resp(100, 180, "").messages()
		}, KindCall, StateInSetup, 0, "", "", ""},
		{"in setup 100 only", func() []trace.Message {
			return newScenario("a").invite(0, "").resp(10, 100, "").messages()
		}, KindCall, StateInSetup, 0, "", "", ""},
		{"no response", func() []trace.Message {
			return newScenario("a").invite(0, "").invite(500, "").invite(1500, "").messages()
		}, KindCall, StateNoResponse, 0, "", "", ""},
		{"cancelled with 487", func() []trace.Message {
			s := newScenario("a").invite(0, "").resp(10, 100, "").resp(100, 180, "")
			s.c2s(3000, sg{method: "CANCEL", cseq: 1, branch: s.branch})
			s.s2c(3005, sg{code: 200, cseq: 1, cseqM: "CANCEL", branch: s.branch})
			s.resp(3010, 487, "")
			return s.ack(3020).messages()
		}, KindCall, StateCancelled, 487, "487 Request Terminated", "caller", "CANCEL"},
		{"cancelled without final", func() []trace.Message {
			s := newScenario("a").invite(0, "").resp(100, 180, "")
			s.c2s(3000, sg{method: "CANCEL", cseq: 1, branch: s.branch})
			return s.messages()
		}, KindCall, StateCancelled, 0, "", "caller", "CANCEL"},
		{"487 without cancel is failed", func() []trace.Message {
			return newScenario("a").invite(0, "").resp(100, 487, "").messages()
		}, KindCall, StateFailed, 487, "487 Request Terminated", "", ""},
		{"busy", func() []trace.Message {
			return newScenario("a").invite(0, "").resp(10, 100, "").resp(300, 486, "").ack(310).messages()
		}, KindCall, StateFailed, 486, "486 Busy Here", "", ""},
		{"503", func() []trace.Message {
			return newScenario("a").invite(0, "").resp(300, 503, "").messages()
		}, KindCall, StateFailed, 503, "503 Service Unavailable", "", ""},
		{"603 decline", func() []trace.Message {
			return newScenario("a").invite(0, "").resp(300, 603, "").messages()
		}, KindCall, StateFailed, 603, "603 Decline", "", ""},
		{"redirected", func() []trace.Message {
			return newScenario("a").invite(0, "").resp(300, 302, "").ack(310).messages()
		}, KindCall, StateRedirected, 302, "302 Moved Temporarily", "", ""},
		{"answered then re-INVITE rejected stays answered", func() []trace.Message {
			s := answeredCall("a")
			s.cseq = 2
			s.c2s(5000, sg{method: "INVITE", cseq: 2, branch: "z9hG4bK-re", toTag: s.ttag})
			s.s2c(5050, sg{code: 488, cseq: 2, cseqM: "INVITE", branch: "z9hG4bK-re", toTag: s.ttag})
			return s.messages()
		}, KindCall, StateAnswered, 200, "200 OK", "", ""},
		{"responses to BYE and PRACK/UPDATE/INFO ignored", func() []trace.Message {
			s := newScenario("a").invite(0, "").resp(100, 180, "")
			s.c2s(150, sg{method: "PRACK", cseq: 2, branch: "z9hG4bK-pr", toTag: s.ttag})
			s.s2c(160, sg{code: 481, cseq: 2, cseqM: "PRACK", branch: "z9hG4bK-pr", toTag: s.ttag})
			s.c2s(170, sg{method: "UPDATE", cseq: 3, branch: "z9hG4bK-up", toTag: s.ttag})
			s.s2c(180, sg{code: 500, cseq: 3, cseqM: "UPDATE", branch: "z9hG4bK-up", toTag: s.ttag})
			return s.messages()
		}, KindCall, StateInSetup, 0, "", "", ""},
		{"BYE without prior 2xx (capture lost it)", func() []trace.Message {
			s := newScenario("a").invite(0, "").resp(100, 180, "")
			return s.bye(8000, true).messages()
		}, KindCall, StateCompleted, 0, "", "caller", "BYE"},
		{"capture started mid-call: BYE only from callee", func() []trace.Message {
			s := newScenario("a")
			s.s2c(0, sg{method: "BYE", cseq: 7, branch: "z9hG4bK-b", fromTag: "tt", toTag: "ft", from: "bob", to: "alice"})
			s.c2s(10, sg{code: 200, cseq: 7, cseqM: "BYE", branch: "z9hG4bK-b", fromTag: "tt", toTag: "ft", from: "bob", to: "alice"})
			return s.messages()
		}, KindCall, StateCompleted, 0, "", "", "BYE"},
		{"capture started mid-call: responses only", func() []trace.Message {
			s := newScenario("a").resp(0, 200, "").ack(10)
			return s.messages()
		}, KindCall, StateAnswered, 200, "200 OK", "", ""},
		{"lost 2xx but ACK seen", func() []trace.Message {
			s := newScenario("a").invite(0, "").resp(100, 180, "").ack(2000)
			return s.messages()
		}, KindCall, StateAnswered, 0, "", "", ""},
		{"ACK for a failure does not answer", func() []trace.Message {
			s := newScenario("a").invite(0, "")
			s.resp(100, 486, "")
			s.c2s(110, sg{method: "ACK", cseq: 1, branch: s.branch, toTag: s.ttag})
			return s.messages()
		}, KindCall, StateFailed, 486, "486 Busy Here", "", ""},
		{"BYE in early dialog is not completed-by-answer", func() []trace.Message {
			s := newScenario("a").invite(0, "").resp(100, 180, "")
			s.bye(500, true)
			return s.messages()
		}, KindCall, StateCompleted, 0, "", "caller", "BYE"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := tt.build()
			c := only(t, Build(m, Options{}))
			if c.Kind != tt.kind || c.State != tt.state || c.FinalCode != tt.code || c.Result != tt.result ||
				c.EndedBy != tt.endedBy || c.EndMethod != tt.endMethod {
				t.Errorf("kind=%s state=%s code=%d result=%q endedBy=%q endMethod=%q\nwant   kind=%s state=%s code=%d result=%q endedBy=%q endMethod=%q",
					c.Kind, c.State, c.FinalCode, c.Result, c.EndedBy, c.EndMethod,
					tt.kind, tt.state, tt.code, tt.result, tt.endedBy, tt.endMethod)
			}
		})
	}
}

func TestTimings(t *testing.T) {
	s := answeredCall("a").bye(12100, false)
	c := only(t, Build(s.messages(), Options{}))
	want := map[string][2]time.Duration{
		"PDD":       {c.PDD, ms(100)},
		"RingTime":  {c.RingTime, ms(2000)},
		"SetupTime": {c.SetupTime, ms(2100)},
		"TalkTime":  {c.TalkTime, ms(10000)},
		"Duration":  {c.Duration(), ms(12100)},
	}
	for k, v := range want {
		if v[0] != v[1] {
			t.Errorf("%s = %v, want %v", k, v[0], v[1])
		}
	}
	if !c.Answered.Equal(t0.Add(ms(2100))) || !c.Ended.Equal(t0.Add(ms(12100))) {
		t.Errorf("answered=%v ended=%v", c.Answered, c.Ended)
	}
	if !c.Start.Equal(t0) || !c.End.Equal(t0.Add(ms(12100))) {
		t.Errorf("start=%v end=%v", c.Start, c.End)
	}
	if c.Caller != alice || c.Callee != bob {
		t.Errorf("caller=%v callee=%v", c.Caller, c.Callee)
	}
	if c.FromUser != "alice" || c.ToUser != "bob" {
		t.Errorf("users %q %q", c.FromUser, c.ToUser)
	}
}

func TestTimingsNoRinging(t *testing.T) {
	// 200 right after 100 Trying: PDD is the time to the final response, RingTime 0.
	s := newScenario("a").invite(0, "").resp(10, 100, "").resp(300, 200, "").ack(310)
	c := only(t, Build(s.messages(), Options{}))
	if c.PDD != ms(300) || c.RingTime != 0 || c.SetupTime != ms(300) {
		t.Errorf("pdd=%v ring=%v setup=%v", c.PDD, c.RingTime, c.SetupTime)
	}
	// Rejected: PDD to the 486, RingTime 0 when no ringing.
	s = newScenario("b").invite(0, "").resp(10, 100, "").resp(400, 486, "")
	c = only(t, Build(s.messages(), Options{}))
	if c.PDD != ms(400) || c.RingTime != 0 || c.SetupTime != 0 {
		t.Errorf("pdd=%v ring=%v setup=%v", c.PDD, c.RingTime, c.SetupTime)
	}
	// Rejected after ringing: RingTime = ring -> final.
	s = newScenario("c").invite(0, "").resp(10, 100, "").resp(200, 180, "").resp(4200, 486, "")
	c = only(t, Build(s.messages(), Options{}))
	if c.PDD != ms(200) || c.RingTime != ms(4000) {
		t.Errorf("pdd=%v ring=%v", c.PDD, c.RingTime)
	}
}

func TestCancelTimings(t *testing.T) {
	s := newScenario("a").invite(0, "").resp(10, 100, "").resp(100, 180, "")
	s.c2s(3100, sg{method: "CANCEL", cseq: 1, branch: s.branch, extra: []string{"Reason: SIP ;cause=200 ;text=\"Call completed elsewhere\""}})
	s.resp(3120, 487, "")
	c := only(t, Build(s.messages(), Options{}))
	if !c.Ended.Equal(t0.Add(ms(3100))) || c.EndedBy != "caller" || c.EndMethod != "CANCEL" {
		t.Errorf("ended=%v by=%q method=%q", c.Ended, c.EndedBy, c.EndMethod)
	}
	if c.Reason != `SIP ;cause=200 ;text="Call completed elsewhere"` {
		t.Errorf("reason = %q", c.Reason)
	}
	if c.TalkTime != 0 || c.SetupTime != 0 {
		t.Errorf("talk=%v setup=%v", c.TalkTime, c.SetupTime)
	}
}

func TestReason(t *testing.T) {
	q850 := `Q.850;cause=16;text="Normal call clearing"`
	t.Run("BYE", func(t *testing.T) {
		c := only(t, Build(answeredCall("a").bye(9000, false, "Reason: "+q850).messages(), Options{}))
		if c.Reason != q850 {
			t.Errorf("reason = %q", c.Reason)
		}
	})
	t.Run("failure response", func(t *testing.T) {
		s := newScenario("a").invite(0, "")
		s.s2c(300, sg{code: 503, cseq: 1, cseqM: "INVITE", branch: s.branch, toTag: "x", extra: []string{"Reason: Q.850;cause=34"}})
		c := only(t, Build(s.messages(), Options{}))
		if c.Reason != "Q.850;cause=34" {
			t.Errorf("reason = %q", c.Reason)
		}
	})
	t.Run("multiple", func(t *testing.T) {
		c := only(t, Build(answeredCall("a").bye(9000, true, "Reason: SIP;cause=200", "Reason: Q.850;cause=16").messages(), Options{}))
		if c.Reason != "SIP;cause=200, Q.850;cause=16" {
			t.Errorf("reason = %q", c.Reason)
		}
	})
	t.Run("compact-free case insensitive", func(t *testing.T) {
		c := only(t, Build(answeredCall("a").bye(9000, true, "REASON: Q.850;cause=16").messages(), Options{}))
		if c.Reason != "Q.850;cause=16" {
			t.Errorf("reason = %q", c.Reason)
		}
	})
}

func TestEndedByNATAndProxy(t *testing.T) {
	// Messages seen on the proxy's side: the caller side shows the proxy's
	// address, so addresses alone cannot attribute the BYE; tags can.
	nat := netipAP("203.0.113.9:40000")
	t.Run("callee BYE from a different source than the INVITE destination", func(t *testing.T) {
		s := answeredCall("a")
		// callee-originated BYE arrives from an address that is neither INVITE endpoint (SBC)
		s.s2c(9000, sg{method: "BYE", cseq: 1, branch: "z9hG4bK-b", fromTag: s.ttag, toTag: s.ftag, from: "bob", to: "alice"})
		s.list[len(s.list)-1].src = nat
		c := only(t, Build(s.messages(), Options{}))
		if c.EndedBy != "callee" {
			t.Errorf("EndedBy = %q, want callee", c.EndedBy)
		}
	})
	t.Run("caller BYE from a different source than the INVITE source", func(t *testing.T) {
		s := answeredCall("a").bye(9000, true)
		s.list[len(s.list)-1].src = nat
		c := only(t, Build(s.messages(), Options{}))
		if c.EndedBy != "caller" {
			t.Errorf("EndedBy = %q, want caller", c.EndedBy)
		}
	})
	t.Run("BYE from the INVITE's destination address but with the caller's tag", func(t *testing.T) {
		// A proxy that relays the caller's BYE with the proxy's own source address
		// equal to the INVITE destination: the From tag still says caller.
		s := answeredCall("a").bye(9000, true)
		s.list[len(s.list)-1].src = bob
		c := only(t, Build(s.messages(), Options{}))
		if c.EndedBy != "caller" {
			t.Errorf("EndedBy = %q, want caller (tag direction beats addresses)", c.EndedBy)
		}
	})
	t.Run("tagless BYE falls back to addresses", func(t *testing.T) {
		s := newScenario("a").invite(0, "").resp(10, 200, "").ack(20)
		s.list = append(s.list, sg{at: ms(5000), src: bob, dst: alice, callID: "a", method: "BYE", cseq: 9, branch: "z9hG4bK-b"})
		c := only(t, Build(s.messages(), Options{}))
		if c.EndedBy != "callee" {
			t.Errorf("EndedBy = %q", c.EndedBy)
		}
	})
}

func TestRetransmissions(t *testing.T) {
	t.Run("invite retransmitted", func(t *testing.T) {
		s := newScenario("a").invite(0, "").invite(500, "").invite(1500, "").resp(1600, 100, "").resp(1700, 486, "").ack(1710)
		c := only(t, Build(s.messages(), Options{}))
		if c.Retransmissions != 2 || c.State != StateFailed || c.Attempts != 1 {
			t.Errorf("retrans=%d state=%s attempts=%d", c.Retransmissions, c.State, c.Attempts)
		}
	})
	t.Run("200 OK retransmitted and no ACK", func(t *testing.T) {
		s := newScenario("a").invite(0, "").resp(10, 100, "").resp(500, 200, "").resp(1000, 200, "").resp(2000, 200, "")
		c := only(t, Build(s.messages(), Options{}))
		if c.Retransmissions != 2 || !c.MissingACK || c.State != StateAnswered {
			t.Errorf("retrans=%d missingACK=%v state=%s", c.Retransmissions, c.MissingACK, c.State)
		}
	})
	t.Run("200 OK retransmitted but ACKed", func(t *testing.T) {
		s := newScenario("a").invite(0, "").resp(500, 200, "").resp(1000, 200, "").ack(1010)
		c := only(t, Build(s.messages(), Options{}))
		if c.Retransmissions != 1 || c.MissingACK {
			t.Errorf("retrans=%d missingACK=%v", c.Retransmissions, c.MissingACK)
		}
	})
	t.Run("same message through two hops is not a retransmission", func(t *testing.T) {
		// Capture on a proxy sees the INVITE in and out: different branch, src, dst.
		s := newScenario("a").invite(0, "")
		s.list = append(s.list, sg{at: ms(2), src: proxy, dst: bob, method: "INVITE", callID: "a", cseq: 1, fromTag: s.ftag, branch: "z9hG4bK-out"})
		c := only(t, Build(s.messages(), Options{}))
		if c.Retransmissions != 0 {
			t.Errorf("retrans = %d", c.Retransmissions)
		}
	})
	t.Run("provisional with different RSeq is distinct", func(t *testing.T) {
		s := newScenario("a").invite(0, "")
		s.resp(100, 183, "")
		s.list[len(s.list)-1].extra = []string{"RSeq: 1"}
		s.resp(200, 183, "")
		s.list[len(s.list)-1].extra = []string{"RSeq: 2"}
		s.resp(300, 183, "")
		s.list[len(s.list)-1].extra = []string{"RSeq: 2"}
		c := only(t, Build(s.messages(), Options{}))
		if c.Retransmissions != 1 {
			t.Errorf("retrans = %d", c.Retransmissions)
		}
	})
	t.Run("many messages use the map path", func(t *testing.T) {
		s := newScenario("a").invite(0, "")
		for i := range 100 {
			s.c2s(10+i, sg{method: "INFO", cseq: 2 + i, branch: "z9hG4bK-info", toTag: s.ttag})
		}
		s.c2s(500, sg{method: "INFO", cseq: 5, branch: "z9hG4bK-info", toTag: s.ttag}) // retransmission of #5
		c := only(t, Build(s.messages(), Options{}))
		if c.Retransmissions != 1 {
			t.Errorf("retrans = %d", c.Retransmissions)
		}
	})
}

func TestForking(t *testing.T) {
	s := newScenario("fork").invite(0, sdpBody("10.0.0.1", 4000, "0=PCMU/8000"))
	b2 := netipAP("10.0.2.2:5060")
	r := func(at int, src string, code int, tag string, body string) sg {
		return sg{at: ms(at), src: netipAP(src), dst: alice, callID: "fork", code: code, cseq: 1, cseqM: "INVITE", branch: s.branch, fromTag: s.ftag, toTag: tag, sdp: body}
	}
	s.list = append(s.list,
		r(50, "10.0.1.2:5060", 180, "forkA", ""),
		r(60, b2.String(), 180, "forkB", ""),
		r(2000, b2.String(), 200, "forkB", sdpBody("10.0.2.2", 7000, "0=PCMU/8000")),
		r(2500, "10.0.1.2:5060", 200, "forkA", sdpBody("10.0.1.2", 6000, "0=PCMU/8000")),
		r(2600, b2.String(), 487, "forkC", ""),
	)
	c := only(t, Build(s.messages(), Options{}))
	if c.State != StateAnswered || c.FinalCode != 200 || c.Forks != 2 { // forkC's 487 is not a 1xx/2xx fork
		t.Errorf("state=%s code=%d forks=%d", c.State, c.FinalCode, c.Forks)
	}
	if !c.Answered.Equal(t0.Add(ms(2000))) || c.SetupTime != ms(2000) {
		t.Errorf("first 2xx must win: answered=%v setup=%v", c.Answered, c.SetupTime)
	}
	if len(c.Media) != 1 || c.Media[0].Callee.String() != "10.0.2.2:7000" {
		t.Errorf("media = %+v", c.Media)
	}
}

func TestForkingAllRejected(t *testing.T) {
	s := newScenario("f2").invite(0, "")
	s.list = append(s.list,
		sg{at: ms(100), src: bob, dst: alice, callID: "f2", code: 486, cseq: 1, cseqM: "INVITE", branch: s.branch, fromTag: s.ftag, toTag: "A"},
		sg{at: ms(200), src: bob, dst: alice, callID: "f2", code: 603, cseq: 1, cseqM: "INVITE", branch: s.branch, fromTag: s.ftag, toTag: "B"},
	)
	c := only(t, Build(s.messages(), Options{}))
	if c.State != StateFailed || c.FinalCode != 603 {
		t.Errorf("state=%s code=%d: the last failure is the one the caller saw", c.State, c.FinalCode)
	}
}

func TestAuthChallenge(t *testing.T) {
	t.Run("REGISTER 401 then 200", func(t *testing.T) {
		list := []sg{
			{at: 0, src: alice, dst: proxy, method: "REGISTER", callID: "r", cseq: 1, fromTag: "f", branch: "z9hG4bK-1"},
			{at: ms(20), src: proxy, dst: alice, code: 401, callID: "r", cseq: 1, cseqM: "REGISTER", fromTag: "f", toTag: "t", branch: "z9hG4bK-1", extra: []string{"Server: Kamailio"}},
			{at: ms(40), src: alice, dst: proxy, method: "REGISTER", callID: "r", cseq: 2, fromTag: "f", branch: "z9hG4bK-2"},
			{at: ms(60), src: proxy, dst: alice, code: 200, callID: "r", cseq: 2, cseqM: "REGISTER", fromTag: "f", toTag: "t", branch: "z9hG4bK-2"},
		}
		c := only(t, Build(msgs(list...), Options{}))
		if c.Kind != KindRegistration || c.State != StateOK || c.FinalCode != 200 || c.Attempts != 2 || c.Result != "200 OK" {
			t.Errorf("kind=%s state=%s code=%d attempts=%d", c.Kind, c.State, c.FinalCode, c.Attempts)
		}
		if !reflect.DeepEqual(c.UserAgents, []string{"Kamailio"}) {
			t.Errorf("UAs = %v", c.UserAgents)
		}
	})
	t.Run("REGISTER 401 and never completed is failed", func(t *testing.T) {
		list := []sg{
			{at: 0, src: alice, dst: proxy, method: "REGISTER", callID: "r", cseq: 1, fromTag: "f", branch: "z9hG4bK-1"},
			{at: ms(20), src: proxy, dst: alice, code: 401, callID: "r", cseq: 1, cseqM: "REGISTER", fromTag: "f", toTag: "t", branch: "z9hG4bK-1"},
		}
		c := only(t, Build(msgs(list...), Options{}))
		if c.State != StateFailed || c.FinalCode != 401 {
			t.Errorf("state=%s code=%d", c.State, c.FinalCode)
		}
	})
	t.Run("REGISTER 401 then 403", func(t *testing.T) {
		list := []sg{
			{at: 0, src: alice, dst: proxy, method: "REGISTER", callID: "r", cseq: 1, fromTag: "f", branch: "z9hG4bK-1"},
			{at: ms(20), src: proxy, dst: alice, code: 401, callID: "r", cseq: 1, cseqM: "REGISTER", fromTag: "f", toTag: "t", branch: "z9hG4bK-1"},
			{at: ms(40), src: alice, dst: proxy, method: "REGISTER", callID: "r", cseq: 2, fromTag: "f", branch: "z9hG4bK-2"},
			{at: ms(60), src: proxy, dst: alice, code: 403, callID: "r", cseq: 2, cseqM: "REGISTER", fromTag: "f", toTag: "t", branch: "z9hG4bK-2"},
		}
		c := only(t, Build(msgs(list...), Options{}))
		if c.State != StateFailed || c.FinalCode != 403 || c.Attempts != 2 {
			t.Errorf("state=%s code=%d attempts=%d", c.State, c.FinalCode, c.Attempts)
		}
	})
	t.Run("REGISTER with no response", func(t *testing.T) {
		list := []sg{
			{at: 0, src: alice, dst: proxy, method: "REGISTER", callID: "r", cseq: 1, fromTag: "f", branch: "z9hG4bK-1"},
			{at: ms(500), src: alice, dst: proxy, method: "REGISTER", callID: "r", cseq: 1, fromTag: "f", branch: "z9hG4bK-1"},
		}
		c := only(t, Build(msgs(list...), Options{}))
		if c.State != StateNoResponse || c.Retransmissions != 1 {
			t.Errorf("state=%s retrans=%d", c.State, c.Retransmissions)
		}
	})
	t.Run("INVITE 407 then 200", func(t *testing.T) {
		s := newScenario("inv").invite(0, "")
		s.s2c(30, sg{code: 407, cseq: 1, cseqM: "INVITE", branch: s.branch, toTag: "tt1"})
		s.c2s(40, sg{method: "ACK", cseq: 1, branch: s.branch, toTag: "tt1"})
		s.c2s(50, sg{method: "INVITE", cseq: 2, branch: "z9hG4bK-2"})
		s.s2c(100, sg{code: 180, cseq: 2, cseqM: "INVITE", branch: "z9hG4bK-2", toTag: s.ttag})
		s.s2c(2000, sg{code: 200, cseq: 2, cseqM: "INVITE", branch: "z9hG4bK-2", toTag: s.ttag})
		s.c2s(2010, sg{method: "ACK", cseq: 2, branch: "z9hG4bK-2a", toTag: s.ttag})
		c := only(t, Build(s.messages(), Options{}))
		if c.State != StateAnswered || c.Attempts != 2 || c.FinalCode != 200 {
			t.Errorf("state=%s attempts=%d code=%d", c.State, c.Attempts, c.FinalCode)
		}
		// Timings run from the first INVITE: the caller waited for the whole thing.
		if c.SetupTime != ms(2000) || c.PDD != ms(100) {
			t.Errorf("setup=%v pdd=%v", c.SetupTime, c.PDD)
		}
	})
}

func TestNonInviteKinds(t *testing.T) {
	mk := func(method string, code int) []trace.Message {
		return msgs(
			sg{at: 0, src: alice, dst: proxy, method: method, callID: "x", cseq: 1, fromTag: "f", branch: "z9hG4bK-1"},
			sg{at: ms(20), src: proxy, dst: alice, code: code, callID: "x", cseq: 1, cseqM: method, fromTag: "f", toTag: "t", branch: "z9hG4bK-1"},
		)
	}
	tests := []struct {
		method string
		code   int
		kind   Kind
		state  State
	}{
		{"OPTIONS", 200, KindOptions, StateOK},
		{"OPTIONS", 404, KindOptions, StateFailed},
		{"OPTIONS", 302, KindOptions, StateRedirected},
		{"SUBSCRIBE", 200, KindSubscription, StateOK},
		{"SUBSCRIBE", 489, KindSubscription, StateFailed},
		{"NOTIFY", 481, KindSubscription, StateFailed},
		{"REFER", 202, KindSubscription, StateOK},
		{"MESSAGE", 200, KindMessage, StateOK},
		{"PUBLISH", 200, KindOther, StateOK},
		{"REGISTER", 200, KindRegistration, StateOK},
	}
	for _, tt := range tests {
		t.Run(tt.method+"/"+itoa(tt.code), func(t *testing.T) {
			c := only(t, Build(mk(tt.method, tt.code), Options{}))
			if c.Kind != tt.kind || c.State != tt.state || c.FinalCode != tt.code {
				t.Errorf("kind=%s state=%s code=%d", c.Kind, c.State, c.FinalCode)
			}
			if c.Method != tt.method {
				t.Errorf("method=%q", c.Method)
			}
		})
	}
	t.Run("SUBSCRIBE then NOTIFY then NOTIFY response", func(t *testing.T) {
		m := msgs(
			sg{at: 0, src: alice, dst: proxy, method: "SUBSCRIBE", callID: "s", cseq: 1, fromTag: "f", branch: "b1"},
			sg{at: ms(10), src: proxy, dst: alice, code: 200, callID: "s", cseq: 1, cseqM: "SUBSCRIBE", fromTag: "f", toTag: "t", branch: "b1"},
			sg{at: ms(20), src: proxy, dst: alice, method: "NOTIFY", callID: "s", cseq: 1, fromTag: "t", toTag: "f", branch: "b2"},
			sg{at: ms(30), src: alice, dst: proxy, code: 481, callID: "s", cseq: 1, cseqM: "NOTIFY", fromTag: "t", toTag: "f", branch: "b2"},
		)
		c := only(t, Build(m, Options{}))
		if c.State != StateOK || c.Kind != KindSubscription || c.Result != "200 OK" {
			t.Errorf("state=%s kind=%s result=%q", c.State, c.Kind, c.Result)
		}
	})
	t.Run("provisional only non-INVITE", func(t *testing.T) {
		m := msgs(
			sg{at: 0, src: alice, dst: proxy, method: "OPTIONS", callID: "o", cseq: 1, fromTag: "f", branch: "b1"},
			sg{at: ms(10), src: proxy, dst: alice, code: 100, callID: "o", cseq: 1, cseqM: "OPTIONS", fromTag: "f", branch: "b1"},
		)
		if c := only(t, Build(m, Options{})); c.State != StateNoResponse {
			t.Errorf("state=%s", c.State)
		}
	})
	t.Run("responses only", func(t *testing.T) {
		m := msgs(sg{at: 0, src: proxy, dst: alice, code: 200, callID: "o", cseq: 1, cseqM: "OPTIONS", fromTag: "f", toTag: "t", branch: "b1"})
		c := only(t, Build(m, Options{}))
		if c.Kind != KindOptions || c.Method != "" || c.State != StateOK {
			t.Errorf("kind=%s method=%q state=%s", c.Kind, c.Method, c.State)
		}
	})
}

func TestUserAgentsAndEndpoints(t *testing.T) {
	s := newScenario("a")
	s.c2s(0, sg{method: "INVITE", cseq: 1, branch: s.branch, extra: []string{"User-Agent: Yealink SIP-T46"}})
	s.s2c(10, sg{code: 100, cseq: 1, cseqM: "INVITE", branch: s.branch, extra: []string{"Server: Asterisk PBX 18"}})
	s.s2c(20, sg{code: 180, cseq: 1, cseqM: "INVITE", branch: s.branch, toTag: "t", extra: []string{"Server: Asterisk PBX 18"}})
	s.s2c(30, sg{code: 200, cseq: 1, cseqM: "INVITE", branch: s.branch, toTag: "t", extra: []string{"User-Agent: Polycom"}}) // UA in a response
	s.c2s(40, sg{method: "ACK", cseq: 1, branch: "z9hG4bK-ack", toTag: "t", extra: []string{"user-agent: Yealink SIP-T46"}})
	c := only(t, Build(s.messages(), Options{}))
	want := []string{"Yealink SIP-T46", "Asterisk PBX 18", "Polycom"}
	if !reflect.DeepEqual(c.UserAgents, want) {
		t.Errorf("UserAgents = %v, want %v", c.UserAgents, want)
	}
	if !reflect.DeepEqual(c.Endpoints, []netipAddrPort{alice, bob}) {
		t.Errorf("Endpoints = %v", c.Endpoints)
	}
}

func TestOrderingAndGrouping(t *testing.T) {
	a := newScenario("A").invite(1000, "").resp(1100, 486, "").messages()
	b := newScenario("B").invite(0, "").resp(100, 486, "").messages()
	empty := msgs(sg{at: 0, src: alice, dst: bob, method: "OPTIONS", callID: "", cseq: 1, branch: "x"})
	// Input is deliberately not chronological and interleaved; empty Call-ID is dropped.
	in := []trace.Message{a[1], b[0], empty[0], a[0], b[1]}
	orig := append([]trace.Message(nil), in...)
	calls := Build(in, Options{})
	if len(calls) != 2 || calls[0].CallID != "B" || calls[1].CallID != "A" {
		t.Fatalf("order: %+v", ids(calls))
	}
	if calls[1].Messages[0].IsRequest != true || calls[1].Messages[1].IsRequest {
		t.Errorf("messages not chronological: %v %v", calls[1].Messages[0].Info(), calls[1].Messages[1].Info())
	}
	if !reflect.DeepEqual(in, orig) {
		t.Error("Build modified its input")
	}
	// Appending to one call's Messages must not corrupt the next one.
	before := calls[1].Messages[0]
	calls[0].Messages = append(calls[0].Messages, trace.Message{CallID: "junk"})
	if !reflect.DeepEqual(calls[1].Messages[0], before) {
		t.Error("calls share capacity")
	}
	if got := Build(nil, Options{}); got != nil {
		t.Errorf("Build(nil) = %v", got)
	}
}

func TestStableForEqualTimestamps(t *testing.T) {
	s := newScenario("a").invite(0, "").resp(0, 100, "").resp(0, 180, "")
	c := only(t, Build(s.messages(), Options{}))
	var got []int
	for _, m := range c.Messages {
		got = append(got, m.Index)
	}
	if !reflect.DeepEqual(got, []int{1, 2, 3}) {
		t.Errorf("order = %v", got)
	}
}

func TestStartTieKeepsFirstSeen(t *testing.T) {
	a := newScenario("Z").invite(0, "").messages()
	b := newScenario("A").invite(0, "").messages()
	calls := Build(append(a, b...), Options{})
	if calls[0].CallID != "Z" || calls[1].CallID != "A" {
		t.Errorf("order = %v", ids(calls))
	}
}

func TestMidCallReINVITEOnly(t *testing.T) {
	s := newScenario("a")
	s.c2s(0, sg{method: "INVITE", cseq: 5, branch: "z9hG4bK-re", toTag: s.ttag})
	s.s2c(10, sg{code: 488, cseq: 5, cseqM: "INVITE", branch: "z9hG4bK-re", toTag: s.ttag})
	c := only(t, Build(s.messages(), Options{}))
	if c.State != StateAnswered {
		t.Errorf("state = %s: a re-INVITE-only capture is an established dialog", c.State)
	}
	if c.Caller.IsValid() {
		t.Errorf("Caller = %v: no initial INVITE captured", c.Caller)
	}
}

func TestRelated(t *testing.T) {
	mk := func(id, hdr string) []trace.Message {
		s := newScenario(id)
		s.c2s(0, sg{method: "INVITE", cseq: 1, branch: s.branch, extra: []string{hdr}})
		return s.messages()
	}
	var in []trace.Message
	in = append(in, mk("leg1", "X-CID: abc-123")...)
	in = append(in, mk("leg2", "x-cid: ABC-123")...)
	in = append(in, mk("leg3", "X-CID: other")...)
	in = append(in, mk("s1", "Session-ID: aaa;remote=bbb")...)
	in = append(in, mk("s2", "Session-ID: bbb;remote=aaa")...)
	calls := Build(in, Options{CorrelateHeaders: []string{"X-CID", "Session-ID"}})
	rel := map[string][]string{}
	for _, c := range calls {
		rel[c.CallID] = c.Related
	}
	want := map[string][]string{"leg1": {"leg2"}, "leg2": {"leg1"}, "leg3": nil, "s1": {"s2"}, "s2": {"s1"}}
	if !reflect.DeepEqual(rel, want) {
		t.Errorf("related = %v, want %v", rel, want)
	}
	// Without the option nothing is correlated.
	for _, c := range Build(in, Options{}) {
		if c.Related != nil {
			t.Errorf("%s: Related without option: %v", c.CallID, c.Related)
		}
	}
}

func ids(calls []Call) []string {
	out := make([]string, len(calls))
	for i, c := range calls {
		out[i] = c.CallID
	}
	return out
}

func TestChallengeThenUnansweredRetry(t *testing.T) {
	s := newScenario("inv").invite(0, "")
	s.s2c(30, sg{code: 407, cseq: 1, cseqM: "INVITE", branch: s.branch, toTag: "tt1"})
	s.c2s(40, sg{method: "ACK", cseq: 1, branch: s.branch, toTag: "tt1"})
	s.c2s(50, sg{method: "INVITE", cseq: 2, branch: "z9hG4bK-2"})
	c := only(t, Build(s.messages(), Options{}))
	if c.State != StateFailed || c.FinalCode != 407 || c.Attempts != 2 {
		t.Errorf("state=%s code=%d attempts=%d", c.State, c.FinalCode, c.Attempts)
	}
}
