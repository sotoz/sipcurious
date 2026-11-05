package analysis

import (
	"strings"
	"testing"
	"time"

	"github.com/sotoz/sipcurious/internal/rtp"
)

const (
	cRTP = "10.0.0.1:4000"
	sRTP = "10.0.1.2:6000"
)

// both returns the two healthy streams of okCall(…, talk).
func both(talk int) []rtp.Stream {
	return []rtp.Stream{
		mkStream(cRTP, sRTP, ms(1100), ms(1100+talk), 1),
		mkStream(sRTP, cRTP, ms(1150), ms(1100+talk), 2),
	}
}

func TestNoMedia(t *testing.T) {
	other := mkStream("9.9.9.9:1000", "9.9.9.8:2000", 0, ms(5000), 9)
	f := mustOne(t, runRule(t, "no-media", input(okCall("a", 10000).messages(), other)))
	if f.Severity != Error {
		t.Errorf("severity %v", f.Severity)
	}
	contains(t, "detail", f.Detail, "10.0.0.1:4000", "10.0.1.2:6000", "1 RTP streams")
	contains(t, "title", f.Title, "PCMA")

	// no RTP anywhere in the capture: one info finding, not one error per call
	fs := runRule(t, "no-media", input(append(okCall("a", 10000).messages(), okCall("b", 10000).messages()...)))
	f = mustOne(t, fs)
	if f.Severity != Info || f.CallID != "" {
		t.Errorf("sip-only capture: %+v", f)
	}
	contains(t, "title", f.Title, "2 calls were")

	tests := []struct {
		name string
		in   *Input
	}{
		{"media present", input(okCall("a", 10000).messages(), both(10000)...)},
		{"too short", input(okCall("a", 500).messages(), other)},
		{"never answered", input(newScenario("a").invite(0, offer()).resp(10, 100, "").resp(100, 486, "").messages(), other)},
		{"on hold", input(newScenario("a").invite(0, sdpBody("10.0.0.1", 4000, "8=PCMA/8000", "sendonly")).resp(100, 200, sdpBody("10.0.1.2", 6000, "8=PCMA/8000", "recvonly")).ack(110).bye(9000, true).messages(), other)},
		{"media disabled", input(newScenario("a").invite(0, offer()).resp(100, 200, "v=0\r\nc=IN IP4 10.0.1.2\r\nm=audio 0 RTP/AVP 8\r\n").ack(110).bye(9000, true).messages(), other)},
	}
	for _, tc := range tests {
		if fs := runRule(t, "no-media", tc.in); len(fs) != 0 {
			t.Errorf("%s: %+v", tc.name, fs)
		}
	}
}

func TestOneWayMedia(t *testing.T) {
	msgs := okCall("a", 10000).messages()
	fwdOnly := input(msgs, both(10000)[0])
	f := mustOne(t, runRule(t, "one-way-media", fwdOnly))
	if f.Severity != Error {
		t.Errorf("severity %v", f.Severity)
	}
	contains(t, "title", f.Title, "only caller->callee", "nothing callee->caller")
	contains(t, "detail", f.Detail, "10.0.1.2:6000", "10.0.0.1:4000", "capture point", "500 packets")
	contains(t, "hint", f.Hint, "callee")

	revOnly := input(msgs, both(10000)[1])
	f = mustOne(t, runRule(t, "one-way-media", revOnly))
	contains(t, "title", f.Title, "only callee->caller", "nothing caller->callee")

	for name, in := range map[string]*Input{
		"both":      input(msgs, both(10000)...),
		"none":      input(msgs),
		"too short": input(okCall("a", 400).messages(), both(400)[0]),
	} {
		if fs := runRule(t, "one-way-media", in); len(fs) != 0 {
			t.Errorf("%s: %+v", name, fs)
		}
	}
	// recvonly/sendonly negotiation is legitimately one-way
	oneway := newScenario("o").invite(0, sdpBody("10.0.0.1", 4000, "8=PCMA/8000", "sendonly")).resp(100, 200, sdpBody("10.0.1.2", 6000, "8=PCMA/8000", "recvonly")).ack(110).bye(9000, true)
	if fs := runRule(t, "one-way-media", input(oneway.messages(), both(9000)[0])); len(fs) != 0 {
		t.Errorf("sendonly call: %+v", fs)
	}
}

func TestMediaQuality(t *testing.T) {
	msgs := okCall("a", 10000).messages()
	mod := func(fn func(s *rtp.Stream)) *Input {
		st := both(10000)
		fn(&st[0])
		return input(msgs, st...)
	}
	tests := []struct {
		name string
		in   *Input
		want int
		sev  Severity
		text string
	}{
		{"healthy", input(msgs, both(10000)...), 0, 0, ""},
		{"low MOS", mod(func(s *rtp.Stream) { s.MOS = 3.3 }), 1, Warning, "MOS 3.3"},
		{"very low MOS", mod(func(s *rtp.Stream) { s.MOS = 2.5 }), 1, Error, "MOS 2.5"},
		{"loss 2%", mod(func(s *rtp.Stream) { s.LossPct, s.Lost = 2, 10 }), 1, Warning, "loss 2.0%"},
		{"loss 8%", mod(func(s *rtp.Stream) { s.LossPct, s.Lost = 8, 40 }), 1, Error, "loss 8.0%"},
		{"loss at threshold", mod(func(s *rtp.Stream) { s.LossPct = 1 }), 0, 0, ""},
		{"jitter 45ms", mod(func(s *rtp.Stream) { s.JitterMean = 45 * time.Millisecond }), 1, Warning, "jitter 45ms"},
		{"jitter 100ms", mod(func(s *rtp.Stream) { s.JitterMean = 100 * time.Millisecond }), 1, Error, "jitter 100ms"},
		{"gap 2s", mod(func(s *rtp.Stream) { s.MaxGap = 2 * time.Second }), 1, Warning, "gap 2s"},
		{"gap 6s", mod(func(s *rtp.Stream) { s.MaxGap = 6 * time.Second }), 1, Error, "gap 6s"},
		{"mos unknown (0) is not low", mod(func(s *rtp.Stream) { s.MOS = 0 }), 0, 0, ""},
		{"tiny stream ignored", mod(func(s *rtp.Stream) { s.Packets, s.MOS = 5, 1 }), 0, 0, ""},
		{"all at once", mod(func(s *rtp.Stream) {
			s.MOS, s.LossPct, s.JitterMean, s.MaxGap = 3.3, 3, 50*time.Millisecond, 2*time.Second
		}), 1, Warning, "MOS 3.3, loss 3.0%, jitter 50ms, gap 2s"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fs := runRule(t, "media-quality", tc.in)
			if len(fs) != tc.want {
				t.Fatalf("got %+v", fs)
			}
			if tc.want == 0 {
				return
			}
			f := mustOne(t, fs)
			if f.Severity != tc.sev || f.CallID != "a" {
				t.Errorf("finding = %+v", f)
			}
			contains(t, "title", f.Title, tc.text, "caller->callee")
			contains(t, "detail", f.Detail, "SSRC 0x1", "PCMA", "Measured at the capture point only")
		})
	}
	// custom thresholds and an uncorrelated stream
	bad := mkStream("1.1.1.1:1", "2.2.2.2:2", 0, ms(5000), 7)
	bad.LossPct = 0.5
	in := &Input{Streams: []rtp.Stream{bad}, Config: Config{MaxLossPct: 0.2}}
	f := mustOne(t, runRule(t, "media-quality", in))
	contains(t, "title", f.Title, "uncorrelated", "loss 0.5%")
	if f.CallID != "" {
		t.Error("uncorrelated stream has no call")
	}
	// RTCP numbers are quoted
	bad.RTCP = rtp.RTCPSummary{Reports: 3, MaxFractionLost: 7.5, MaxJitter: 40 * time.Millisecond}
	f = mustOne(t, runRule(t, "media-quality", &Input{Streams: []rtp.Stream{bad}, Config: Config{MaxLossPct: 0.2}}))
	contains(t, "detail", f.Detail, "RTCP reports (3)", "7.5%")
}

func TestSDPMismatch(t *testing.T) {
	reject := func(code int, body string, extra ...string) *scenario {
		s := newScenario("a").invite(0, sdpBody("10.0.0.1", 4000, "18=G729/8000 101=telephone-event/8000")).resp(10, 100, "")
		s.s2c(100, sg{code: code, cseq: 1, cseqM: "INVITE", branch: s.branch, toTag: s.ttag, sdp: body, extra: extra})
		return s.ack(110)
	}
	f := mustOne(t, runRule(t, "sdp-mismatch", input(reject(488, "", "Warning: 304 pbx \"Media type not available\"").messages())))
	if f.Severity != Error {
		t.Error("severity")
	}
	contains(t, "detail", f.Detail, "G729", "Warning: 304", "10.0.1.2:5060")
	f = mustOne(t, runRule(t, "sdp-mismatch", input(reject(488, sdpBody("10.0.1.2", 6000, "0=PCMU/8000")).messages())))
	contains(t, "detail", f.Detail, "acceptable per its SDP", "PCMU")
	mustOne(t, runRule(t, "sdp-mismatch", input(reject(606, "").messages())))
	if fs := runRule(t, "sdp-mismatch", input(reject(486, "").messages())); len(fs) != 0 {
		t.Errorf("486 is not an SDP problem: %+v", fs)
	}

	noCommon := newScenario("n").invite(0, sdpBody("10.0.0.1", 4000, "18=G729/8000 101=telephone-event/8000")).resp(100, 200, sdpBody("10.0.1.2", 6000, "0=PCMU/8000 101=telephone-event/8000")).ack(110)
	f = mustOne(t, runRule(t, "sdp-mismatch", input(noCommon.messages())))
	contains(t, "title", f.Title, "not offered")
	contains(t, "detail", f.Detail, "G729", "PCMU")

	allOff := newScenario("z").invite(0, offer()).resp(100, 200, "v=0\r\nc=IN IP4 10.0.1.2\r\nm=audio 0 RTP/AVP 8\r\n").ack(110)
	f = mustOne(t, runRule(t, "sdp-mismatch", input(allOff.messages())))
	contains(t, "title", f.Title, "every media line was rejected")

	for name, s := range map[string]*scenario{"fine": okCall("a", 1000), "no sdp": newScenario("b").invite(0, "").resp(100, 200, "").ack(110)} {
		if fs := runRule(t, "sdp-mismatch", input(s.messages())); len(fs) != 0 {
			t.Errorf("%s: %+v", name, fs)
		}
	}
}

func TestCodecChange(t *testing.T) {
	// 183 early media with PCMU, final answer PCMA
	s := newScenario("a").invite(0, sdpBody("10.0.0.1", 4000, "0=PCMU/8000 8=PCMA/8000")).resp(10, 100, "").
		resp(200, 183, sdpBody("10.0.1.2", 6000, "0=PCMU/8000")).
		resp(3000, 200, sdpBody("10.0.1.2", 6000, "8=PCMA/8000")).ack(3010)
	f := mustOne(t, runRule(t, "codec-change", input(s.messages())))
	if f.Severity != Info {
		t.Error("severity")
	}
	contains(t, "title", f.Title, "pcmu -> pcma")
	// stable codec: no finding
	if fs := runRule(t, "codec-change", input(okCall("b", 3000).messages())); len(fs) != 0 {
		t.Errorf("%+v", fs)
	}
	// re-INVITE switching the codec
	r := okCall("c", 20000)
	r.list = r.list[:len(r.list)-1]
	r.c2s(5000, sg{method: "INVITE", cseq: 2, branch: "z9hG4bK-re", toTag: r.ttag, sdp: sdpBody("10.0.0.1", 4000, "0=PCMU/8000")})
	r.s2c(5020, sg{code: 200, cseq: 2, cseqM: "INVITE", branch: "z9hG4bK-re", toTag: r.ttag, sdp: sdpBody("10.0.1.2", 6000, "0=PCMU/8000")})
	r.ack(5030)
	f = mustOne(t, runRule(t, "codec-change", input(r.messages())))
	contains(t, "detail", f.Detail, "pcma -> pcmu")
}

func TestNATSuspected(t *testing.T) {
	pub := netipAP("203.0.113.7:5060")
	nat := func() *scenario {
		s := newScenario("n")
		s.caller = pub
		s.invite(0, sdpBody("192.168.1.10", 4000, "8=PCMA/8000"))
		s.list[0].extra = []string{"Contact: <sip:alice@192.168.1.10:5060>"}
		return s.resp(10, 100, "").resp(1100, 200, sdpBody("10.0.1.2", 6000, "8=PCMA/8000")).ack(1110)
	}
	msgs := nat().messages()
	msgs[0].Contact = "<sip:alice@192.168.1.10:5060>"
	msgs[0].Via = "SIP/2.0/UDP 192.168.1.10:5060;branch=z9hG4bK-n"
	f := mustOne(t, runRule(t, "nat-suspected", input(msgs)))
	if f.Severity != Warning {
		t.Errorf("severity %v", f.Severity)
	}
	contains(t, "detail", f.Detail, "Contact <sip:alice@192.168.1.10:5060>", "Via 192.168.1.10", "SDP audio 192.168.1.10/4000", "203.0.113.7")
	if len(f.Packets) == 0 || f.Packets[0].Index != 1 {
		t.Errorf("packets %v", f.Packets)
	}

	// private on both ends of a private network: no NAT
	if fs := runRule(t, "nat-suspected", input(okCall("p", 1000).messages())); len(fs) != 0 {
		t.Errorf("LAN call: %+v", fs)
	}
	// public contact from public host: fine
	clean := newScenario("c")
	clean.caller = pub
	clean.invite(0, sdpBody("203.0.113.7", 4000, "8=PCMA/8000")).resp(10, 100, "")
	m := clean.messages()
	m[0].Contact = "<sip:alice@203.0.113.7:5060>"
	m[1].Via = "SIP/2.0/UDP 203.0.113.7:5060;branch=z9hG4bK-c" // a real response echoes the request's Via
	if fs := runRule(t, "nat-suspected", input(m)); len(fs) != 0 {
		t.Errorf("public call: %+v", fs)
	}

	// response to a public client whose private Via has no received
	resp := newScenario("r")
	resp.caller = pub
	resp.invite(0, "").resp(10, 100, "")
	rm := resp.messages()
	rm[1].Via = "SIP/2.0/UDP 192.168.1.10:5060;branch=z9hG4bK-r"
	f = mustOne(t, runRule(t, "nat-suspected", input(rm)))
	contains(t, "detail", f.Detail, "no received parameter")
	rm[1].Via += ";received=203.0.113.7"
	if fs := runRule(t, "nat-suspected", input(rm)); len(fs) != 0 {
		t.Errorf("received present: %+v", fs)
	}

	// media: SDP announced private, stream arrives from the public mapping
	media := okCall("m", 10000).messages()
	st := mkStream("203.0.113.7:30000", sRTP, ms(1100), ms(11000), 1)
	in := input(media, st)
	in.Calls[0].Streams = []rtp.Stream{func() rtp.Stream { s := st; s.Leg, s.CallID = "caller->callee", "m"; return s }()}
	f = mustOne(t, runRule(t, "nat-suspected", in))
	if f.Severity != Info {
		t.Errorf("media NAT severity %v", f.Severity)
	}
	contains(t, "detail", f.Detail, "203.0.113.7:30000", "10.0.0.1:4000")
}

func TestStuckAndLongCall(t *testing.T) {
	// call a: answered, never ended, media stops at 20s; call b keeps the capture running to 2 minutes.
	a := newScenario("a").invite(0, offer()).resp(100, 200, answer()).ack(110)
	b := newScenario("b").invite(0, sdpBody("10.0.0.1", 4100, "8=PCMA/8000")).resp(100, 200, sdpBody("10.0.1.2", 6100, "8=PCMA/8000")).ack(110).bye(120000, true)
	msgs := append(a.messages(), b.messages()...)
	msgs[0].Index = 1
	bStreams := []rtp.Stream{mkStream("10.0.0.1:4100", "10.0.1.2:6100", ms(100), ms(120000), 5), mkStream("10.0.1.2:6100", "10.0.0.1:4100", ms(100), ms(120000), 6)}
	aStreams := []rtp.Stream{mkStream(cRTP, sRTP, ms(100), ms(20000), 1), mkStream(sRTP, cRTP, ms(150), ms(20000), 2)}
	f := mustOne(t, runRule(t, "stuck-call", input(msgs, append(aStreams, bStreams...)...)))
	if f.Severity != Warning || f.CallID != "a" {
		t.Errorf("finding %+v", f)
	}
	contains(t, "title", f.Title, "stopped 1m40s before the capture ended")

	// media runs to the end of the capture: not stuck
	running := []rtp.Stream{mkStream(cRTP, sRTP, ms(100), ms(119000), 1), mkStream(sRTP, cRTP, ms(150), ms(119000), 2)}
	if fs := runRule(t, "stuck-call", input(msgs, append(running, bStreams...)...)); len(fs) != 0 {
		t.Errorf("running: %+v", fs)
	}
	// no media at all: silence cannot be told from an uncaptured media path
	if fs := runRule(t, "stuck-call", input(msgs)); len(fs) != 0 {
		t.Errorf("no media: %+v", fs)
	}
	// ended calls are never stuck
	if fs := runRule(t, "stuck-call", input(msgs, bStreams...)); len(fs) != 0 {
		t.Errorf("b: %+v", fs)
	}

	// long-call
	long := input(okCall("l", 3600000).messages())
	if fs := runRule(t, "long-call", long); len(fs) != 0 {
		t.Errorf("default is off: %+v", fs)
	}
	long.Config.LongCall = 30 * time.Minute
	f = mustOne(t, runRule(t, "long-call", long))
	contains(t, "title", f.Title, "1h00m", "limit 30m00s")
	long.Config.LongCall = 2 * time.Hour
	if fs := runRule(t, "long-call", long); len(fs) != 0 {
		t.Errorf("%+v", fs)
	}
	// still up at the end of the capture: talk time runs to the last packet
	open := input(msgs)
	open.Config.LongCall = time.Minute
	fs := runRule(t, "long-call", open)
	if len(fs) != 2 {
		t.Fatalf("got %+v", fs)
	}
	for _, f := range fs {
		checkFinding(t, f)
		if f.CallID == "a" {
			contains(t, "title", f.Title, "still up at the end of the capture")
		} else if strings.Contains(f.Title, "still up") {
			t.Errorf("ended call reported as still up: %s", f.Title)
		}
	}
}
