package flow

import (
	"strings"

	"github.com/sotoz/sipcurious/internal/call"
)

// proxied is alice -> proxy -> bob; the ACK goes straight from alice to bob
// and so crosses the proxy's lifeline.
func proxied() call.Call {
	return build(
		sg{at: 0, src: alice, dst: proxy, method: "INVITE", cseq: 1, branch: "z9hG4bKa", extra: []string{"User-Agent: Yealink SIP-T46"}},
		sg{at: ms(5), src: proxy, dst: alice, code: 100, cseq: 1, cseqM: "INVITE", branch: "z9hG4bKa", extra: []string{"Server: OpenSIPS (3.4)"}},
		sg{at: ms(6), src: proxy, dst: bob, method: "INVITE", cseq: 1, branch: "z9hG4bKb"},
		sg{at: ms(300), src: bob, dst: proxy, code: 180, cseq: 1, cseqM: "INVITE", branch: "z9hG4bKb", toTag: "tt", extra: []string{"User-Agent: FreeSWITCH-mod_sofia/1.10"}},
		sg{at: ms(301), src: proxy, dst: alice, code: 180, cseq: 1, cseqM: "INVITE", branch: "z9hG4bKa", toTag: "tt"},
		sg{at: ms(900), src: bob, dst: proxy, code: 200, cseq: 1, cseqM: "INVITE", branch: "z9hG4bKb", toTag: "tt"},
		sg{at: ms(901), src: proxy, dst: alice, code: 200, cseq: 1, cseqM: "INVITE", branch: "z9hG4bKa", toTag: "tt"},
		sg{at: ms(950), src: alice, dst: bob, method: "ACK", cseq: 1, branch: "z9hG4bKack", toTag: "tt"},
	)
}

// failed is a busy call whose INVITE and 486 were both retransmitted.
func failed() call.Call {
	return build(
		sg{at: 0, src: alice, dst: bob, method: "INVITE", cseq: 1, branch: "z9hG4bKa"},
		sg{at: ms(500), src: alice, dst: bob, method: "INVITE", cseq: 1, branch: "z9hG4bKa"},
		sg{at: ms(520), src: bob, dst: alice, code: 486, cseq: 1, cseqM: "INVITE", branch: "z9hG4bKa", toTag: "tt", extra: []string{"Reason: SIP;cause=486;text=\"Busy\""}},
		sg{at: ms(530), src: alice, dst: bob, method: "ACK", cseq: 1, branch: "z9hG4bKa", toTag: "tt"},
		sg{at: ms(1020), src: bob, dst: alice, code: 486, cseq: 1, cseqM: "INVITE", branch: "z9hG4bKa", toTag: "tt"},
	)
}

// held is an answered call with a hold re-INVITE and a resume.
func held() call.Call {
	ok := func(at int, ip string, port int, attrs ...string) sg {
		return sg{at: ms(at), src: bob, dst: alice, code: 200, cseq: 2, cseqM: "INVITE", branch: "z9hG4bKr", toTag: "tt", sdp: sdpBody(ip, port, "PCMU", attrs...)}
	}
	return build(
		sg{at: 0, src: alice, dst: bob, method: "INVITE", cseq: 1, branch: "z9hG4bKa", sdp: sdpBody("10.0.0.1", 20000, "PCMU")},
		sg{at: ms(200), src: bob, dst: alice, code: 200, cseq: 1, cseqM: "INVITE", branch: "z9hG4bKa", toTag: "tt", sdp: sdpBody("10.0.0.3", 30000, "PCMU")},
		sg{at: ms(210), src: alice, dst: bob, method: "ACK", cseq: 1, branch: "z9hG4bKack", toTag: "tt"},
		sg{at: ms(10000), src: alice, dst: bob, method: "INVITE", cseq: 2, branch: "z9hG4bKr", toTag: "tt", sdp: sdpBody("10.0.0.1", 20000, "PCMU", "a=sendonly")},
		ok(10020, "10.0.0.3", 30000, "a=recvonly"),
		sg{at: ms(10030), src: alice, dst: bob, method: "ACK", cseq: 2, branch: "z9hG4bKack2", toTag: "tt"},
		sg{at: ms(20000), src: alice, dst: bob, method: "BYE", cseq: 3, branch: "z9hG4bKbye", toTag: "tt"},
	)
}

// hostile carries control characters, bidi overrides, markup and Mermaid
// metacharacters in every captured text field, plus IPv6 endpoints and a
// self-addressed message.
func hostile() call.Call {
	nasty := "x\x1b[31m\r\ny\u202e\x00#;%<>&\"'z"
	v6a, v6b := "[2001:db8::1]:5060", "[2001:db8::2]:5060"
	return build(
		sg{callID: "id\r\n\x1b]0;pwn\x07<script>", at: 0, src: v6a, dst: v6b, method: "INVITE", cseq: 1, branch: "z9hG4bKa", extra: []string{"User-Agent: " + nasty}},
		sg{callID: "id\r\n\x1b]0;pwn\x07<script>", at: ms(10), src: v6b, dst: v6b, code: 486, reason: nasty, cseq: 1, cseqM: "INVITE", branch: "z9hG4bKa", toTag: "tt", extra: []string{"Server: " + nasty}},
	)
}

func render(f func(w *strings.Builder) error) string {
	var b strings.Builder
	if err := f(&b); err != nil {
		panic(err)
	}
	return b.String()
}

type goldenCase struct {
	name string
	c    func() call.Call
	o    Options
}

// goldenCases are rendered and compared with goldens (goldens_test.go).
var goldenCases = []goldenCase{
	{"answeredSDPMedia", func() call.Call { return withStreams(answered()) }, Options{UTC: true, SDP: true, Media: true}},
	{"answeredAbsolute", answered, Options{UTC: true, Absolute: true}},
	{"proxy", proxied, Options{UTC: true}},
	{"failedRetrans", failed, Options{UTC: true}},
	{"holdSDP", held, Options{UTC: true, SDP: true}},
	{"hostile", hostile, Options{UTC: true, SDP: true, Media: true, MaxLabel: 20}},
}
