package call

import (
	"reflect"
	"testing"
)

func TestMediaBasicOfferAnswer(t *testing.T) {
	c := only(t, Build(answeredCall("a").messages(), Options{}))
	if len(c.Media) != 1 {
		t.Fatalf("media = %+v", c.Media)
	}
	m := c.Media[0]
	if m.Type != "audio" || m.Caller != netipAP("10.0.0.1:4000") || m.Callee != netipAP("10.0.1.2:6000") {
		t.Errorf("endpoints: %+v", m)
	}
	if want := []string{"PCMA", "telephone-event"}; !reflect.DeepEqual(m.Codecs, want) {
		t.Errorf("Codecs = %v, want %v", m.Codecs, want)
	}
	if want := []string{"PCMU", "PCMA", "telephone-event"}; !reflect.DeepEqual(m.Offered, want) {
		t.Errorf("Offered = %v, want %v", m.Offered, want)
	}
	if m.Direction != "sendrecv" || m.Hold || m.Disabled || m.Secure || m.Early {
		t.Errorf("flags: %+v", m)
	}
	if !m.Time.Equal(t0.Add(ms(2100))) {
		t.Errorf("Time = %v", m.Time)
	}
}

func TestMediaCodecsFirstIsNegotiated(t *testing.T) {
	// Answer lists telephone-event first: Codecs[0] must still be the real codec.
	s := newScenario("a").
		invite(0, sdpBody("10.0.0.1", 4000, "0=PCMU/8000 101=telephone-event/8000")).
		resp(100, 200, sdpBody("10.0.1.2", 6000, "101=telephone-event/8000 13=CN/8000 18=G729/8000 0=PCMU/8000")).
		ack(110)
	m := only(t, Build(s.messages(), Options{})).Media[0]
	if want := []string{"G729", "telephone-event", "CN", "PCMU"}; !reflect.DeepEqual(m.Codecs, want) {
		t.Errorf("Codecs = %v, want %v", m.Codecs, want)
	}
}

func TestMediaDynamicPTWithoutRtpmapInAnswer(t *testing.T) {
	offer := "v=0\r\nc=IN IP4 10.0.0.1\r\nm=audio 4000 RTP/AVP 96 101\r\na=rtpmap:96 opus/48000/2\r\na=rtpmap:101 telephone-event/8000\r\n"
	answer := "v=0\r\nc=IN IP4 10.0.1.2\r\nm=audio 6000 RTP/AVP 96\r\n" // sloppy UA: no rtpmap
	s := newScenario("a").invite(0, offer).resp(100, 200, answer).ack(110)
	m := only(t, Build(s.messages(), Options{})).Media[0]
	if !reflect.DeepEqual(m.Codecs, []string{"opus"}) {
		t.Errorf("Codecs = %v", m.Codecs)
	}
}

func TestMediaOfferOnly(t *testing.T) {
	s := newScenario("a").invite(0, sdpBody("10.0.0.1", 4000, "0=PCMU/8000 8=PCMA/8000")).resp(10, 100, "").resp(100, 486, "")
	c := only(t, Build(s.messages(), Options{}))
	if len(c.Media) != 1 {
		t.Fatalf("media = %+v", c.Media)
	}
	m := c.Media[0]
	if m.Caller != netipAP("10.0.0.1:4000") || m.Callee.IsValid() {
		t.Errorf("endpoints %v %v", m.Caller, m.Callee)
	}
	if !reflect.DeepEqual(m.Codecs, []string{"PCMU", "PCMA"}) || !reflect.DeepEqual(m.Offered, m.Codecs) {
		t.Errorf("codecs %v offered %v", m.Codecs, m.Offered)
	}
}

func TestMediaEarlyMedia(t *testing.T) {
	s := newScenario("a").
		invite(0, sdpBody("10.0.0.1", 4000, "0=PCMU/8000 8=PCMA/8000")).
		resp(50, 183, sdpBody("10.0.1.9", 8000, "8=PCMA/8000")).
		resp(3000, 200, sdpBody("10.0.1.2", 6000, "8=PCMA/8000")).
		ack(3010)
	c := only(t, Build(s.messages(), Options{}))
	if len(c.Media) != 2 {
		t.Fatalf("media = %+v", c.Media)
	}
	if !c.Media[0].Early || c.Media[0].Callee != netipAP("10.0.1.9:8000") {
		t.Errorf("early = %+v", c.Media[0])
	}
	if c.Media[1].Early || c.Media[1].Callee != netipAP("10.0.1.2:6000") {
		t.Errorf("final = %+v", c.Media[1])
	}
}

func TestMediaEarlyMediaSameEndpointsNotDuplicated(t *testing.T) {
	body := sdpBody("10.0.1.2", 6000, "8=PCMA/8000")
	s := newScenario("a").
		invite(0, sdpBody("10.0.0.1", 4000, "8=PCMA/8000")).
		resp(50, 183, body).
		resp(3000, 200, body).
		ack(3010)
	c := only(t, Build(s.messages(), Options{}))
	if len(c.Media) != 1 || !c.Media[0].Early {
		t.Errorf("media = %+v", c.Media)
	}
}

func TestMediaDelayedOffer(t *testing.T) {
	// INVITE without SDP; the offer arrives in the 200, the answer in the ACK.
	s := newScenario("a").
		invite(0, "").
		resp(100, 180, "").
		resp(2000, 200, sdpBody("10.0.1.2", 6000, "0=PCMU/8000 8=PCMA/8000 101=telephone-event/8000")).
		ack(2010)
	// replace the ACK by one carrying the answer
	s.list[len(s.list)-1].sdp = sdpBody("10.0.0.1", 4000, "8=PCMA/8000")
	c := only(t, Build(s.messages(), Options{}))
	if len(c.Media) != 1 {
		t.Fatalf("media = %+v", c.Media)
	}
	m := c.Media[0]
	if m.Callee != netipAP("10.0.1.2:6000") || m.Caller != netipAP("10.0.0.1:4000") {
		t.Errorf("endpoints: caller=%v callee=%v", m.Caller, m.Callee)
	}
	if !reflect.DeepEqual(m.Codecs, []string{"PCMA"}) || !reflect.DeepEqual(m.Offered, []string{"PCMU", "PCMA", "telephone-event"}) {
		t.Errorf("codecs=%v offered=%v", m.Codecs, m.Offered)
	}
}

func TestMediaDelayedOfferUnanswered(t *testing.T) {
	// Offer in the 200 and no ACK captured: reported as an offer from the callee side.
	s := newScenario("a").invite(0, "").resp(2000, 200, sdpBody("10.0.1.2", 6000, "0=PCMU/8000"))
	m := only(t, Build(s.messages(), Options{})).Media
	if len(m) != 1 || m[0].Callee != netipAP("10.0.1.2:6000") || m[0].Caller.IsValid() {
		t.Errorf("media = %+v", m)
	}
}

func TestMediaHoldResume(t *testing.T) {
	s := answeredCall("a")
	s.cseq = 2
	// caller puts the call on hold (sendonly), callee answers recvonly; then resume.
	s.c2s(5000, sg{method: "INVITE", cseq: 2, branch: "z9hG4bK-h1", toTag: s.ttag,
		sdp: sdpBody("10.0.0.1", 4000, "8=PCMA/8000", "sendonly")})
	s.s2c(5050, sg{code: 200, cseq: 2, cseqM: "INVITE", branch: "z9hG4bK-h1", toTag: s.ttag,
		sdp: sdpBody("10.0.1.2", 6000, "8=PCMA/8000", "recvonly")})
	s.c2s(5060, sg{method: "ACK", cseq: 2, branch: "z9hG4bK-h1a", toTag: s.ttag})
	s.c2s(9000, sg{method: "INVITE", cseq: 3, branch: "z9hG4bK-h2", toTag: s.ttag,
		sdp: sdpBody("10.0.0.1", 4000, "8=PCMA/8000", "sendrecv")})
	s.s2c(9050, sg{code: 200, cseq: 3, cseqM: "INVITE", branch: "z9hG4bK-h2", toTag: s.ttag,
		sdp: sdpBody("10.0.1.2", 6000, "8=PCMA/8000", "sendrecv")})
	s.c2s(9060, sg{method: "ACK", cseq: 3, branch: "z9hG4bK-h2a", toTag: s.ttag})
	c := only(t, Build(s.messages(), Options{}))
	if len(c.Media) != 3 {
		t.Fatalf("media entries = %d: %+v", len(c.Media), c.Media)
	}
	if c.Media[0].Hold || !c.Media[1].Hold || c.Media[2].Hold {
		t.Errorf("hold flags: %v %v %v", c.Media[0].Hold, c.Media[1].Hold, c.Media[2].Hold)
	}
	if c.Media[1].Direction != "recvonly" {
		t.Errorf("direction = %q (answer's direction)", c.Media[1].Direction)
	}
	if c.State != StateAnswered {
		t.Errorf("state = %s", c.State)
	}
}

func TestMediaLegacyHold(t *testing.T) {
	s := answeredCall("a")
	s.c2s(5000, sg{method: "INVITE", cseq: 2, branch: "z9hG4bK-h1", toTag: s.ttag,
		sdp: "v=0\r\no=- 1 1 IN IP4 10.0.0.1\r\ns=-\r\nc=IN IP4 0.0.0.0\r\nt=0 0\r\nm=audio 4000 RTP/AVP 8\r\na=rtpmap:8 PCMA/8000\r\n"})
	s.s2c(5050, sg{code: 200, cseq: 2, cseqM: "INVITE", branch: "z9hG4bK-h1", toTag: s.ttag,
		sdp: sdpBody("10.0.1.2", 6000, "8=PCMA/8000")})
	c := only(t, Build(s.messages(), Options{}))
	if len(c.Media) != 2 || !c.Media[1].Hold {
		t.Fatalf("media = %+v", c.Media)
	}
	if c.Media[1].Caller.IsValid() {
		t.Errorf("0.0.0.0 must not be reported as an endpoint: %v", c.Media[1].Caller)
	}
}

func TestMediaDisabled(t *testing.T) {
	offer := "v=0\r\nc=IN IP4 10.0.0.1\r\nm=audio 4000 RTP/AVP 0\r\nm=video 4002 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\n"
	answer := "v=0\r\nc=IN IP4 10.0.1.2\r\nm=audio 6000 RTP/AVP 0\r\nm=video 0 RTP/AVP 96\r\n"
	s := newScenario("a").invite(0, offer).resp(100, 200, answer).ack(110)
	c := only(t, Build(s.messages(), Options{}))
	if len(c.Media) != 2 {
		t.Fatalf("media = %+v", c.Media)
	}
	if c.Media[0].Type != "audio" || c.Media[0].Disabled {
		t.Errorf("audio: %+v", c.Media[0])
	}
	v := c.Media[1]
	if v.Type != "video" || !v.Disabled || v.Hold || v.Callee.IsValid() {
		t.Errorf("video: %+v", v)
	}
}

func TestMediaSecure(t *testing.T) {
	offer := "v=0\r\nc=IN IP4 10.0.0.1\r\nm=audio 4000 RTP/SAVP 0\r\na=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:abc\r\n"
	answer := "v=0\r\nc=IN IP4 10.0.1.2\r\nm=audio 6000 RTP/SAVP 0\r\na=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:def\r\n"
	s := newScenario("a").invite(0, offer).resp(100, 200, answer).ack(110)
	if m := only(t, Build(s.messages(), Options{})).Media[0]; !m.Secure {
		t.Errorf("not secure: %+v", m)
	}
}

func TestMediaMultipart(t *testing.T) {
	body := "--b1\r\nContent-Type: application/isup\r\n\r\nxyz\r\n--b1\r\nContent-Type: application/sdp\r\n\r\n" +
		sdpBody("10.0.0.1", 4000, "0=PCMU/8000") + "--b1--\r\n"
	s := newScenario("a").invite(0, body)
	s.list[0].ctype = `multipart/mixed;boundary="b1"`
	m := only(t, Build(s.messages(), Options{})).Media
	if len(m) != 1 || m[0].Caller != netipAP("10.0.0.1:4000") {
		t.Errorf("media = %+v", m)
	}
}

func TestMediaRetransmittedInviteAndAuthRetry(t *testing.T) {
	// INVITE with SDP, 407, second INVITE with a different SDP port, 200: one description.
	s := newScenario("a").invite(0, sdpBody("10.0.0.1", 4000, "0=PCMU/8000"))
	s.invite(500, sdpBody("10.0.0.1", 4000, "0=PCMU/8000"))
	s.s2c(600, sg{code: 407, cseq: 1, cseqM: "INVITE", branch: s.branch, toTag: "x"})
	s.c2s(610, sg{method: "INVITE", cseq: 2, branch: "z9hG4bK-2", sdp: sdpBody("10.0.0.1", 4002, "0=PCMU/8000")})
	s.s2c(1000, sg{code: 200, cseq: 2, cseqM: "INVITE", branch: "z9hG4bK-2", toTag: s.ttag, sdp: sdpBody("10.0.1.2", 6000, "0=PCMU/8000")})
	s.c2s(1010, sg{method: "ACK", cseq: 2, branch: "z9hG4bK-2a", toTag: s.ttag})
	c := only(t, Build(s.messages(), Options{}))
	if len(c.Media) != 1 || c.Media[0].Caller != netipAP("10.0.0.1:4002") || c.Media[0].Callee != netipAP("10.0.1.2:6000") {
		t.Errorf("media = %+v", c.Media)
	}
}

func TestMediaProvisionalAnswersAndPRACK(t *testing.T) {
	// 100rel: offer in INVITE, answer in reliable 183, then UPDATE/PRACK with no SDP.
	s := newScenario("a").
		invite(0, sdpBody("10.0.0.1", 4000, "0=PCMU/8000")).
		resp(100, 183, sdpBody("10.0.1.2", 6000, "0=PCMU/8000"))
	s.c2s(150, sg{method: "PRACK", cseq: 2, branch: "z9hG4bK-pr", toTag: s.ttag})
	s.resp(3000, 200, sdpBody("10.0.1.2", 6000, "0=PCMU/8000")).ack(3010)
	c := only(t, Build(s.messages(), Options{}))
	if len(c.Media) != 1 || !c.Media[0].Early {
		t.Errorf("media = %+v", c.Media)
	}
}

func TestMediaUPDATE(t *testing.T) {
	s := answeredCall("a")
	s.c2s(3000, sg{method: "UPDATE", cseq: 2, branch: "z9hG4bK-u", toTag: s.ttag,
		sdp: sdpBody("10.0.0.1", 4100, "8=PCMA/8000")})
	s.s2c(3050, sg{code: 200, cseq: 2, cseqM: "UPDATE", branch: "z9hG4bK-u", toTag: s.ttag,
		sdp: sdpBody("10.0.1.2", 6000, "8=PCMA/8000")})
	c := only(t, Build(s.messages(), Options{}))
	if len(c.Media) != 2 || c.Media[1].Caller != netipAP("10.0.0.1:4100") {
		t.Errorf("media = %+v", c.Media)
	}
}

func TestMediaGarbageSDP(t *testing.T) {
	s := newScenario("a").invite(0, "this is not sdp\r\n").resp(10, 486, "")
	if c := only(t, Build(s.messages(), Options{})); len(c.Media) != 0 {
		t.Errorf("media = %+v", c.Media)
	}
}

func TestMediaCalleeSideOffer(t *testing.T) {
	// The callee re-offers (re-INVITE from callee): endpoints still map to caller/callee roles.
	s := answeredCall("a")
	s.s2c(5000, sg{method: "INVITE", cseq: 1, fromTag: s.ttag, toTag: s.ftag, from: "bob", to: "alice", branch: "z9hG4bK-bre",
		sdp: sdpBody("10.0.1.2", 6100, "8=PCMA/8000")})
	s.c2s(5050, sg{code: 200, cseq: 1, cseqM: "INVITE", fromTag: s.ttag, toTag: s.ftag, from: "bob", to: "alice", branch: "z9hG4bK-bre",
		sdp: sdpBody("10.0.0.1", 4000, "8=PCMA/8000")})
	c := only(t, Build(s.messages(), Options{}))
	if len(c.Media) != 2 {
		t.Fatalf("media = %+v", c.Media)
	}
	if m := c.Media[1]; m.Callee != netipAP("10.0.1.2:6100") || m.Caller != netipAP("10.0.0.1:4000") {
		t.Errorf("roles swapped: %+v", m)
	}
}

func TestMediaOfferOnlyKeepsOfferedOrder(t *testing.T) {
	// telephone-event first in the offer: Codecs[0] is the real codec, Offered stays in offer order.
	s := newScenario("a").invite(0, sdpBody("10.0.0.1", 4000, "101=telephone-event/8000 8=PCMA/8000 0=PCMU/8000")).resp(100, 486, "")
	m := only(t, Build(s.messages(), Options{})).Media[0]
	if want := []string{"PCMA", "telephone-event", "PCMU"}; !reflect.DeepEqual(m.Codecs, want) {
		t.Errorf("Codecs = %v, want %v", m.Codecs, want)
	}
	if want := []string{"telephone-event", "PCMA", "PCMU"}; !reflect.DeepEqual(m.Offered, want) {
		t.Errorf("Offered = %v, want %v", m.Offered, want)
	}
}
