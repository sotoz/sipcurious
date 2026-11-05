package call

import (
	"fmt"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/sotoz/sipcurious/internal/rtp"
)

func strm(src, dst string, start, end time.Duration, ssrc uint32) rtp.Stream {
	return rtp.Stream{
		Key:   rtp.Key{Src: netipAP(src), Dst: netipAP(dst), SSRC: ssrc},
		Start: t0.Add(start), End: t0.Add(end), Packets: 100, PayloadType: 8, Codec: "PCMA",
	}
}

// mediaCall builds an answered, completed call announcing callerRTP/calleeRTP
// that starts at `at` and is up for `talk`.
func mediaCall(id string, at int, talk int, callerRTP, calleeRTP string) *scenario {
	ip := func(s string) (string, int) {
		ap := netipAP(s)
		return ap.Addr().String(), int(ap.Port())
	}
	ci, cp := ip(callerRTP)
	bi, bp := ip(calleeRTP)
	s := newScenario(id)
	s.invite(at, sdpBody(ci, cp, "8=PCMA/8000")).
		resp(at+10, 100, "").
		resp(at+500, 200, sdpBody(bi, bp, "8=PCMA/8000")).
		ack(at+510).
		bye(at+500+talk, true)
	return s
}

func TestAttachBasic(t *testing.T) {
	calls := Build(mediaCall("a", 0, 10000, "10.0.0.1:4000", "10.0.1.2:6000").messages(), Options{})
	streams := []rtp.Stream{
		strm("10.0.1.2:6000", "10.0.0.1:4000", ms(600), ms(10400), 2), // callee -> caller
		strm("10.0.0.1:4000", "10.0.1.2:6000", ms(500), ms(10500), 1), // caller -> callee
		strm("10.9.9.9:1000", "10.9.9.8:2000", ms(500), ms(10500), 3), // unrelated
	}
	orig := append([]rtp.Stream(nil), streams...)
	Attach(calls, streams)
	if !reflect.DeepEqual(streams, orig) {
		t.Error("Attach modified its streams input")
	}
	got := calls[0].Streams
	if len(got) != 2 {
		t.Fatalf("streams = %d", len(got))
	}
	// ordered by Start
	if got[0].SSRC != 1 || got[0].Leg != "caller->callee" || got[0].CallID != "a" {
		t.Errorf("stream 0: %+v", got[0])
	}
	if got[1].SSRC != 2 || got[1].Leg != "callee->caller" || got[1].CallID != "a" {
		t.Errorf("stream 1: %+v", got[1])
	}
}

func TestAttachNATTolerance(t *testing.T) {
	calls := Build(mediaCall("a", 0, 10000, "192.168.1.10:4000", "10.0.1.2:6000").messages(), Options{})
	streams := []rtp.Stream{
		// caller is NATed: its media is seen from the public address, source differs from the SDP.
		strm("203.0.113.5:31000", "10.0.1.2:6000", ms(500), ms(10500), 1),
		// the callee sends to the NAT's public address: only the source matches the announced callee endpoint.
		strm("10.0.1.2:6000", "203.0.113.5:31000", ms(600), ms(10500), 2),
	}
	Attach(calls, streams)
	got := calls[0].Streams
	if len(got) != 2 {
		t.Fatalf("streams = %+v", got)
	}
	legs := map[uint32]string{}
	for _, s := range got {
		legs[s.SSRC] = s.Leg
	}
	want := map[uint32]string{1: "caller->callee", 2: "callee->caller"}
	if !reflect.DeepEqual(legs, want) {
		t.Errorf("legs = %v, want %v", legs, want)
	}
}

func TestAttachPortReuseBetweenConsecutiveCalls(t *testing.T) {
	// Same gateway ports for two back-to-back calls.
	m := mediaCall("first", 0, 20000, "10.0.0.1:4000", "10.0.1.2:6000").messages()
	m = append(m, mediaCall("second", 30000, 20000, "10.0.0.1:4000", "10.0.1.2:6000").messages()...)
	calls := Build(m, Options{})
	if len(calls) != 2 {
		t.Fatalf("calls = %d", len(calls))
	}
	streams := []rtp.Stream{
		strm("10.0.0.1:4000", "10.0.1.2:6000", ms(500), ms(20400), 1),
		strm("10.0.1.2:6000", "10.0.0.1:4000", ms(520), ms(20400), 2),
		strm("10.0.0.1:4000", "10.0.1.2:6000", ms(30500), ms(50400), 3),
		strm("10.0.1.2:6000", "10.0.0.1:4000", ms(30520), ms(50400), 4),
	}
	Attach(calls, streams)
	ssrcs := func(c Call) []uint32 {
		var out []uint32
		for _, s := range c.Streams {
			out = append(out, s.SSRC)
		}
		return out
	}
	if got := ssrcs(calls[0]); !reflect.DeepEqual(got, []uint32{1, 2}) {
		t.Errorf("first = %v", got)
	}
	if got := ssrcs(calls[1]); !reflect.DeepEqual(got, []uint32{3, 4}) {
		t.Errorf("second = %v", got)
	}
}

func TestAttachPortReuseWithinSlack(t *testing.T) {
	// The second call starts 3 s after the first one ended: both windows (+-5 s)
	// cover the gap; a stream belongs to the call it overlaps most.
	m := mediaCall("first", 0, 10000, "10.0.0.1:4000", "10.0.1.2:6000").messages()
	m = append(m, mediaCall("second", 13500, 10000, "10.0.0.1:4000", "10.0.1.2:6000").messages()...)
	calls := Build(m, Options{})
	streams := []rtp.Stream{
		strm("10.0.0.1:4000", "10.0.1.2:6000", ms(500), ms(10400), 1),
		strm("10.0.0.1:4000", "10.0.1.2:6000", ms(14000), ms(23900), 2),
	}
	Attach(calls, streams)
	if len(calls[0].Streams) != 1 || calls[0].Streams[0].SSRC != 1 || len(calls[1].Streams) != 1 || calls[1].Streams[0].SSRC != 2 {
		t.Errorf("first=%+v second=%+v", calls[0].Streams, calls[1].Streams)
	}
}

func TestAttachAtMostOneCall(t *testing.T) {
	// Two concurrent legs of a B2BUA announce the same endpoint (e.g. both reference one media server).
	m := mediaCall("leg1", 0, 10000, "10.0.0.1:4000", "10.0.5.5:7000").messages()
	m = append(m, mediaCall("leg2", 100, 10000, "10.0.2.2:4100", "10.0.5.5:7000").messages()...)
	calls := Build(m, Options{})
	streams := []rtp.Stream{strm("10.0.5.5:7000", "10.0.0.1:4000", ms(600), ms(10400), 1)}
	Attach(calls, streams)
	n := 0
	for _, c := range calls {
		n += len(c.Streams)
	}
	if n != 1 {
		t.Fatalf("stream attached %d times", n)
	}
	// both endpoints match leg1 (level both), only the source matches leg2.
	for _, c := range calls {
		if c.CallID == "leg1" && len(c.Streams) != 1 {
			t.Errorf("stream should go to leg1")
		}
	}
}

func TestAttachOutsideWindow(t *testing.T) {
	calls := Build(mediaCall("a", 0, 10000, "10.0.0.1:4000", "10.0.1.2:6000").messages(), Options{})
	streams := []rtp.Stream{
		strm("10.0.0.1:4000", "10.0.1.2:6000", -ms(3_600_000), -ms(3_590_000), 1), // an hour earlier
		strm("10.0.0.1:4000", "10.0.1.2:6000", ms(3_600_000), ms(3_610_000), 2),   // an hour later
	}
	Attach(calls, streams)
	if len(calls[0].Streams) != 0 {
		t.Errorf("streams = %+v", calls[0].Streams)
	}
}

func TestAttachEarlyMediaBeforeAnswer(t *testing.T) {
	s := newScenario("a").
		invite(0, sdpBody("10.0.0.1", 4000, "8=PCMA/8000")).
		resp(50, 183, sdpBody("10.0.1.9", 8000, "8=PCMA/8000")).
		resp(4000, 486, "")
	calls := Build(s.messages(), Options{})
	streams := []rtp.Stream{strm("10.0.1.9:8000", "10.0.0.1:4000", ms(100), ms(3900), 1)}
	Attach(calls, streams)
	if len(calls[0].Streams) != 1 || calls[0].Streams[0].Leg != "callee->caller" {
		t.Errorf("streams = %+v", calls[0].Streams)
	}
}

func TestAttachAnsweredWithoutBYEIsOpenEnded(t *testing.T) {
	s := newScenario("a").
		invite(0, sdpBody("10.0.0.1", 4000, "8=PCMA/8000")).
		resp(500, 200, sdpBody("10.0.1.2", 6000, "8=PCMA/8000")).
		ack(510)
	calls := Build(s.messages(), Options{})
	// The capture holds media for minutes after the last SIP message.
	streams := []rtp.Stream{strm("10.0.0.1:4000", "10.0.1.2:6000", ms(600), ms(600_000), 1)}
	Attach(calls, streams)
	if len(calls[0].Streams) != 1 {
		t.Errorf("streams = %+v", calls[0].Streams)
	}
}

func TestAttachNoMedia(t *testing.T) {
	calls := Build(newScenario("a").invite(0, "").resp(10, 486, "").messages(), Options{})
	Attach(calls, []rtp.Stream{strm("10.0.0.1:4000", "10.0.1.2:6000", 0, ms(1000), 1)})
	if calls[0].Streams != nil {
		t.Error("streams attached to a call without SDP")
	}
	Attach(nil, nil)
	Attach(calls, nil)
}

func TestAttachClearsPreviousResult(t *testing.T) {
	calls := Build(mediaCall("a", 0, 10000, "10.0.0.1:4000", "10.0.1.2:6000").messages(), Options{})
	Attach(calls, []rtp.Stream{strm("10.0.0.1:4000", "10.0.1.2:6000", ms(500), ms(10500), 1)})
	Attach(calls, nil)
	if calls[0].Streams != nil {
		t.Error("stale streams kept")
	}
}

func TestAttachMultipleStreamsSorted(t *testing.T) {
	calls := Build(mediaCall("a", 0, 10000, "10.0.0.1:4000", "10.0.1.2:6000").messages(), Options{})
	var streams []rtp.Stream
	for i := range 5 { // SSRC changes mid call, later ones listed first
		streams = append(streams, strm("10.0.0.1:4000", "10.0.1.2:6000", ms(8000-i*1500), ms(9000-i*1500), uint32(i)))
	}
	Attach(calls, streams)
	var prev time.Time
	for _, s := range calls[0].Streams {
		if s.Start.Before(prev) {
			t.Errorf("not sorted by Start: %+v", calls[0].Streams)
		}
		prev = s.Start
	}
	if len(calls[0].Streams) != 5 {
		t.Errorf("len = %d", len(calls[0].Streams))
	}
}

func TestAttachIPv6(t *testing.T) {
	s := newScenario("a")
	v6 := func(ip string, port int) string {
		return fmt.Sprintf("v=0\r\nc=IN IP6 %s\r\nm=audio %d RTP/AVP 8\r\n", ip, port)
	}
	s.invite(0, v6("2001:db8::1", 4000)).resp(100, 200, v6("2001:db8::2", 6000)).ack(110)
	calls := Build(s.messages(), Options{})
	st := rtp.Stream{Key: rtp.Key{Src: netip.MustParseAddrPort("[2001:db8::2]:6000"), Dst: netip.MustParseAddrPort("[2001:db8::1]:4000"), SSRC: 9}, Start: t0.Add(ms(200)), End: t0.Add(ms(900))}
	Attach(calls, []rtp.Stream{st})
	if len(calls[0].Streams) != 1 || calls[0].Streams[0].Leg != "callee->caller" {
		t.Errorf("streams = %+v", calls[0].Streams)
	}
}
