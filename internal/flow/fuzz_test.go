package flow

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/sotoz/sipcurious/internal/call"
	"github.com/sotoz/sipcurious/internal/rtp"
	"github.com/sotoz/sipcurious/internal/trace"
)

// FuzzRender feeds hostile text through the whole pipeline (call.Build, then
// every renderer) and checks that nothing panics and that the output is safe.
func FuzzRender(f *testing.F) {
	f.Add("INVITE", "reason", "call-id", "ua", "audio 4000 RTP/AVP 0", uint8(0), uint8(2), uint8(7), uint8(255))
	f.Add("\x1b[31m", "a\r\nb", "<svg onload=x>", "%%;#", "\u202e", uint8(3), uint8(0), uint8(0), uint8(1))
	f.Add("", "", "", "", "", uint8(9), uint8(9), uint8(9), uint8(9))
	f.Fuzz(func(t *testing.T, method, reason, id, ua, media string, a, b, n, flags uint8) {
		addrs := []netip.AddrPort{
			netip.MustParseAddrPort("10.0.0.1:5060"), netip.MustParseAddrPort("[2001:db8::1]:5060"),
			netip.MustParseAddrPort("10.0.0.3:5060"), netip.MustParseAddrPort("10.0.0.4:5061"),
		}
		var msgs []trace.Message
		for i := range int(n%12) + 1 {
			src, dst := addrs[(int(a)+i)%len(addrs)], addrs[(int(b)+i*int(a%3))%len(addrs)]
			resp := (i+int(flags))%2 == 0
			m := trace.Message{
				Index: i + 1, Time: t0.Add(time.Duration(i) * time.Duration(flags) * 300 * time.Millisecond),
				Src: src.Addr(), SrcPort: src.Port(), Dst: dst.Addr(), DstPort: dst.Port(),
				Transport: "UDP", IsRequest: !resp, Method: method, CallID: id,
				From: "<sip:a@x>;tag=1", To: "<sip:b@x>", CSeq: "1 " + method, Via: "SIP/2.0/UDP x;branch=" + id,
			}
			body := "v=0\r\nc=IN IP4 10.0.0.1\r\nm=" + media + "\r\n"
			if resp {
				m.StatusCode, m.Reason = 100+int(flags)%6*100, reason
				m.Method = method
			} else {
				m.RequestURI = "sip:b@x"
			}
			m.Raw = "X\r\nUser-Agent: " + ua + "\r\nServer: " + ua + "\r\nContent-Type: application/sdp\r\n\r\n"
			m.HeaderEnd = len(m.Raw)
			m.Raw += body
			msgs = append(msgs, m)
		}
		calls := call.Build(msgs, call.Options{})
		if len(calls) == 0 {
			calls = []call.Call{{CallID: id, Messages: msgs}}
		}
		call.Attach(calls, []rtp.Stream{{
			Key:   rtp.Key{Src: addrs[0], Dst: addrs[1]},
			Start: t0, End: t0.Add(time.Second), Codec: media, Packets: uint64(n), MOS: float64(flags) / 60,
		}})
		for i := range calls {
			if i == 0 && len(calls[0].Streams) == 0 {
				calls[0].Streams = []rtp.Stream{{Key: rtp.Key{Src: addrs[0], Dst: addrs[2]}, Start: t0, Codec: media, Leg: ua}}
			}
		}
		for _, o := range []Options{{UTC: true, SDP: true, Media: true}, {Absolute: true, MaxLabel: int(flags % 20)}} {
			ascii := render(func(w *strings.Builder) error { return WriteASCII(w, calls, o) })
			mer := render(func(w *strings.Builder) error { return WriteMermaid(w, calls, o) })
			checkSafe(t, "ascii", ascii, true)
			checkSafe(t, "mermaid", mer, true)
			for _, c := range calls {
				svg, err := SVG(c, o)
				if err != nil {
					t.Fatal(err)
				}
				checkSafe(t, "svg", svg, true)
				parseSVG(t, svg)
			}
		}
	})
}
