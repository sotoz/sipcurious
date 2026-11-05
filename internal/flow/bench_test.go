package flow

import (
	"io"
	"testing"
	"time"

	"github.com/sotoz/sipcurious/internal/call"
	"github.com/sotoz/sipcurious/internal/trace"
)

// bigCall is a 5000-message call between 4 endpoints with SDP in every
// re-INVITE.
func bigCall() call.Call {
	addrs := []string{alice, proxy, bob, "10.0.0.4:5060"}
	msgs := make([]trace.Message, 5000)
	for i := range msgs {
		s := sg{at: time.Duration(i) * 20 * time.Millisecond, src: addrs[i%3], dst: addrs[i%3+1], cseq: i/2 + 1, branch: "z9hG4bK" + itoa(i/2)}
		if i%2 == 0 {
			s.method = "INVITE"
			s.sdp = sdpBody("10.0.0.1", 20000, "PCMU PCMA")
		} else {
			s.src, s.dst = s.dst, s.src
			s.code, s.cseqM = 200, "INVITE"
		}
		msgs[i] = s.msg(i)
	}
	cs := call.Build(msgs, call.Options{})
	return cs[0]
}

func BenchmarkRender5000(b *testing.B) {
	c := bigCall()
	o := Options{UTC: true, SDP: true, Media: true}
	calls := []call.Call{c}
	b.Run("ASCII", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			if err := WriteASCII(io.Discard, calls, o); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("Mermaid", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			if err := WriteMermaid(io.Discard, calls, o); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("SVG", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			if _, err := SVG(c, o); err != nil {
				b.Fatal(err)
			}
		}
	})
}
