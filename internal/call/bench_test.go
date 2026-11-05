package call

import (
	"fmt"
	"math/rand/v2"
	"slices"
	"testing"
	"time"

	"github.com/sotoz/sipcurious/internal/rtp"
	"github.com/sotoz/sipcurious/internal/trace"
)

// bigCapture builds nCalls answered calls (10 messages each) and shuffles them
// so that Build has to group and sort: nCalls*10 messages in total.
func bigCapture(nCalls int, shuffle bool) []trace.Message {
	out := make([]trace.Message, 0, nCalls*10)
	for i := range nCalls {
		id := fmt.Sprintf("call-%d@pbx", i)
		s := newScenario(id)
		at := i * 7
		s.invite(at, sdpBody("10.0.0.1", 4000+2*(i%1000), "0=PCMU/8000 8=PCMA/8000 101=telephone-event/8000")).
			resp(at+1, 100, "").
			resp(at+20, 180, "").
			resp(at+2000, 200, sdpBody("10.0.1.2", 6000+2*(i%1000), "8=PCMA/8000 101=telephone-event/8000")).
			ack(at+2005).
			bye(at+9000, i%2 == 0)
		s.s2c(at+9010, sg{code: 200, cseq: s.cseq + 1, cseqM: "BYE", branch: s.branch + "-bye", toTag: s.ttag})
		s.s2c(at+2100, sg{code: 200, cseq: s.cseq, cseqM: "INVITE", branch: s.branch, toTag: s.ttag}) // retransmission
		s.c2s(at+2200, sg{method: "OPTIONS", cseq: 77, branch: s.branch + "-o", toTag: s.ttag})
		s.s2c(at+2210, sg{code: 200, cseq: 77, cseqM: "OPTIONS", branch: s.branch + "-o", toTag: s.ttag})
		out = append(out, s.messages()...)
	}
	if shuffle {
		r := rand.New(rand.NewPCG(1, 2))
		r.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	}
	return out
}

func BenchmarkBuild1M(b *testing.B) {
	for _, shuffled := range []bool{false, true} {
		b.Run(fmt.Sprintf("shuffled=%v", shuffled), func(b *testing.B) {
			msgs := bigCapture(100_000, shuffled)
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				calls := Build(msgs, Options{})
				if len(calls) != 100_000 {
					b.Fatalf("calls = %d", len(calls))
				}
			}
			b.ReportMetric(float64(len(msgs))*float64(b.N)/b.Elapsed().Seconds(), "msgs/s")
		})
	}
}

func BenchmarkBuildSingleCall(b *testing.B) {
	msgs := answeredCall("x").bye(9000, true).messages()
	b.ReportAllocs()
	for range b.N {
		Build(msgs, Options{})
	}
}

func BenchmarkAttach(b *testing.B) {
	const n = 20_000
	msgs := bigCapture(n, false)
	calls := Build(msgs, Options{})
	streams := make([]rtp.Stream, 0, n*2)
	for i := range n {
		at := time.Duration(i*7) * time.Millisecond
		p := uint16(i % 1000)
		src := fmt.Sprintf("10.0.0.1:%d", 4000+2*p)
		dst := fmt.Sprintf("10.0.1.2:%d", 6000+2*p)
		streams = append(streams, strm(src, dst, at+ms(2000), at+ms(9000), uint32(2*i)), strm(dst, src, at+ms(2010), at+ms(9000), uint32(2*i+1)))
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		Attach(calls, streams)
	}
	attached := 0
	for _, c := range calls {
		attached += len(c.Streams)
	}
	b.ReportMetric(float64(attached), "attached")
}

// FuzzBuild feeds hostile message sequences to Build and Attach and checks the
// structural invariants every Call must satisfy.
func FuzzBuild(f *testing.F) {
	f.Add([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20})
	f.Add([]byte("INVITE\x00200\x00BYE\x00ACK\x00CANCEL\x00487\x00180"))
	f.Fuzz(func(t *testing.T, data []byte) {
		methods := []string{"INVITE", "ACK", "BYE", "CANCEL", "REGISTER", "OPTIONS", "UPDATE", "PRACK", "INFO", "NOTIFY", ""}
		codes := []int{100, 180, 183, 200, 302, 401, 407, 480, 486, 487, 500, 503, 603}
		var list []sg
		for i := 0; i+3 < len(data) && len(list) < 200; i += 4 {
			b0, b1, b2, b3 := data[i], data[i+1], data[i+2], data[i+3]
			x := sg{
				at: ms(int(b1) * 10), callID: fmt.Sprintf("c%d", b0%4), cseq: int(b2 % 5),
				fromTag: fmt.Sprintf("f%d", b3%3), toTag: []string{"", "t1", "t2"}[b3/3%3], branch: fmt.Sprintf("b%d", b2/5%4),
				src: []netipAddrPort{alice, bob, proxy}[b0/4%3], dst: []netipAddrPort{alice, bob, proxy}[b0/16%3],
			}
			if m := methods[int(b0>>2)%len(methods)]; m != "" {
				x.method = m
			} else {
				x.code, x.cseqM = codes[int(b3)%len(codes)], methods[int(b2)%(len(methods)-1)]
			}
			if b3&0x80 != 0 {
				x.sdp = sdpBody("10.0.0.1", 4000+int(b1), "0=PCMU/8000 101=telephone-event/8000", []string{"sendonly", "inactive", "sendrecv"}[b2%3])
			}
			list = append(list, x)
		}
		in := msgs(list...)
		orig := slices.Clone(in)
		calls := Build(in, Options{CorrelateHeaders: []string{"X-CID"}})
		if !slices.EqualFunc(in, orig, func(a, b trace.Message) bool { return a == b }) {
			t.Fatal("Build modified input")
		}
		total := 0
		for i, c := range calls {
			total += len(c.Messages)
			if len(c.Messages) == 0 || c.CallID == "" || c.State == "" || c.Kind == "" {
				t.Fatalf("incomplete call %+v", c)
			}
			if c.End.Before(c.Start) || c.Duration() < 0 {
				t.Fatalf("negative duration")
			}
			if i > 0 && c.Start.Before(calls[i-1].Start) {
				t.Fatal("calls not ordered by Start")
			}
			if c.PDD < 0 || c.RingTime < 0 || c.SetupTime < 0 || c.TalkTime < 0 || c.Retransmissions >= len(c.Messages) {
				t.Fatalf("bad numbers %+v", c)
			}
			for j := 1; j < len(c.Messages); j++ {
				if c.Messages[j].Time.Before(c.Messages[j-1].Time) {
					t.Fatal("messages not chronological")
				}
			}
			if (c.State == StateCompleted) != (c.EndMethod == "BYE") {
				t.Fatalf("state %s endMethod %q", c.State, c.EndMethod)
			}
		}
		if total != len(in) {
			t.Fatalf("messages lost: %d != %d", total, len(in))
		}
		Attach(calls, []rtp.Stream{strm("10.0.0.1:4000", "10.0.1.2:6000", 0, ms(5000), 1)})
	})
}
