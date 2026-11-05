package stats

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/sotoz/sipcurious/internal/call"
	"github.com/sotoz/sipcurious/internal/rtp"
	"github.com/sotoz/sipcurious/internal/trace"
)

// synthetic builds n messages in n/8 calls (INVITE, 100, 180, 200, ACK, BYE,
// 200 and a retransmitted INVITE) without going through call.Build, so the
// benchmark measures Compute only.
func synthetic(n int) Input {
	callsN := n / 8
	msgs := make([]trace.Message, 0, n)
	calls := make([]call.Call, 0, callsN)
	hosts := make([]netip.Addr, 200)
	for i := range hosts {
		hosts[i] = netip.AddrFrom4([4]byte{10, 0, byte(i / 256), byte(i)})
	}
	codes := []int{100, 180, 200, 200, 486, 503}
	for i := 0; i < callsN; i++ {
		id := fmt.Sprintf("call-%d", i)
		start := t0.Add(time.Duration(i) * 50 * time.Millisecond)
		src, dst := hosts[i%len(hosts)], hosts[(i*7+1)%len(hosts)]
		for k := 0; k < 8; k++ {
			m := trace.Message{Time: start.Add(time.Duration(k) * 100 * time.Millisecond), Src: src, Dst: dst, SrcPort: 5060, DstPort: 5060, Transport: "UDP", CallID: id}
			if k%2 == 0 {
				m.IsRequest, m.Method = true, []string{"INVITE", "ACK", "BYE", "INVITE"}[k/2]
			} else {
				m.StatusCode, m.Reason = codes[(i+k)%len(codes)], "x"
			}
			msgs = append(msgs, m)
		}
		c := call.Call{
			CallID: id, Kind: call.KindCall, State: call.StateCompleted, FinalCode: 200, Start: start,
			Answered: start.Add(300 * time.Millisecond), Ended: start.Add(time.Duration(10+i%90) * time.Second),
			PDD: 100 * time.Millisecond, SetupTime: 300 * time.Millisecond, RingTime: 200 * time.Millisecond,
			TalkTime: time.Duration(10+i%90) * time.Second, Caller: netip.AddrPortFrom(src, 5060),
			FromUser: fmt.Sprintf("u%d", i%5000), ToUser: fmt.Sprintf("n%d", i%7000),
			UserAgents: []string{"ua" + fmt.Sprint(i%12)}, Retransmissions: i % 2,
		}
		if i%5 == 0 {
			c.State, c.FinalCode = call.StateFailed, codes[4+i%2]
		}
		c.End = c.Ended
		calls = append(calls, c)
	}
	streams := make([]rtp.Stream, callsN)
	for i := range streams {
		streams[i] = rtp.Stream{Key: rtp.Key{SSRC: uint32(i)}, Codec: "PCMU", Packets: 500, LossPct: float64(i % 7), JitterMean: time.Duration(i%30) * time.Millisecond, MOS: 4 + float64(i%5)/10, Start: t0, End: t0.Add(time.Minute)}
	}
	return Input{Messages: msgs, Calls: calls, Streams: streams}
}

func BenchmarkCompute1M(b *testing.B) {
	in := synthetic(1_000_000)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Compute(in)
	}
	b.ReportMetric(float64(len(in.Messages))*float64(b.N)/b.Elapsed().Seconds(), "msgs/s")
}
