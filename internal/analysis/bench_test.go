package analysis

import (
	"testing"
	"time"

	"github.com/sotoz/sipcurious/internal/call"
	"github.com/sotoz/sipcurious/internal/rtp"
	"github.com/sotoz/sipcurious/internal/trace"
)

// BenchmarkRun measures all rules over 2000 calls (about 20k messages) with media.
func BenchmarkRun(b *testing.B) {
	var msgs []trace.Message
	var streams []rtp.Stream
	for i := 0; i < 2000; i++ {
		id := "call" + itoa(i)
		s := newScenario(id)
		off := i * 50
		port := 10000 + (i%2000)*2
		s.invite(off, sdpBody("10.0.0.1", port, "0=PCMU/8000 8=PCMA/8000 101=telephone-event/8000")).
			resp(off+10, 100, "").resp(off+100, 180, "")
		switch i % 10 {
		case 0:
			s.resp(off+4500, 486, "").ack(off + 4510)
		case 1:
			s.invite(off+500, "").invite(off+1500, "")
		default:
			s.resp(off+1100, 200, sdpBody("10.0.1.2", port, "8=PCMA/8000 101=telephone-event/8000")).ack(off+1110).bye(off+9000, true)
			st := mkStream("10.0.0.1:"+itoa(port), "10.0.1.2:"+itoa(port), ms(off+1100), ms(off+9000), uint32(i*2+1))
			st.LossPct = float64(i % 7)
			streams = append(streams, st)
		}
		msgs = append(msgs, s.messages()...)
	}
	for i := range msgs {
		msgs[i].Index = i + 1
	}
	calls := call.Build(msgs, call.Options{})
	call.Attach(calls, streams)
	in := &Input{Messages: msgs, Calls: calls, Streams: streams, Config: Config{LongCall: time.Second}}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Run(in, RunOptions{}); err != nil {
			b.Fatal(err)
		}
	}
}
