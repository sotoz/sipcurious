package analysis

import (
	"testing"
	"time"

	"github.com/sotoz/sipcurious/internal/call"
	"github.com/sotoz/sipcurious/internal/rtp"
	"github.com/sotoz/sipcurious/internal/trace"
)

// FuzzRun feeds hostile header text and numbers through call.Build, Attach and
// every rule: nothing may panic.
func FuzzRun(f *testing.F) {
	f.Add("INVITE sip:a SIP/2.0\r\nVia: SIP/2.0/UDP 10.0.0.1\r\nContact: <sip:a@192.168.0.1>\r\nMax-Forwards: 1\r\n\r\n", "v=0\r\nc=IN IP4 10.0.0.1\r\nm=audio 4000 RTP/AVP 0\r\n", 200, uint8(3))
	f.Add("SIP/2.0 401 x\r\nWWW-Authenticate: Digest stale=true\r\nReason: Q.850;cause=\r\n\r\n", "", 488, uint8(0))
	f.Fuzz(func(t *testing.T, head, body string, code int, n uint8) {
		raw := head + "\r\n" + body
		var msgs []trace.Message
		for i := 0; i < int(n%8)+1; i++ {
			m := trace.Message{
				File: "f", Index: i + 1, Time: t0.Add(time.Duration(i) * 400 * time.Millisecond),
				Src: netipAP("203.0.113.1:5060").Addr(), SrcPort: 5060, Dst: netipAP("10.0.0.1:5060").Addr(), DstPort: 5060,
				IsRequest: i%2 == 0, Method: []string{"INVITE", "REGISTER", "BYE"}[i%3], StatusCode: code, CallID: "c" + itoa(i%2),
				Via: head, Contact: head, From: head, To: head, CSeq: "1 INVITE", Raw: raw, HeaderEnd: len(head) + 2,
			}
			msgs = append(msgs, m)
		}
		in := &Input{Messages: msgs, Config: Config{LongCall: time.Second}}
		in.Calls = call.Build(msgs, call.Options{})
		in.Streams = []rtp.Stream{mkStream("10.0.0.1:4000", "10.0.1.2:6000", 0, time.Minute, 1)}
		call.Attach(in.Calls, in.Streams)
		fs, err := Run(in, RunOptions{})
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range fs {
			if f.Rule == "" {
				t.Fatal("finding without rule")
			}
		}
	})
}
