package stats

import (
	"encoding/json"
	"math"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/sotoz/sipcurious/internal/call"
	"github.com/sotoz/sipcurious/internal/report"
	"github.com/sotoz/sipcurious/internal/rtp"
	"github.com/sotoz/sipcurious/internal/trace"
)

// FuzzCompute feeds hostile field values (odd codes, zero times, huge
// durations, NaN floats) and checks Compute and the renderers stay total.
func FuzzCompute(f *testing.F) {
	f.Add([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20})
	f.Add([]byte{255, 255, 255, 255, 0, 0, 0, 0, 128, 128, 128, 128, 7, 7, 7, 7, 1, 1, 1, 1})
	f.Fuzz(func(t *testing.T, b []byte) {
		r := &byteSrc{b: b}
		var in Input
		for i := r.n(40); i > 0; i-- {
			in.Messages = append(in.Messages, trace.Message{
				Time: time.Unix(int64(r.i32()), int64(r.i32())), IsRequest: r.n(2) == 0,
				Method: []string{"INVITE", "", "BYE"}[r.n(3)], StatusCode: int(r.i32()) % 2000,
				Src: netip.AddrFrom4([4]byte{byte(r.n(256)), 0, 0, 1}), Transport: []string{"UDP", "", "TCP"}[r.n(3)],
			})
		}
		for i := r.n(30); i > 0; i-- {
			c := call.Call{
				CallID: "x", Kind: call.Kind([]string{"call", "", "registration"}[r.n(3)]),
				State:     call.State([]string{"answered", "completed", "failed", "", "cancelled"}[r.n(5)]),
				FinalCode: int(r.i32()) % 2000, Start: time.Unix(int64(r.i32()), 0), Answered: time.Unix(int64(r.i32()), 0),
				End: time.Unix(int64(r.i32()), 0), Ended: time.Unix(int64(r.i32()), 0),
				PDD: time.Duration(int32(r.i32())), SetupTime: time.Duration(r.i32()) << 20, TalkTime: time.Duration(int32(r.i32())),
				UserAgents: []string{"ua" + string(rune('a'+r.n(5)))},
			}
			if r.n(2) == 0 {
				c.Caller = netip.MustParseAddrPort("1.2.3.4:5")
			}
			in.Calls = append(in.Calls, c)
		}
		for i := r.n(20); i > 0; i-- {
			in.Streams = append(in.Streams, rtp.Stream{
				Packets: uint64(r.i32()), LossPct: []float64{0, 1.5, math.NaN(), math.Inf(1), -3}[r.n(5)],
				MOS: []float64{0, 4.2, math.NaN()}[r.n(3)], JitterMean: time.Duration(int32(r.i32())),
				Start: time.Unix(int64(r.i32()), 0), End: time.Unix(int64(r.i32()), 0),
			})
		}
		s := Compute(in)
		if _, err := json.Marshal(s); err != nil && !strings.Contains(err.Error(), "unsupported value") {
			t.Fatal(err)
		}
		var sb strings.Builder
		_ = report.WriteSections(&sb, report.FormatTable, s.Sections(report.Options{UTC: true}), report.Options{UTC: true})
		_ = s.KeyValues()
	})
}

type byteSrc struct {
	b []byte
	i int
}

func (r *byteSrc) next() byte {
	if r.i >= len(r.b) {
		return 0
	}
	v := r.b[r.i]
	r.i++
	return v
}

func (r *byteSrc) n(m int) int { return int(r.next()) % m }

func (r *byteSrc) i32() uint32 {
	return uint32(r.next()) | uint32(r.next())<<8 | uint32(r.next())<<16 | uint32(r.next())<<24
}
