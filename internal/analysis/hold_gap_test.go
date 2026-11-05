package analysis

import (
	"testing"
	"time"

	"github.com/sotoz/sipcurious/internal/call"
)

// Regression: the demo capture hold-resume.pcap (testdata/samples/README.md)
// holds each call for 2 s; the RTP silence during hold is not a media fault.
func TestGapExplainedByHold(t *testing.T) {
	media := func(at time.Duration, hold bool) call.Media {
		return call.Media{Time: t0.Add(at), Type: "audio", Hold: hold}
	}
	held := &call.Call{
		End:   t0.Add(10 * time.Second),
		Media: []call.Media{media(0, false), media(4*time.Second, true), media(6*time.Second, false)},
	}
	open := &call.Call{
		End:   t0.Add(10 * time.Second),
		Media: []call.Media{media(0, false), media(4*time.Second, true)},
	}
	tests := []struct {
		name string
		c    *call.Call
		gap  time.Duration
		want bool
	}{
		{"nil call", nil, 2 * time.Second, false},
		{"no hold", &call.Call{Media: []call.Media{media(0, false)}}, 2 * time.Second, false},
		{"gap of the hold", held, 2013 * time.Millisecond, true},
		{"gap longer than the hold", held, 5 * time.Second, false},
		{"hold never resumed", open, 5 * time.Second, true},
		{"hold never resumed, gap beyond call", open, 9 * time.Second, false},
	}
	for _, tc := range tests {
		if got := gapExplainedByHold(tc.c, tc.gap, time.Second); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}
