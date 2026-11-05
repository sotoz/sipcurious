package engine

import (
	"context"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"testing"

	"github.com/sotoz/sipcurious/internal/analysis"
)

func sample(name string) string {
	_, f, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(f), "..", "..", "testdata", "samples", name)
}

func TestLoad(t *testing.T) {
	tests := []struct {
		name         string
		files        []string
		rtp          bool
		packets, sip int
		streams      int
		calls        int
	}{
		{"basic", []string{"basic-call.pcap"}, true, 507, 7, 2, 1},
		{"basic sip only", []string{"basic-call.pcap"}, false, 507, 7, 0, 1},
		{"bad-media", []string{"bad-media.pcap"}, true, 803, 21, 3, 3},
		{"two files merged", []string{"basic-call.pcap", "busy-and-reject.pcap"}, true, 520, 20, 2, 4},
		{"mixed (3-packet streams are below the RTP detection threshold)", []string{"mixed-busy-hour.pcapng"}, true, 1574, 1100, 0, 164},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var paths []string
			for _, f := range tc.files {
				paths = append(paths, sample(f))
			}
			d, err := Load(context.Background(), paths, Options{RTP: tc.rtp})
			if err != nil {
				t.Fatal(err)
			}
			if d.Packets != tc.packets || len(d.Messages) != tc.sip || len(d.Streams) != tc.streams || len(d.Calls()) != tc.calls {
				t.Errorf("packets=%d sip=%d streams=%d calls=%d, want %d %d %d %d",
					d.Packets, len(d.Messages), len(d.Streams), len(d.Calls()), tc.packets, tc.sip, tc.streams, tc.calls)
			}
			if !sort.SliceIsSorted(d.Messages, func(i, j int) bool { return d.Messages[i].Time.Before(d.Messages[j].Time) }) {
				t.Error("messages not sorted by time")
			}
			if !tc.rtp && d.Skipped == 0 && tc.packets > tc.sip {
				t.Error("RTP off should leave RTP packets skipped")
			}
		})
	}
}

func TestLoadErrors(t *testing.T) {
	if _, err := Load(context.Background(), []string{"/nonexistent/x.pcap"}, DefaultOptions()); err == nil {
		t.Error("missing file: want error")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Load(ctx, []string{sample("basic-call.pcap")}, DefaultOptions()); err == nil {
		t.Error("cancelled ctx: want error")
	}
}

func TestCallsConcurrent(t *testing.T) {
	d, err := Load(context.Background(), []string{sample("bad-media.pcap")}, DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	res := make([]int, 8)
	for i := range res {
		wg.Add(1)
		go func() { defer wg.Done(); res[i] = len(d.Calls()) }()
	}
	wg.Wait()
	for _, n := range res {
		if n != 3 {
			t.Fatalf("calls = %v", res)
		}
	}
	withMedia := 0
	for _, c := range d.Calls() {
		if len(c.Streams) > 0 {
			withMedia++
		}
	}
	if withMedia != 2 {
		t.Errorf("calls with streams = %d, want 2", withMedia)
	}
	in := d.AnalysisInput(analysis.DefaultConfig())
	if len(in.Calls) != 3 || len(in.Messages) != 21 || len(in.Streams) != 3 {
		t.Errorf("analysis input = %d calls %d msgs %d streams", len(in.Calls), len(in.Messages), len(in.Streams))
	}
	if si := d.StatsInput(); si.Packets != 803 || len(si.Files) != 1 {
		t.Errorf("stats input = %+v", si.Packets)
	}
}

func BenchmarkLoadMixed(b *testing.B) {
	for _, rtpOn := range []bool{true, false} {
		name := "sip-only"
		if rtpOn {
			name = "rtp"
		}
		b.Run(name, func(b *testing.B) {
			p := []string{sample("mixed-busy-hour.pcapng")}
			b.ReportAllocs()
			for b.Loop() {
				d, err := Load(context.Background(), p, Options{RTP: rtpOn})
				if err != nil {
					b.Fatal(err)
				}
				_ = d.Calls()
			}
		})
	}
}
