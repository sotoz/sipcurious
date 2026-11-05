package capture_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"github.com/sotoz/sipcurious/internal/capture"
)

type rawWant struct {
	ts      time.Time
	lt      layers.LinkType
	data    string
	orig    int
	ifIndex int
}

var rawT0 = time.Date(2026, 3, 4, 10, 0, 0, 123456789, time.UTC)

func collectRaw(t *testing.T, r func(func(capture.RawPacket) bool) error) []rawWant {
	t.Helper()
	var got []rawWant
	if err := r(func(p capture.RawPacket) bool {
		if p.Index != len(got)+1 {
			t.Errorf("index = %d, want %d", p.Index, len(got)+1)
		}
		got = append(got, rawWant{p.Time, p.LinkType, string(p.Data), p.OrigLen, p.InterfaceID})
		return true
	}); err != nil {
		t.Fatal(err)
	}
	return got
}

func TestReadRawFormats(t *testing.T) {
	// classic nanosecond pcap with a snaplen-cut record
	var pc bytes.Buffer
	w := pcapgo.NewWriterNanos(&pc)
	if err := w.WriteFileHeader(65535, layers.LinkTypeLinuxSLL); err != nil {
		t.Fatal(err)
	}
	pcWant := []rawWant{
		{rawT0, layers.LinkTypeLinuxSLL, "abcdef", 6, 0},
		{rawT0.Add(time.Second), layers.LinkTypeLinuxSLL, "xy", 100, 0},
	}
	for _, r := range pcWant {
		if err := w.WritePacket(gopacket.CaptureInfo{Timestamp: r.ts, CaptureLength: len(r.data), Length: r.orig}, []byte(r.data)); err != nil {
			t.Fatal(err)
		}
	}

	// pcapng with two interfaces of different link types
	var ng bytes.Buffer
	nw, err := pcapgo.NewNgWriter(&ng, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := nw.AddInterface(pcapgo.NgInterface{Name: "raw0", LinkType: layers.LinkTypeRaw, TimestampResolution: 9}); err != nil {
		t.Fatal(err)
	}
	ngWant := []rawWant{
		{rawT0, layers.LinkTypeEthernet, "eth-frame", 9, 0},
		{rawT0.Add(time.Millisecond), layers.LinkTypeRaw, "ip-packet!", 10, 1},
		{rawT0.Add(2 * time.Millisecond), layers.LinkTypeEthernet, "eth-2", 50, 0},
	}
	for _, r := range ngWant {
		ci := gopacket.CaptureInfo{Timestamp: r.ts, CaptureLength: len(r.data), Length: r.orig, InterfaceIndex: r.ifIndex}
		if err := nw.WritePacket(ci, []byte(r.data)); err != nil {
			t.Fatal(err)
		}
	}
	if err := nw.Flush(); err != nil {
		t.Fatal(err)
	}

	gz := func(b []byte) []byte {
		var z bytes.Buffer
		zw := gzip.NewWriter(&z)
		zw.Write(b)
		zw.Close()
		return z.Bytes()
	}
	tests := []struct {
		name string
		data []byte
		want []rawWant
	}{
		{"pcap", pc.Bytes(), pcWant},
		{"pcap.gz", gz(pc.Bytes()), pcWant},
		{"pcapng multi-interface", ng.Bytes(), ngWant},
		{"pcapng.gz", gz(ng.Bytes()), ngWant},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "in")
			if err := os.WriteFile(path, tc.data, 0o644); err != nil {
				t.Fatal(err)
			}
			check := func(name string, got []rawWant) {
				if len(got) != len(tc.want) {
					t.Fatalf("%s: %d records, want %d", name, len(got), len(tc.want))
				}
				for i := range got {
					if !got[i].ts.Equal(tc.want[i].ts) || got[i] != tc.want[i] {
						t.Errorf("%s: record %d = %+v, want %+v", name, i+1, got[i], tc.want[i])
					}
				}
			}
			check("file", collectRaw(t, func(fn func(capture.RawPacket) bool) error {
				return capture.ReadRaw(context.Background(), path, fn)
			}))
			// the stdin-like path: any io.Reader
			check("reader", collectRaw(t, func(fn func(capture.RawPacket) bool) error {
				return capture.ReadRawFrom(context.Background(), "-", bytes.NewReader(tc.data), fn)
			}))
		})
	}
}

func TestReadRawStopAndErrors(t *testing.T) {
	var pc bytes.Buffer
	w := pcapgo.NewWriter(&pc)
	_ = w.WriteFileHeader(65535, layers.LinkTypeEthernet)
	for range 5 {
		_ = w.WritePacket(gopacket.CaptureInfo{Timestamp: rawT0, CaptureLength: 4, Length: 4}, []byte("data"))
	}
	ctx := context.Background()

	n := 0
	err := capture.ReadRawFrom(ctx, "x", bytes.NewReader(pc.Bytes()), func(capture.RawPacket) bool { n++; return n < 2 })
	if err != nil || n != 2 {
		t.Errorf("stop: n=%d err=%v, want 2 nil", n, err)
	}

	// cut in the middle of the 4th record: 3 records delivered, ErrTruncated
	cut := pc.Bytes()[:24+3*20+16+2]
	n = 0
	err = capture.ReadRawFrom(ctx, "x", bytes.NewReader(cut), func(capture.RawPacket) bool { n++; return true })
	if !errors.Is(err, capture.ErrTruncated) || n != 3 {
		t.Errorf("truncated: n=%d err=%v", n, err)
	}

	err = capture.ReadRawFrom(ctx, "x", bytes.NewReader([]byte("not a capture file at all")), func(capture.RawPacket) bool { return true })
	if err == nil || errors.Is(err, capture.ErrTruncated) {
		t.Errorf("garbage: err=%v", err)
	}
	if err := capture.ReadRaw(ctx, filepath.Join(t.TempDir(), "missing.pcap"), nil); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing file: err=%v", err)
	}

	cctx, cancel := context.WithCancel(ctx)
	cancel()
	err = capture.ReadRawFrom(cctx, "x", bytes.NewReader(pc.Bytes()), func(capture.RawPacket) bool { return true })
	if !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled: err=%v", err)
	}
}

func TestReadRawMatchesReadIndex(t *testing.T) {
	const path = "../../testdata/samples/mixed-busy-hour.pcapng"
	n := 0
	if err := capture.ReadRaw(context.Background(), path, func(capture.RawPacket) bool { n++; return true }); err != nil {
		t.Fatal(err)
	}
	res, err := capture.Read(context.Background(), []string{path}, capture.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if n != res.Packets || n != 1574 {
		t.Errorf("ReadRaw saw %d records, Read %d, want 1574", n, res.Packets)
	}
}
