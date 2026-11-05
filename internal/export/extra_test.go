package export_test

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sotoz/sipcurious/internal/export"
)

func TestGzipInputAndDuplicate(t *testing.T) {
	src, err := os.ReadFile(samples + "bad-media.pcap")
	if err != nil {
		t.Fatal(err)
	}
	gz := filepath.Join(t.TempDir(), "in.pcap.gz")
	var z bytes.Buffer
	zw := gzip.NewWriter(&z)
	zw.Write(src)
	zw.Close()
	if err := os.WriteFile(gz, z.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	calls, _ := load(t, gz)
	out, st := write(t, []string{gz}, export.SelectCalls(calls[:1], true), export.Options{})
	got, _ := load(t, out)
	if len(got) != 1 || len(got[0].Messages) != len(calls[0].Messages) || st.Flows == 0 {
		t.Errorf("gzip round trip: %d calls, stats %+v", len(got), st)
	}
	var buf bytes.Buffer
	if _, err := export.Write(context.Background(), &buf, []string{gz, gz}, export.SelectCalls(calls[:1], true), export.Options{}); err == nil || !strings.Contains(err.Error(), "twice") {
		t.Errorf("duplicate input: err = %v", err)
	}
}

func TestMultiInterfaceInput(t *testing.T) {
	in := "../../testdata/realworld/derived-cloudshark-multiif.pcapng"
	var all []export.Ref
	n := 0
	res := map[export.Ref]struct{}{}
	_ = readAll(t, in, func(i int) {
		n++
		all = append(all, export.Ref{File: in, Index: i})
		res[export.Ref{File: in, Index: i}] = struct{}{}
	})
	out, st := write(t, []string{in}, export.Selector{Packets: res}, export.Options{})
	if st.Written != n {
		t.Fatalf("written %d, input has %d", st.Written, n)
	}
	a, b := frames(t, in), frames(t, out)
	if strings.Join(a, "\n") != strings.Join(b, "\n") {
		t.Error("exporting every record does not reproduce the frames")
	}
	if p, err := exec.LookPath("tshark"); err == nil {
		o, err := exec.Command(p, "-r", out, "-T", "fields", "-e", "frame.number").CombinedOutput()
		if err != nil || len(strings.Fields(string(o))) != n {
			t.Errorf("tshark: %v, %d frames, want %d", err, len(strings.Fields(string(o))), n)
		}
	}
}

// TestStableMergeOnEqualTimestamps: records of equal time keep input order.
func TestStableMergeOnEqualTimestamps(t *testing.T) {
	dir := t.TempDir()
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var paths []string
	sel := export.Selector{Packets: map[export.Ref]struct{}{}}
	for i, name := range []string{"a.pcap", "b.pcap"} {
		p := filepath.Join(dir, name)
		w := newPcap(t, p)
		for k := range 3 {
			w.rec(t0.Add(time.Duration(k)*time.Second), []byte{byte(i), byte(k)})
			sel.Packets[export.Ref{File: p, Index: k + 1}] = struct{}{}
		}
		w.close(t)
		paths = append(paths, p)
	}
	out, _ := write(t, paths, sel, export.Options{Format: export.PCAP})
	b, _ := os.ReadFile(out)
	// records: 16-byte header + 2 bytes after the 24-byte file header
	var order []byte
	for off := 24; off < len(b); off += 18 {
		order = append(order, b[off+16], b[off+17])
	}
	if want := []byte{0, 0, 1, 0, 0, 1, 1, 1, 0, 2, 1, 2}; !bytes.Equal(order, want) {
		t.Errorf("order %v, want %v", order, want)
	}
}

func readAll(t *testing.T, path string, fn func(int)) error {
	t.Helper()
	return rawEach(path, fn)
}

type pcapFile struct {
	f *os.File
	w *bufio.Writer
}

func newPcap(t testing.TB, path string) *pcapFile {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	pf := &pcapFile{f, bufio.NewWriterSize(f, 1<<20)}
	var h [24]byte
	binary.LittleEndian.PutUint32(h[0:], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(h[4:], 2)
	binary.LittleEndian.PutUint16(h[6:], 4)
	binary.LittleEndian.PutUint32(h[16:], 65535)
	binary.LittleEndian.PutUint32(h[20:], 1)
	pf.w.Write(h[:])
	return pf
}

func (p *pcapFile) rec(ts time.Time, data []byte) {
	var h [16]byte
	binary.LittleEndian.PutUint32(h[0:], uint32(ts.Unix()))
	binary.LittleEndian.PutUint32(h[4:], uint32(ts.Nanosecond()/1000))
	binary.LittleEndian.PutUint32(h[8:], uint32(len(data)))
	binary.LittleEndian.PutUint32(h[12:], uint32(len(data)))
	p.w.Write(h[:])
	p.w.Write(data)
}

func (p *pcapFile) close(t testing.TB) {
	t.Helper()
	if err := p.w.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := p.f.Close(); err != nil {
		t.Fatal(err)
	}
}

// udpFrame builds an Ethernet/IPv4/UDP frame (zero UDP checksum).
func udpFrame(src, dst netip.AddrPort, payload []byte) []byte {
	b := make([]byte, 14+20+8+len(payload))
	binary.BigEndian.PutUint16(b[12:], 0x0800)
	ip := b[14:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(20+8+len(payload)))
	ip[8], ip[9] = 64, 17
	s, d := src.Addr().As4(), dst.Addr().As4()
	copy(ip[12:], s[:])
	copy(ip[16:], d[:])
	u := ip[20:]
	binary.BigEndian.PutUint16(u[0:], src.Port())
	binary.BigEndian.PutUint16(u[2:], dst.Port())
	binary.BigEndian.PutUint16(u[4:], uint16(8+len(payload)))
	copy(u[8:], payload)
	return b
}

const benchPackets = 1_000_000

// BenchmarkWrite1M exports 1 of 10 RTP flows plus 1000 SIP-ish records of a
// generated one-million-packet capture.
func BenchmarkWrite1M(b *testing.B) {
	path := filepath.Join(b.TempDir(), "1m.pcap")
	pf := newPcap(b, path)
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	rtpPayload := make([]byte, 172)
	rtpPayload[0] = 0x80
	var flows [10][2]netip.AddrPort
	frames := make([][]byte, len(flows))
	for i := range flows {
		flows[i] = [2]netip.AddrPort{netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, 1, byte(i + 1)}), 16384), netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, 2, byte(i + 1)}), 18000)}
		frames[i] = udpFrame(flows[i][0], flows[i][1], rtpPayload)
	}
	sel := export.Selector{Packets: map[export.Ref]struct{}{}, Flows: []export.Flow{{Src: flows[3][0], Dst: flows[3][1]}}}
	for i := range benchPackets {
		pf.rec(t0.Add(time.Duration(i)*20*time.Microsecond), frames[i%len(frames)])
		if i%1000 == 0 {
			sel.Packets[export.Ref{File: path, Index: i + 1}] = struct{}{}
		}
	}
	pf.close(b)
	fi, _ := os.Stat(path)
	b.SetBytes(fi.Size())
	b.ReportAllocs()
	b.ResetTimer()
	var st export.Stats
	for range b.N {
		var err error
		if st, err = export.Write(context.Background(), io.Discard, []string{path}, sel, export.Options{}); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(benchPackets)*float64(b.N)/b.Elapsed().Seconds(), "pkts/s")
	b.ReportMetric(float64(st.Written), "written")
}
