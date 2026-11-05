package capture_test

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gopacket/gopacket/layers"

	"github.com/sotoz/sipcurious/internal/capture"
)

// recorder keeps a copy of every packet it sees (Packet and Payload are reused
// by the reader, so they must be copied) and consumes those for which take
// returns true.
type recorder struct {
	file     string
	take     func(*capture.Packet) bool
	pkts     []capture.Packet
	finished int
}

func (r *recorder) Handle(p *capture.Packet) bool {
	c := *p
	c.Payload = bytes.Clone(p.Payload)
	r.pkts = append(r.pkts, c)
	return r.take == nil || r.take(p)
}

func (r *recorder) Finish() { r.finished++ }

func recordAll(file string) capture.Handler { return &recorder{file: file} }

func readRecorded(t *testing.T, path string, mk ...capture.Factory) (capture.Result, []*recorder) {
	t.Helper()
	res, err := capture.Read(context.Background(), []string{path}, capture.Options{Handlers: mk})
	if err != nil {
		t.Fatal(err)
	}
	var rs []*recorder
	for _, h := range res.Files[0].Handlers {
		rs = append(rs, h.(*recorder))
	}
	return res, rs
}

func TestPacketFields(t *testing.T) {
	f := flow{pbAddr("10.1.1.1"), pbAddr("10.2.2.2"), 40000, 5060}
	f6 := flow{pbAddr("2001:db8::1"), pbAddr("2001:db8::2"), 40001, 5061}
	eth := func(v6 bool, ip []byte) []byte { return pbEth(pbEtherType(v6), ip) }
	recs := []pbRec{
		{ts: mt0, data: eth(false, f.udpIP("udp-payload"))},
		{ts: mt0.Add(time.Second), data: eth(false, f.tcpIP(0xfffffff0, pbSYN, ""))},
		{ts: mt0.Add(2 * time.Second), data: eth(true, f6.tcpIP(77, pbACK|pbPSH|pbFIN, "tcp-payload"))},
		{ts: mt0.Add(3 * time.Second), data: eth(false, f.tcpIP(5, pbRST, ""))},
		{ts: mt0.Add(4 * time.Second), data: eth(false, pbIPv4(f.src, f.dst, pbProtoSCTP, pbSCTP(f.sport, f.dpt, pbSCTPData(1, 0, []byte("sctp-payload!"))), pbIP4Opts{}))},
		{ts: mt0.Add(5 * time.Second), data: pbEth(0x0806, make([]byte, 28))}, // ARP: never reaches a handler
	}
	path := pbWriteFile(t, "x.pcap", pbPcap(pbPcapOpts{lt: layers.LinkTypeEthernet}, recs...))
	res, rs := readRecorded(t, path, func(file string) capture.Handler { return &recorder{file: file} })
	if res.Packets != 6 || res.Skipped != 1 {
		t.Errorf("packets/skipped = %d/%d, want 6/1 (ARP)", res.Packets, res.Skipped)
	}
	want := []capture.Packet{
		{File: path, Index: 1, Time: mt0, Src: f.src, Dst: f.dst, SrcPort: 40000, DstPort: 5060, Transport: "UDP", Payload: []byte("udp-payload")},
		{File: path, Index: 2, Time: mt0.Add(time.Second), Src: f.src, Dst: f.dst, SrcPort: 40000, DstPort: 5060, Transport: "TCP", TCPSeq: 0xfffffff0, TCPSYN: true, Payload: []byte{}},
		{File: path, Index: 3, Time: mt0.Add(2 * time.Second), Src: f6.src, Dst: f6.dst, SrcPort: 40001, DstPort: 5061, Transport: "TCP", TCPSeq: 77, TCPFIN: true, Payload: []byte("tcp-payload")},
		{File: path, Index: 4, Time: mt0.Add(3 * time.Second), Src: f.src, Dst: f.dst, SrcPort: 40000, DstPort: 5060, Transport: "TCP", TCPSeq: 5, TCPRST: true, Payload: []byte{}},
		{File: path, Index: 5, Time: mt0.Add(4 * time.Second), Src: f.src, Dst: f.dst, SrcPort: 40000, DstPort: 5060, Transport: "SCTP", Payload: []byte("sctp-payload!")},
	}
	got := rs[0].pkts
	if len(got) != len(want) {
		t.Fatalf("handler saw %d packets, want %d", len(got), len(want))
	}
	for i := range want {
		g, w := got[i], want[i]
		if g.File != w.File || g.Index != w.Index || !g.Time.Equal(w.Time) || g.Src != w.Src || g.Dst != w.Dst ||
			g.SrcPort != w.SrcPort || g.DstPort != w.DstPort || g.Transport != w.Transport ||
			g.TCPSeq != w.TCPSeq || g.TCPSYN != w.TCPSYN || g.TCPFIN != w.TCPFIN || g.TCPRST != w.TCPRST ||
			!bytes.Equal(g.Payload, w.Payload) || g.Partial || g.Time.Location() != time.UTC {
			t.Errorf("packet %d:\n got %+v\nwant %+v", i+1, g, w)
		}
	}
	if rs[0].finished != 1 {
		t.Errorf("Finish called %d times, want 1", rs[0].finished)
	}
}

func TestHandlerPriorityAndSkipped(t *testing.T) {
	f := flow4
	recs := []pbRec{
		{ts: mt0, data: pbEth(0x0800, f.udpIP("one"))},
		{ts: mt0, data: pbEth(0x0800, f.udpIP("two"))},
		{ts: mt0, data: pbEth(0x0800, f.udpIP("three"))},
	}
	path := pbWriteFile(t, "x.pcap", pbPcap(pbPcapOpts{lt: layers.LinkTypeEthernet}, recs...))
	takeOne := func(file string) capture.Handler {
		return &recorder{file: file, take: func(p *capture.Packet) bool { return string(p.Payload) == "one" }}
	}
	takeTwo := func(file string) capture.Handler {
		return &recorder{file: file, take: func(p *capture.Packet) bool { return string(p.Payload) == "two" }}
	}
	res, rs := readRecorded(t, path, takeOne, takeTwo)
	if len(rs) != 2 || len(rs[0].pkts) != 3 || len(rs[1].pkts) != 2 {
		t.Fatalf("first handler saw %d, second saw %d packets; want 3 and 2 (first consumer wins)", len(rs[0].pkts), len(rs[1].pkts))
	}
	if res.Skipped != 1 || res.Files[0].Skipped != 1 || res.Packets != 3 {
		t.Errorf("packets/skipped = %d/%d, want 3/1", res.Packets, res.Skipped)
	}
	if hs := capture.HandlersOf[*recorder](res); len(hs) != 2 || hs[0] != rs[0] {
		t.Errorf("HandlersOf = %v", hs)
	}
}

func TestNoHandlers(t *testing.T) {
	res, err := capture.Read(context.Background(), []string{samplePCAP}, capture.Options{})
	if err != nil || res.Packets != samplePackets || res.Skipped != samplePackets {
		t.Fatalf("res = %+v err = %v", res, err)
	}
}

// Every file gets its own handler instance; the result keeps input order and
// warnings carry the path.
func TestPerFileHandlersAndOrder(t *testing.T) {
	f := flow4
	mk := func(name string, n int, cut bool) string {
		var recs []pbRec
		for i := range n {
			recs = append(recs, pbRec{ts: mt0.Add(time.Duration(i) * time.Millisecond), data: pbEth(0x0800, f.udpIP(name))})
		}
		data := pbPcap(pbPcapOpts{lt: layers.LinkTypeEthernet}, recs...)
		if cut {
			data = data[:len(data)-3]
		}
		return pbWriteFile(t, name+".pcap", data)
	}
	paths := []string{mk("a", 3, false), mk("b", 5, true), mk("c", 1, false)}
	var (
		mu    sync.Mutex
		files []string
	)
	res, err := capture.Read(context.Background(), paths, capture.Options{Handlers: []capture.Factory{func(file string) capture.Handler {
		mu.Lock()
		files = append(files, file)
		mu.Unlock()
		return &recorder{file: file}
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 3 {
		t.Fatalf("factory called %d times, want once per file", len(files))
	}
	for i, p := range paths {
		fr := res.Files[i]
		if fr.Path != p || len(fr.Handlers) != 1 || fr.Handlers[0].(*recorder).file != p {
			t.Errorf("file %d: %+v", i, fr)
		}
	}
	if res.Files[0].Packets != 3 || res.Files[1].Packets != 4 || res.Files[2].Packets != 1 || res.Packets != 8 {
		t.Errorf("packets = %d/%d/%d total %d, want 3/4/1 total 8", res.Files[0].Packets, res.Files[1].Packets, res.Files[2].Packets, res.Packets)
	}
	if len(res.Warnings) != 1 || len(res.Files[1].Warnings) != 1 || !strings.Contains(res.Warnings[0], paths[1]) {
		t.Errorf("warnings = %q", res.Warnings)
	}
}

func TestErrorsWrapPath(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.pcap")
	if err := os.WriteFile(bad, []byte("this is not a capture file at all"), 0o644); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "missing.pcap")
	for _, p := range []string{bad, missing} {
		_, err := capture.Read(context.Background(), []string{samplePCAP, p}, capture.Options{})
		if err == nil || !strings.Contains(err.Error(), p) {
			t.Errorf("err = %v, want it to name %s", err, p)
		}
	}
	if _, err := capture.Read(context.Background(), []string{missing}, capture.Options{}); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("single missing file: err = %v, want ErrNotExist", err)
	}
}

func TestStdin(t *testing.T) {
	data := pbPcap(pbPcapOpts{lt: layers.LinkTypeEthernet}, pbRec{ts: mt0, data: pbEth(0x0800, flow4.udpIP("stdin"))})
	var gz bytes.Buffer
	w := newGzip(&gz)
	_, _ = w.Write(data)
	_ = w.Close()
	ng := newPbNG(false).shb().idb(layers.LinkTypeEthernet, 0).epb(0, uint64(mt0.UnixMicro()), pbEth(0x0800, flow4.udpIP("stdin")), 0).bytes()
	var ngz bytes.Buffer
	w = newGzip(&ngz)
	_, _ = w.Write(ng)
	_ = w.Close()

	for name, b := range map[string][]byte{"pcap": data, "pcap.gz": gz.Bytes(), "pcapng": ng, "pcapng.gz": ngz.Bytes()} {
		t.Run(name, func(t *testing.T) {
			fr, err := capture.ReadStream(context.Background(), "-", bytes.NewReader(b), capture.Options{Handlers: []capture.Factory{recordAll}})
			if err != nil {
				t.Fatal(err)
			}
			r := fr.Handlers[0].(*recorder)
			if fr.Path != "-" || fr.Packets != 1 || len(r.pkts) != 1 || r.pkts[0].File != "-" || string(r.pkts[0].Payload) != "stdin" {
				t.Fatalf("fr = %+v pkts = %+v", fr, r.pkts)
			}
		})
	}

	// And through os.Stdin itself.
	rd, wr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdin
	os.Stdin = rd
	defer func() { os.Stdin = old }()
	go func() { _, _ = wr.Write(data); _ = wr.Close() }()
	res, err := capture.Read(context.Background(), []string{"-"}, capture.Options{Handlers: []capture.Factory{recordAll}})
	if err != nil || res.Packets != 1 || res.Files[0].Path != "-" {
		t.Fatalf("res = %+v err = %v", res, err)
	}
}

func TestGzipPcapng(t *testing.T) {
	var gz bytes.Buffer
	w := newGzip(&gz)
	ng := newPbNG(true).shb().idb(layers.LinkTypeEthernet, 0).epb(0, uint64(mt0.UnixMicro()), pbEth(0x0800, flow4.udpIP("zz")), 0).bytes()
	_, _ = w.Write(ng)
	_ = w.Close()
	path := pbWriteFile(t, "x.pcapng.gz", gz.Bytes())
	res, rs := readRecorded(t, path, recordAll)
	if res.Packets != 1 || len(rs[0].pkts) != 1 || !rs[0].pkts[0].Time.Equal(mt0) {
		t.Fatalf("res = %+v pkts = %+v", res, rs[0].pkts)
	}
}

func TestPartialFlag(t *testing.T) {
	f := flow4
	full := pbEth(0x0800, f.udpIP(strings.Repeat("x", 200)))
	cut := full[:14+20+8+50] // snaplen cut inside the payload
	tcp := pbEth(0x0800, f.tcpIP(9, pbACK, strings.Repeat("y", 200)))
	path := pbWriteFile(t, "x.pcap", pbPcap(pbPcapOpts{lt: layers.LinkTypeEthernet},
		pbRec{ts: mt0, data: full},
		pbRec{ts: mt0, data: cut, orig: len(full)},
		pbRec{ts: mt0, data: tcp[:14+20+20+10], orig: len(tcp)},
	))
	_, rs := readRecorded(t, path, recordAll)
	got := rs[0].pkts
	if len(got) != 3 || got[0].Partial || !got[1].Partial || !got[2].Partial {
		t.Fatalf("partial flags = %v", func() (o []bool) {
			for _, p := range got {
				o = append(o, p.Partial)
			}
			return
		}())
	}
	if len(got[1].Payload) != 50 || len(got[2].Payload) != 10 {
		t.Errorf("cut payloads = %d, %d, want 50, 10", len(got[1].Payload), len(got[2].Payload))
	}
}

// Fragments are reassembled and delivered once, as the packet that completed
// the datagram; the endpoints are the innermost IP header's.
func TestReassembledPacketIsNotPartial(t *testing.T) {
	f := flow4
	payload := []byte(strings.Repeat("0123456789", 30))
	l4 := pbUDP(f.src, f.dst, f.sport, f.dpt, payload)
	cutAt := 8 * 20
	frag := func(off int, more bool, data []byte) []byte {
		return pbEth(0x0800, pbIPv4(f.src, f.dst, pbProtoUDP, data, pbIP4Opts{id: 7, frag: uint16(off/8) | map[bool]uint16{true: 0x2000}[more]}))
	}
	path := pbWriteFile(t, "x.pcap", pbPcap(pbPcapOpts{lt: layers.LinkTypeEthernet},
		pbRec{ts: mt0, data: frag(0, true, l4[:cutAt])},
		pbRec{ts: mt0.Add(time.Millisecond), data: frag(cutAt, false, l4[cutAt:])},
	))
	res, rs := readRecorded(t, path, recordAll)
	if res.Packets != 2 || len(rs[0].pkts) != 1 {
		t.Fatalf("packets %d, delivered %d", res.Packets, len(rs[0].pkts))
	}
	p := rs[0].pkts[0]
	if p.Index != 2 || !bytes.Equal(p.Payload, payload) || p.Partial || p.Transport != "UDP" || p.SrcPort != f.sport {
		t.Fatalf("packet = index %d len %d partial %v", p.Index, len(p.Payload), p.Partial)
	}
	if res.Skipped != 1 { // the first fragment is not a packet any handler saw
		t.Errorf("skipped = %d, want 1", res.Skipped)
	}
}

func TestIPv4MappedIPv6IsUnmapped(t *testing.T) {
	f := flow{pbAddr("::ffff:10.1.2.3"), pbAddr("::ffff:10.1.2.4"), 5060, 5060}
	path := pbWriteFile(t, "x.pcap", pbPcap(pbPcapOpts{lt: layers.LinkTypeEthernet}, pbRec{ts: mt0, data: pbEth(0x86dd, f.udpIP("m"))}))
	_, rs := readRecorded(t, path, recordAll)
	p := rs[0].pkts[0]
	if p.Src != netip.MustParseAddr("10.1.2.3") || !p.Dst.Is4() {
		t.Fatalf("src/dst = %v/%v", p.Src, p.Dst)
	}
}
