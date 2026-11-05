package capture_test

import (
	"bufio"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/sotoz/sipcurious/internal/capture"
	"github.com/sotoz/sipcurious/internal/sip"
)

const benchPackets = 1_000_000

var (
	benchOnce sync.Once
	benchPath string
	benchDir  string
)

// benchCapture writes (once per process) a deterministic capture of
// benchPackets Ethernet packets: 80% UDP with a 172-byte payload (RTP-sized),
// 15% SIP over UDP, 5% other (ARP and TCP without SIP).
func benchCapture(b *testing.B) string {
	b.Helper()
	benchOnce.Do(func() {
		dir, err := os.MkdirTemp("", "capbench")
		if err != nil {
			b.Fatal(err)
		}
		benchDir = dir
		benchPath = filepath.Join(dir, "1m.pcap")
		f, err := os.Create(benchPath)
		if err != nil {
			b.Fatal(err)
		}
		w := bufio.NewWriterSize(f, 1<<20)

		media := flow{pbAddr("10.0.0.10"), pbAddr("10.0.0.20"), 16384, 16386}
		sigf := flow{pbAddr("10.0.0.1"), pbAddr("10.0.0.2"), 5060, 5060}
		rtp := make([]byte, 172)
		rtp[0] = 0x80
		pkts := [][]byte{
			pbEth(0x0800, media.udpIP(string(rtp))),
			pbEth(0x0800, sigf.udpIP(pbSIP("INVITE", "bench-call@example.com", 1))),
			pbEth(0x0806, make([]byte, 28)),
			pbEth(0x0800, flow{pbAddr("10.0.0.3"), pbAddr("10.0.0.4"), 40000, 443}.tcpIP(1, pbACK|pbPSH, "\x16\x03\x03\x00\x20"+string(rtp[:60]))),
		}
		hdr := pbPcap(pbPcapOpts{lt: layers.LinkTypeEthernet})
		_, _ = w.Write(hdr)
		var rec [16]byte
		for i := range benchPackets {
			var p []byte
			switch m := i % 20; {
			case m < 16:
				p = pkts[0]
			case m < 19:
				p = pkts[1]
			case i%40 == 19:
				p = pkts[2]
			default:
				p = pkts[3]
			}
			ts := time.Unix(1_700_000_000, 0).Add(time.Duration(i) * 20 * time.Microsecond)
			binary.LittleEndian.PutUint32(rec[0:], uint32(ts.Unix()))
			binary.LittleEndian.PutUint32(rec[4:], uint32(ts.Nanosecond()/1000))
			binary.LittleEndian.PutUint32(rec[8:], uint32(len(p)))
			binary.LittleEndian.PutUint32(rec[12:], uint32(len(p)))
			_, _ = w.Write(rec[:])
			_, _ = w.Write(p)
		}
		if err := w.Flush(); err != nil {
			b.Fatal(err)
		}
		_ = f.Close()
	})
	if benchPath == "" {
		b.Fatal("benchmark capture was not generated")
	}
	return benchPath
}

func TestMain(m *testing.M) {
	code := m.Run()
	if benchDir != "" {
		_ = os.RemoveAll(benchDir)
	}
	os.Exit(code)
}

type noop struct{}

func (noop) Handle(*capture.Packet) bool { return false }

func benchRead(b *testing.B, opt capture.Options) {
	path := benchCapture(b)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		res, err := capture.Read(context.Background(), []string{path}, opt)
		if err != nil || res.Packets != benchPackets {
			b.Fatalf("packets %d err %v", res.Packets, err)
		}
	}
	b.ReportMetric(float64(benchPackets)*float64(b.N)/b.Elapsed().Seconds(), "pkts/s")
}

// BenchmarkReadNoop measures file reading plus L2-L4 decoding with a handler
// that consumes nothing.
func BenchmarkReadNoop(b *testing.B) {
	benchRead(b, capture.Options{Handlers: []capture.Factory{func(string) capture.Handler { return noop{} }}})
}

// BenchmarkReadSIP adds the SIP handler (parses and stores 15% of the packets).
func BenchmarkReadSIP(b *testing.B) {
	benchRead(b, capture.Options{Handlers: []capture.Factory{sip.NewHandler(sip.ParseOptions{})}})
}

// BenchmarkReadNoHandlers is the floor: record reading only.
func BenchmarkReadNoHandlers(b *testing.B) { benchRead(b, capture.Options{}) }

// BenchmarkGopacketBaseline is what the pre-v2 reader did per packet: decode
// every record with gopacket (lazy, no copy) and walk its layers, no handlers.
func BenchmarkGopacketBaseline(b *testing.B) {
	path := benchCapture(b)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		src, err := capture.NewSource(mustOpen(b, path))
		if err != nil {
			b.Fatal(err)
		}
		n := 0
		for {
			data, _, _, err := src.Next()
			if err != nil {
				break
			}
			pkt := gopacket.NewPacket(data, layers.LinkTypeEthernet, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
			for _, l := range pkt.Layers() {
				if u, ok := l.(*layers.UDP); ok {
					n += len(u.Payload)
				}
			}
		}
	}
	b.ReportMetric(float64(benchPackets)*float64(b.N)/b.Elapsed().Seconds(), "pkts/s")
}

func mustOpen(b *testing.B, path string) *os.File {
	f, err := os.Open(path)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = f.Close() })
	return f
}
