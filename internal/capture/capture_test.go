package capture_test

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"github.com/sotoz/sipcurious/internal/capture"
	"github.com/sotoz/sipcurious/internal/trace"
)

const (
	samplePCAP    = "../../testdata/aaa.pcap"
	samplePackets = 691
	sampleSIP     = 81
	sampleCallID  = "29858147-465b0752@29858051-465b07b2"
)

var t0 = time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)

const (
	inviteMsg = "INVITE sip:bob@example.com SIP/2.0\r\nCall-ID: c1\r\nFrom: <sip:a@x>\r\nTo: <sip:b@x>\r\nCSeq: 1 INVITE\r\n\r\n"
	okMsg     = "SIP/2.0 200 OK\r\nCall-ID: c1\r\nCSeq: 1 INVITE\r\n\r\n"
)

// frame builds a link-layer packet for the given link type carrying payload
// over proto ("udp", "tcp") and IP version of src/dst.
type frame struct {
	lt       layers.LinkType
	proto    string
	src, dst string
	sp, dp   uint16
	seq      uint32 // TCP sequence number, default 1
	vlan     bool
	payload  string
}

func (f frame) bytes(t *testing.T) []byte {
	t.Helper()
	src, dst := netip.MustParseAddr(f.src), netip.MustParseAddr(f.dst)
	var ls []gopacket.SerializableLayer
	var netType layers.EthernetType

	switch f.lt {
	case layers.LinkTypeEthernet:
		eth := &layers.Ethernet{
			SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11},
		}
		if src.Is4() {
			eth.EthernetType = layers.EthernetTypeIPv4
		} else {
			eth.EthernetType = layers.EthernetTypeIPv6
		}
		netType = eth.EthernetType
		if f.vlan {
			eth.EthernetType = layers.EthernetTypeDot1Q
			ls = append(ls, eth, &layers.Dot1Q{VLANIdentifier: 42, Type: netType})
		} else {
			ls = append(ls, eth)
		}
	case layers.LinkTypeLinuxSLL:
		proto := layers.EthernetTypeIPv4
		if src.Is6() {
			proto = layers.EthernetTypeIPv6
		}
		// LinuxSLL has no serializer: emit the 16-byte cooked header by hand.
		ls = append(ls, gopacket.Payload([]byte{
			0, 0, 0, 1, 0, 6, 0, 1, 2, 3, 4, 5, 0, 0, byte(proto >> 8), byte(proto),
		}))
	case layers.LinkTypeRaw:
	default:
		t.Fatalf("unsupported link type %v in test helper", f.lt)
	}

	var ip4 *layers.IPv4
	var ip6 *layers.IPv6
	ipProto := layers.IPProtocolUDP
	if f.proto == "tcp" {
		ipProto = layers.IPProtocolTCP
	}
	if src.Is4() {
		ip4 = &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: ipProto, SrcIP: src.AsSlice(), DstIP: dst.AsSlice()}
		ls = append(ls, ip4)
	} else {
		ip6 = &layers.IPv6{Version: 6, HopLimit: 64, NextHeader: ipProto, SrcIP: src.AsSlice(), DstIP: dst.AsSlice()}
		ls = append(ls, ip6)
	}
	var nl gopacket.NetworkLayer = ip4
	if ip4 == nil {
		nl = ip6
	}
	switch f.proto {
	case "udp":
		u := &layers.UDP{SrcPort: layers.UDPPort(f.sp), DstPort: layers.UDPPort(f.dp)}
		if err := u.SetNetworkLayerForChecksum(nl); err != nil {
			t.Fatalf("checksum: %v", err)
		}
		ls = append(ls, u)
	case "tcp":
		tc := &layers.TCP{SrcPort: layers.TCPPort(f.sp), DstPort: layers.TCPPort(f.dp), Seq: max(f.seq, 1), ACK: true, PSH: true, Window: 100}
		if err := tc.SetNetworkLayerForChecksum(nl); err != nil {
			t.Fatalf("checksum: %v", err)
		}
		ls = append(ls, tc)
	default:
		t.Fatalf("bad proto %q", f.proto)
	}
	ls = append(ls, gopacket.Payload(f.payload))

	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ls...); err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return buf.Bytes()
}

func ci(ts time.Time, n int) gopacket.CaptureInfo {
	return gopacket.CaptureInfo{Timestamp: ts, CaptureLength: n, Length: n}
}

// writePCAP writes a classic pcap file with a single link type.
func writePCAP(t *testing.T, path string, lt layers.LinkType, pkts []timedPacket) {
	t.Helper()
	var buf bytes.Buffer
	w := pcapgo.NewWriter(&buf)
	if err := w.WriteFileHeader(65535, lt); err != nil {
		t.Fatalf("file header: %v", err)
	}
	for _, p := range pkts {
		if err := w.WritePacket(ci(p.ts, len(p.data)), p.data); err != nil {
			t.Fatalf("write packet: %v", err)
		}
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
}

type timedPacket struct {
	ts   time.Time
	data []byte
}

func udp4(t *testing.T, payload string) []byte {
	t.Helper()
	return frame{lt: layers.LinkTypeEthernet, proto: "udp", src: "10.0.0.1", dst: "10.0.0.2", sp: 5060, dp: 5060, payload: payload}.bytes(t)
}

func TestReadFileSample(t *testing.T) {
	res, err := readFile(context.Background(), samplePCAP)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if res.Packets != samplePackets {
		t.Errorf("Packets = %d, want %d", res.Packets, samplePackets)
	}
	if len(res.Messages) != sampleSIP {
		t.Errorf("len(Messages) = %d, want %d", len(res.Messages), sampleSIP)
	}
	if res.Skipped != samplePackets-sampleSIP {
		t.Errorf("Skipped = %d, want %d", res.Skipped, samplePackets-sampleSIP)
	}
	for i := 1; i < len(res.Messages); i++ {
		if res.Messages[i].Time.Before(res.Messages[i-1].Time) {
			t.Fatalf("messages not sorted at %d", i)
		}
	}

	byIndex := map[int]trace.Message{}
	n := 0
	for _, m := range res.Messages {
		byIndex[m.Index] = m
		if m.CallID == sampleCallID {
			n++
		}
	}
	if n != 14 {
		t.Errorf("messages with Call-ID %s = %d, want 14", sampleCallID, n)
	}

	t.Run("first message", func(t *testing.T) {
		want := trace.Message{
			File: samplePCAP, Index: 19, Time: time.Date(2005, 7, 4, 9, 32, 52, 844249000, time.UTC),
			Src: netip.MustParseAddr("192.168.1.2"), Dst: netip.MustParseAddr("212.242.33.35"),
			SrcPort: 5060, DstPort: 5060, Transport: "UDP",
			IsRequest: true, Method: "REGISTER", RequestURI: "sip:sip.cybercity.dk",
			CallID:  "578222729-4665d775@578222732-4665d772",
			From:    "<sip:voi18063@sip.cybercity.dk>;tag=903df0a",
			To:      "<sip:voi18063@sip.cybercity.dk>",
			Contact: "<sip:voi18063@192.168.1.2:5060;line=9c7d2dbd8822013c>;expires=1200;q=0.500",
			CSeq:    "68 REGISTER",
		}
		if got := res.Messages[0]; got != want {
			t.Fatalf("first message =\n %+v\nwant\n %+v", got, want)
		}
	})
	t.Run("request with known Call-ID", func(t *testing.T) {
		want := trace.Message{
			File: samplePCAP, Index: 515, Time: time.Date(2005, 7, 4, 9, 53, 16, 804243000, time.UTC),
			Src: netip.MustParseAddr("192.168.1.2"), Dst: netip.MustParseAddr("212.242.33.35"),
			SrcPort: 5060, DstPort: 5060, Transport: "UDP",
			IsRequest: true, Method: "REGISTER", RequestURI: "sip:sip.cybercity.dk",
			CallID:  sampleCallID,
			From:    "<sip:35104723@sip.cybercity.dk>;tag=1b89bcd",
			To:      "<sip:35104723@sip.cybercity.dk>",
			Contact: "pel <sip:35104723@192.168.1.2:5060;line=7d36558f31367051>;expires=1200;q=0.500",
			CSeq:    "1 REGISTER",
		}
		if got := byIndex[515]; got != want {
			t.Fatalf("packet 515 =\n %+v\nwant\n %+v", got, want)
		}
	})
	t.Run("response", func(t *testing.T) {
		got := byIndex[516]
		if got.IsRequest || got.StatusCode != 401 || got.Reason != "Unauthorized" || got.Method != "REGISTER" ||
			got.CallID != sampleCallID || got.Src != netip.MustParseAddr("212.242.33.35") || got.Info() != "401 Unauthorized" {
			t.Fatalf("packet 516 = %+v", got)
		}
	})
	t.Run("INVITE", func(t *testing.T) {
		var found bool
		for _, m := range res.Messages {
			if m.IsRequest && m.Method == "INVITE" {
				found = true
				if m.RequestURI != "sip:97239287044@voip.brujula.net" || m.Dst != netip.MustParseAddr("200.68.120.81") {
					t.Fatalf("INVITE = %+v", m)
				}
				break
			}
		}
		if !found {
			t.Fatal("no INVITE found")
		}
	})
	t.Run("non-SIP packets are skipped", func(t *testing.T) {
		// packet 39733 style DNS lookups for _sip._udp must not be reported
		for _, m := range res.Messages {
			if m.SrcPort == 2742 || m.DstPort == 53 {
				t.Fatalf("DNS packet reported as SIP: %+v", m)
			}
		}
	})
}

func TestReadFileErrors(t *testing.T) {
	dir := t.TempDir()
	short := filepath.Join(dir, "short.pcap")
	garbage := filepath.Join(dir, "garbage.pcap")
	empty := filepath.Join(dir, "empty.pcap")
	if err := os.WriteFile(short, []byte{0xd4, 0xc3}, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(garbage, bytes.Repeat([]byte("not a capture "), 10), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(empty, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "missing.pcap")

	tests := []struct {
		name string
		path string
		is   error
	}{
		{"missing", missing, os.ErrNotExist},
		{"short", short, nil},
		{"garbage", garbage, nil},
		{"empty", empty, nil},
		{"directory", dir, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := readFile(context.Background(), tc.path)
			if err == nil {
				t.Fatal("expected error")
			}
			if !bytes.Contains([]byte(err.Error()), []byte(tc.path)) {
				t.Errorf("error %q does not mention path %q", err, tc.path)
			}
			if tc.is != nil && !errors.Is(err, tc.is) {
				t.Errorf("error %v does not wrap %v", err, tc.is)
			}
		})
	}
}

// A capture cut off mid-record (tcpdump killed, disk full) keeps everything
// read before the cut and reports a warning instead of failing the file.
func TestReadFileTruncatedPacket(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.pcap")
	writePCAP(t, path, layers.LinkTypeEthernet, []timedPacket{{t0, udp4(t, inviteMsg)}, {t0, udp4(t, okMsg)}})
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b[:len(b)-10], 0o644); err != nil {
		t.Fatal(err)
	}
	for _, read := range []func() (sipResult, error){
		func() (sipResult, error) { return readFile(context.Background(), path) },
		func() (sipResult, error) { return readFiles(context.Background(), []string{path}) },
	} {
		res, err := read()
		if err != nil {
			t.Fatalf("truncated capture must not fail: %v", err)
		}
		if res.Packets != 1 || len(res.Messages) != 1 || res.Messages[0].Method != "INVITE" {
			t.Errorf("got %d packets, %d messages; want the 1 packet before the cut", res.Packets, len(res.Messages))
		}
		if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "packet 2") {
			t.Errorf("warnings = %q, want one naming packet 2", res.Warnings)
		}
	}
}

func TestReadFileLinkTypesAndTransports(t *testing.T) {
	tests := []struct {
		name  string
		f     frame
		src   string
		dst   string
		trans string
	}{
		{"ethernet udp4", frame{lt: layers.LinkTypeEthernet, proto: "udp", src: "10.0.0.1", dst: "10.0.0.2", sp: 5060, dp: 5080}, "10.0.0.1", "10.0.0.2", "UDP"},
		{"ethernet udp6", frame{lt: layers.LinkTypeEthernet, proto: "udp", src: "2001:db8::1", dst: "2001:db8::2", sp: 5060, dp: 5060}, "2001:db8::1", "2001:db8::2", "UDP"},
		{"ethernet vlan udp4", frame{lt: layers.LinkTypeEthernet, vlan: true, proto: "udp", src: "10.0.0.1", dst: "10.0.0.2", sp: 1, dp: 2}, "10.0.0.1", "10.0.0.2", "UDP"},
		{"ethernet tcp4 odd port", frame{lt: layers.LinkTypeEthernet, proto: "tcp", src: "10.0.0.1", dst: "10.0.0.2", sp: 40000, dp: 5060}, "10.0.0.1", "10.0.0.2", "TCP"},
		{"ethernet tcp6", frame{lt: layers.LinkTypeEthernet, proto: "tcp", src: "::1", dst: "::2", sp: 40000, dp: 5060}, "::1", "::2", "TCP"},
		{"linux sll udp4", frame{lt: layers.LinkTypeLinuxSLL, proto: "udp", src: "10.0.0.1", dst: "10.0.0.2", sp: 5060, dp: 5060}, "10.0.0.1", "10.0.0.2", "UDP"},
		{"raw ip udp4", frame{lt: layers.LinkTypeRaw, proto: "udp", src: "10.0.0.1", dst: "10.0.0.2", sp: 5060, dp: 5060}, "10.0.0.1", "10.0.0.2", "UDP"},
		{"raw ip udp6", frame{lt: layers.LinkTypeRaw, proto: "udp", src: "fe80::1", dst: "ff02::1", sp: 5060, dp: 5060}, "fe80::1", "ff02::1", "UDP"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.f.payload = inviteMsg
			path := filepath.Join(t.TempDir(), "x.pcap")
			writePCAP(t, path, tc.f.lt, []timedPacket{{t0, tc.f.bytes(t)}})
			res, err := readFile(context.Background(), path)
			if err != nil {
				t.Fatalf("ReadFile: %v", err)
			}
			if res.Packets != 1 || len(res.Messages) != 1 || res.Skipped != 0 {
				t.Fatalf("result = %d packets, %d messages, %d skipped", res.Packets, len(res.Messages), res.Skipped)
			}
			m := res.Messages[0]
			if m.Src != netip.MustParseAddr(tc.src) || m.Dst != netip.MustParseAddr(tc.dst) ||
				m.SrcPort != tc.f.sp || m.DstPort != tc.f.dp || m.Transport != tc.trans {
				t.Errorf("endpoints = %v -> %v %s, want %s:%d -> %s:%d %s", m.SrcAddr(), m.DstAddr(), m.Transport,
					tc.src, tc.f.sp, tc.dst, tc.f.dp, tc.trans)
			}
			if m.File != path || m.Index != 1 || !m.Time.Equal(t0) || m.Time.Location() != time.UTC {
				t.Errorf("file/index/time = %q/%d/%v", m.File, m.Index, m.Time)
			}
			if m.Method != "INVITE" || m.CallID != "c1" || m.CSeq != "1 INVITE" {
				t.Errorf("message = %+v", m)
			}
		})
	}
}

func TestReadFileSkipsNonSIP(t *testing.T) {
	arp := make([]byte, 42)
	arp[12], arp[13] = 0x08, 0x06 // EtherType ARP
	pkts := []timedPacket{
		{t0, udp4(t, "hello")},
		{t0.Add(1 * time.Second), udp4(t, inviteMsg)},
		{t0.Add(2 * time.Second), arp},
		{t0.Add(3 * time.Second), []byte{1, 2, 3}}, // undecodable
		{t0.Add(4 * time.Second), udp4(t, "")},
		{t0.Add(5 * time.Second), udp4(t, okMsg)},
	}
	path := filepath.Join(t.TempDir(), "x.pcap")
	writePCAP(t, path, layers.LinkTypeEthernet, pkts)
	res, err := readFile(context.Background(), path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if res.Packets != 6 || res.Skipped != 4 || len(res.Messages) != 2 {
		t.Fatalf("packets/skipped/messages = %d/%d/%d, want 6/4/2", res.Packets, res.Skipped, len(res.Messages))
	}
	if res.Messages[0].Index != 2 || res.Messages[1].Index != 6 {
		t.Errorf("indexes = %d, %d; want 2, 6", res.Messages[0].Index, res.Messages[1].Index)
	}
	if res.Messages[1].IsRequest || res.Messages[1].Method != "INVITE" || res.Messages[1].StatusCode != 200 {
		t.Errorf("response = %+v", res.Messages[1])
	}
}

func TestReadFileTCPSegmentWithoutStartLine(t *testing.T) {
	f := frame{lt: layers.LinkTypeEthernet, proto: "tcp", src: "10.0.0.1", dst: "10.0.0.2", sp: 40000, dp: 5060}
	f.payload = "Content-Length: 0\r\n\r\n" // continuation segment
	cont := f.bytes(t)
	f.payload = inviteMsg
	start := f.bytes(t)
	f.seq, f.payload = 1+uint32(len(inviteMsg)), "Content-Length: 0\r\n\r\n" // right behind the INVITE, but not a start line
	cont = f.bytes(t)
	path := filepath.Join(t.TempDir(), "x.pcap")
	writePCAP(t, path, layers.LinkTypeEthernet, []timedPacket{{t0, start}, {t0.Add(time.Millisecond), cont}})
	res, err := readFile(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Messages) != 1 || res.Messages[0].Index != 1 || res.Skipped != 1 {
		t.Fatalf("messages = %+v, skipped = %d", res.Messages, res.Skipped)
	}
}

func TestReadFileIPv4MappedIPv6(t *testing.T) {
	f := frame{lt: layers.LinkTypeEthernet, proto: "udp", src: "::ffff:10.1.2.3", dst: "::ffff:10.1.2.4", sp: 5060, dp: 5060, payload: inviteMsg}
	path := filepath.Join(t.TempDir(), "x.pcap")
	writePCAP(t, path, layers.LinkTypeEthernet, []timedPacket{{t0, f.bytes(t)}})
	res, err := readFile(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Messages) != 1 {
		t.Fatalf("messages = %d", len(res.Messages))
	}
	if got := res.Messages[0]; !got.Src.Is4() || got.Src != netip.MustParseAddr("10.1.2.3") || got.Dst != netip.MustParseAddr("10.1.2.4") {
		t.Fatalf("addresses not unmapped: %v -> %v", got.Src, got.Dst)
	}
}

func TestReadFileNanosecondPCAP(t *testing.T) {
	var buf bytes.Buffer
	w := pcapgo.NewWriterNanos(&buf)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	ts := t0.Add(123456789 * time.Nanosecond)
	d := udp4(t, inviteMsg)
	if err := w.WritePacket(ci(ts, len(d)), d); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "n.pcap")
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := readFile(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Messages) != 1 || !res.Messages[0].Time.Equal(ts) {
		t.Fatalf("messages = %+v, want time %v", res.Messages, ts)
	}
}

func TestReadFilePcapNg(t *testing.T) {
	var buf bytes.Buffer
	eth := pcapgo.DefaultNgInterface
	eth.Name = "eth0"
	eth.LinkType = layers.LinkTypeEthernet
	w, err := pcapgo.NewNgWriterInterface(&buf, eth, pcapgo.DefaultNgWriterOptions)
	if err != nil {
		t.Fatalf("NewNgWriterInterface: %v", err)
	}
	raw := pcapgo.DefaultNgInterface
	raw.Name = "tun0"
	raw.LinkType = layers.LinkTypeRaw
	rawID, err := w.AddInterface(raw)
	if err != nil {
		t.Fatalf("AddInterface: %v", err)
	}

	ethPkt := udp4(t, inviteMsg)
	rawPkt := frame{lt: layers.LinkTypeRaw, proto: "udp", src: "2001:db8::a", dst: "2001:db8::b", sp: 5070, dp: 5060, payload: okMsg}.bytes(t)
	junk := udp4(t, "not sip")

	c := ci(t0, len(ethPkt))
	if err := w.WritePacket(c, ethPkt); err != nil {
		t.Fatal(err)
	}
	c = ci(t0.Add(time.Second), len(junk))
	if err := w.WritePacket(c, junk); err != nil {
		t.Fatal(err)
	}
	c = ci(t0.Add(2*time.Second), len(rawPkt))
	c.InterfaceIndex = rawID
	if err := w.WritePacket(c, rawPkt); err != nil {
		t.Fatal(err)
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "x.pcapng")
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := readFile(context.Background(), path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if res.Packets != 3 || res.Skipped != 1 || len(res.Messages) != 2 {
		t.Fatalf("packets/skipped/messages = %d/%d/%d, want 3/1/2", res.Packets, res.Skipped, len(res.Messages))
	}
	a, b := res.Messages[0], res.Messages[1]
	if a.Index != 1 || a.Method != "INVITE" || !a.IsRequest || a.Src != netip.MustParseAddr("10.0.0.1") ||
		a.Transport != "UDP" || !a.Time.Equal(t0) || a.File != path {
		t.Errorf("first message = %+v", a)
	}
	if b.Index != 3 || b.IsRequest || b.StatusCode != 200 || b.Method != "INVITE" ||
		b.Src != netip.MustParseAddr("2001:db8::a") || b.SrcPort != 5070 || !b.Time.Equal(t0.Add(2*time.Second)) {
		t.Errorf("second message (raw-IP interface) = %+v", b)
	}
}

func TestReadFilesMerge(t *testing.T) {
	dir := t.TempDir()
	// Interleaved timestamps across files, plus an exact tie (t0+2s) that must
	// keep file order: a before b.
	pa := filepath.Join(dir, "a.pcap")
	pb := filepath.Join(dir, "b.pcapng")
	writePCAP(t, pa, layers.LinkTypeEthernet, []timedPacket{
		{t0, udp4(t, "INVITE sip:a SIP/2.0\r\nCall-ID: a1\r\n\r\n")},
		{t0.Add(2 * time.Second), udp4(t, "INVITE sip:a SIP/2.0\r\nCall-ID: a2\r\n\r\n")},
		{t0.Add(4 * time.Second), udp4(t, "x")},
	})
	var buf bytes.Buffer
	w, err := pcapgo.NewNgWriter(&buf, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []timedPacket{
		{t0.Add(1 * time.Second), udp4(t, "INVITE sip:b SIP/2.0\r\nCall-ID: b1\r\n\r\n")},
		{t0.Add(2 * time.Second), udp4(t, "INVITE sip:b SIP/2.0\r\nCall-ID: b2\r\n\r\n")},
	} {
		if err := w.WritePacket(ci(p.ts, len(p.data)), p.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pb, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := readFiles(context.Background(), []string{pa, pb})
	if err != nil {
		t.Fatalf("ReadFiles: %v", err)
	}
	if res.Packets != 5 || res.Skipped != 1 {
		t.Errorf("packets/skipped = %d/%d, want 5/1", res.Packets, res.Skipped)
	}
	var got []string
	for _, m := range res.Messages {
		got = append(got, m.CallID)
	}
	want := []string{"a1", "b1", "a2", "b2"}
	if len(got) != len(want) {
		t.Fatalf("call IDs = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("call IDs = %v, want %v", got, want)
		}
	}
	if res.Messages[1].File != pb || res.Messages[0].File != pa {
		t.Errorf("files = %q, %q", res.Messages[0].File, res.Messages[1].File)
	}
}

func TestReadFilesSameFileTwice(t *testing.T) {
	single, err := readFile(context.Background(), samplePCAP)
	if err != nil {
		t.Fatal(err)
	}
	res, err := readFiles(context.Background(), []string{samplePCAP, samplePCAP})
	if err != nil {
		t.Fatalf("ReadFiles: %v", err)
	}
	if res.Packets != 2*samplePackets || len(res.Messages) != 2*sampleSIP || res.Skipped != 2*single.Skipped {
		t.Fatalf("packets/messages/skipped = %d/%d/%d", res.Packets, len(res.Messages), res.Skipped)
	}
	// Equal timestamps keep input order, so every message appears twice in a row
	// and indexes are those of the single read.
	for i := 0; i < len(res.Messages); i += 2 {
		if res.Messages[i] != single.Messages[i/2] || res.Messages[i+1] != single.Messages[i/2] {
			t.Fatalf("messages %d,%d differ from single read %d", i, i+1, i/2)
		}
	}
}

func TestReadFilesEdgeCases(t *testing.T) {
	t.Run("no paths", func(t *testing.T) {
		res, err := readFiles(context.Background(), nil)
		if err != nil || res.Packets != 0 || len(res.Messages) != 0 {
			t.Fatalf("res = %+v, err = %v", res, err)
		}
	})
	t.Run("one bad file fails the lot", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "nope.pcap")
		_, err := readFiles(context.Background(), []string{samplePCAP, missing, samplePCAP})
		if err == nil {
			t.Fatal("expected error")
		}
		if !errors.Is(err, os.ErrNotExist) || !bytes.Contains([]byte(err.Error()), []byte(missing)) {
			t.Fatalf("err = %v, want wrapped ErrNotExist naming %s", err, missing)
		}
	})
}

func TestContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	t.Run("ReadFile", func(t *testing.T) {
		_, err := readFile(ctx, samplePCAP)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	})
	t.Run("ReadFiles", func(t *testing.T) {
		_, err := readFiles(ctx, []string{samplePCAP, samplePCAP})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	})
	t.Run("cancelled mid-read", func(t *testing.T) {
		// More packets than the check interval so the periodic check fires.
		n := 3 * capture.CtxCheckInterval
		pkts := make([]timedPacket, n)
		d := udp4(t, inviteMsg)
		for i := range pkts {
			pkts[i] = timedPacket{t0.Add(time.Duration(i) * time.Millisecond), d}
		}
		path := filepath.Join(t.TempDir(), "big.pcap")
		writePCAP(t, path, layers.LinkTypeEthernet, pkts)

		res, err := readFile(context.Background(), path)
		if err != nil || res.Packets != n || len(res.Messages) != n {
			t.Fatalf("uncancelled read: %d packets, %d messages, err %v", res.Packets, len(res.Messages), err)
		}
		// Cancel on the second check, i.e. after capture.CtxCheckInterval packets.
		cc := &cancelAfter{Context: context.Background(), okChecks: 1}
		if _, err := readFile(cc, path); !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
		if cc.checks != 2 {
			t.Fatalf("ctx.Err called %d times, want 2 (cancel noticed at first periodic check)", cc.checks)
		}
	})
}

// cancelAfter reports success for the first okChecks calls to Err, then
// context.Canceled.
type cancelAfter struct {
	context.Context
	okChecks, checks int
}

func (c *cancelAfter) Err() error {
	c.checks++
	if c.checks > c.okChecks {
		return context.Canceled
	}
	return nil
}
