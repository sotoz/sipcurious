package capture_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gopacket/gopacket/layers"

	"github.com/sotoz/sipcurious/internal/capture"
	"github.com/sotoz/sipcurious/internal/sip"
	"github.com/sotoz/sipcurious/internal/trace"
)

// pbKuzPcap serialises a libpcap "modified" (Kuznetsov, magic 0xa1b2cd34) file:
// every record header carries 8 extra bytes after the usual 16.
func pbKuzPcap(order binary.AppendByteOrder, lt layers.LinkType, recs ...pbRec) []byte {
	var b []byte
	u32 := func(v uint32) { b = order.AppendUint32(b, v) }
	u16 := func(v uint16) { b = order.AppendUint16(b, v) }
	u32(0xa1b2cd34)
	u16(2)
	u16(4)
	u32(0)
	u32(0)
	u32(65535)
	u32(uint32(lt))
	for _, r := range recs {
		u32(uint32(r.ts.Unix()))
		u32(uint32(r.ts.Nanosecond() / 1000))
		u32(uint32(len(r.data)))
		u32(uint32(len(r.data)))
		u32(7)              // ifindex
		u16(0x0800)         // protocol
		b = append(b, 0, 0) // pkt_type, pad
		b = append(b, r.data...)
	}
	return b
}

// pbPcapVersion returns file with its version fields overwritten.
func pbPcapVersion(file []byte, major, minor uint16) []byte {
	b := bytes.Clone(file)
	binary.LittleEndian.PutUint16(b[4:], major)
	binary.LittleEndian.PutUint16(b[6:], minor)
	return b
}

func TestClassicCaplenExceedsOriginal(t *testing.T) {
	f := flow4
	a := pbEth(0x0800, f.udpIP(pbSIP("INVITE", "a", 1)))
	b := pbEth(0x0800, f.udpIP(pbSIP("BYE", "b", 2)))
	// origlen is smaller than caplen on both records, like the real writer
	// that produced testdata/realworld/wireshark-sip-tls13-caplen-gt-origlen.pcap.
	file := pbPcap(pbPcapOpts{lt: layers.LinkTypeEthernet},
		pbRec{ts: mt0, data: a, orig: 1},
		pbRec{ts: mt0.Add(time.Second), data: b, orig: len(b) - 16})
	res, p := pbMustRead(t, "x.pcap", file)
	if len(res.Warnings) != 0 || res.Packets != 2 {
		t.Fatalf("packets = %d, warnings = %q", res.Packets, res.Warnings)
	}
	want := []trace.Message{
		f.want("UDP", pbWantReq("INVITE", "a", 1), p, 1, mt0),
		f.want("UDP", pbWantReq("BYE", "b", 2), p, 2, mt0.Add(time.Second)),
	}
	pbCheckMsgs(t, res.Messages, want)
}

func TestClassicVersions(t *testing.T) {
	f := flow4
	good := pbPcap(pbPcapOpts{lt: layers.LinkTypeEthernet},
		pbRec{ts: mt0, data: pbEth(0x0800, f.udpIP(pbSIP("OPTIONS", "v", 1)))})
	tests := []struct {
		major, minor uint16
		ok           bool
	}{
		{2, 4, true},
		{2, 3, true},
		{2, 5, true},
		{2, 0, true},
		{2, 65535, true},
		{1, 4, false},
		{3, 0, false},
		{0, 0, false},
	}
	for _, tc := range tests {
		t.Run(strconv.Itoa(int(tc.major))+"."+strconv.Itoa(int(tc.minor)), func(t *testing.T) {
			res, p, err := pbRead(t, "x.pcap", pbPcapVersion(good, tc.major, tc.minor))
			if !tc.ok {
				if err == nil || !strings.Contains(err.Error(), p) {
					t.Fatalf("err = %v, want error naming the file", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("err = %v", err)
			}
			if res.Packets != 1 || len(res.Messages) != 1 || len(res.Warnings) != 0 {
				t.Fatalf("res = %+v", res)
			}
		})
	}
}

func TestClassicHugeCaplen(t *testing.T) {
	f := flow4
	pkt := pbEth(0x0800, f.udpIP(pbSIP("OPTIONS", "h", 1)))
	good := pbPcap(pbPcapOpts{lt: layers.LinkTypeEthernet}, pbRec{ts: mt0, data: pkt})
	header := good[:24]
	rec := func(caplen uint32) []byte {
		r := make([]byte, 16)
		binary.LittleEndian.PutUint32(r[8:], caplen)
		binary.LittleEndian.PutUint32(r[12:], caplen)
		return r
	}

	for _, caplen := range []uint32{capture.MaxSnaplen + 1, 0x7fffffff, 0xffffffff} {
		t.Run(strconv.FormatUint(uint64(caplen), 10), func(t *testing.T) {
			// A valid packet first, then the corrupt record, followed by
			// plenty of bytes that must never be consumed as its body.
			file := append(bytes.Clone(good), rec(caplen)...)
			file = append(file, make([]byte, 4096)...)

			res, p := pbMustRead(t, "x.pcap", file)
			if res.Packets != 1 || len(res.Messages) != 1 {
				t.Errorf("packets/messages = %d/%d, want 1/1", res.Packets, len(res.Messages))
			}
			if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], p) || !strings.Contains(res.Warnings[0], "packet 2") {
				t.Errorf("warnings = %q", res.Warnings)
			}

			// The reader itself must refuse the record before allocating
			// anything near the announced length (at least 256 KiB).
			c, err := capture.NewClassicReader(bytes.NewReader(file))
			if err != nil {
				t.Fatal(err)
			}
			if _, _, _, err := c.Next(); err != nil {
				t.Fatal(err)
			}
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			_, _, _, err = c.Next()
			runtime.ReadMemStats(&after)
			if err == nil || err == io.EOF || err == io.ErrUnexpectedEOF {
				t.Fatalf("err = %v, want a capture length error", err)
			}
			if grown := after.TotalAlloc - before.TotalAlloc; grown > 4<<10 {
				t.Errorf("rejecting the record allocated %d bytes", grown)
			}
		})
	}

	t.Run("caplen of exactly capture.MaxSnaplen is accepted", func(t *testing.T) {
		body := make([]byte, capture.MaxSnaplen)
		file := append(bytes.Clone(header), rec(capture.MaxSnaplen)...)
		file = append(file, body...)
		res, _ := pbMustRead(t, "x.pcap", file)
		if res.Packets != 1 || len(res.Warnings) != 0 {
			t.Errorf("packets = %d, warnings = %q", res.Packets, res.Warnings)
		}
	})
	t.Run("record body cut short is an unexpected EOF", func(t *testing.T) {
		file := append(bytes.Clone(header), rec(100)...)
		file = append(file, make([]byte, 40)...)
		c, err := capture.NewClassicReader(bytes.NewReader(file))
		if err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := c.Next(); err != io.ErrUnexpectedEOF {
			t.Errorf("err = %v, want io.ErrUnexpectedEOF", err)
		}
	})
	t.Run("record body missing entirely is an unexpected EOF", func(t *testing.T) {
		file := append(bytes.Clone(header), rec(100)...)
		c, err := capture.NewClassicReader(bytes.NewReader(file))
		if err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := c.Next(); err != io.ErrUnexpectedEOF {
			t.Errorf("err = %v, want io.ErrUnexpectedEOF", err)
		}
	})
	t.Run("clean end of file is io.EOF", func(t *testing.T) {
		c, err := capture.NewClassicReader(bytes.NewReader(good))
		if err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := c.Next(); err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := c.Next(); err != io.EOF {
			t.Errorf("err = %v, want io.EOF", err)
		}
	})
}

func TestClassicBigEndianNanoseconds(t *testing.T) {
	f := flow6
	ts := time.Date(2024, 2, 29, 23, 59, 59, 987654321, time.UTC)
	a := pbEth(0x86dd, f.udpIP(pbSIP("INVITE", "be", 1)))
	b := pbEth(0x86dd, f.udpIP(pbSIPResp(200, "OK", "INVITE", "be", 1)))
	file := pbPcap(pbPcapOpts{bigEndian: true, nanos: true, lt: layers.LinkTypeEthernet},
		pbRec{ts: ts, data: a},
		pbRec{ts: ts.Add(1500 * time.Nanosecond), data: b, orig: 3}) // caplen > origlen in a BE file too
	if binary.BigEndian.Uint32(file) != 0xa1b23c4d {
		t.Fatalf("fixture is not a big-endian nanosecond file: % x", file[:4])
	}
	res, p := pbMustRead(t, "x.pcap", file)
	if len(res.Warnings) != 0 {
		t.Fatalf("warnings = %q", res.Warnings)
	}
	pbCheckMsgs(t, res.Messages, []trace.Message{
		f.want("UDP", pbWantReq("INVITE", "be", 1), p, 1, ts),
		f.want("UDP", pbWantResp(200, "OK", "INVITE", "be", 1), p, 2, ts.Add(1500*time.Nanosecond)),
	})
}

func TestClassicMicrosecondsBigEndian(t *testing.T) {
	f := flow4
	file := pbPcap(pbPcapOpts{bigEndian: true, lt: layers.LinkTypeEthernet},
		pbRec{ts: mt0, data: pbEth(0x0800, f.udpIP(pbSIP("INVITE", "mbe", 1)))})
	res, p := pbMustRead(t, "x.pcap", file)
	pbCheckMsgs(t, res.Messages, []trace.Message{f.want("UDP", pbWantReq("INVITE", "mbe", 1), p, 1, mt0)})
}

func TestClassicKuznetsov(t *testing.T) {
	f := flow4
	for _, tc := range []struct {
		name  string
		order binary.AppendByteOrder
	}{{"little endian", binary.LittleEndian}, {"big endian", binary.BigEndian}} {
		t.Run(tc.name, func(t *testing.T) {
			file := pbKuzPcap(tc.order, layers.LinkTypeEthernet,
				pbRec{ts: mt0, data: pbEth(0x0800, f.udpIP(pbSIP("INVITE", "k1", 1)))},
				pbRec{ts: mt0.Add(time.Millisecond), data: pbEth(0x0800, f.udpIP(pbSIP("BYE", "k2", 2)))})
			res, p := pbMustRead(t, "x.pcap", file)
			if len(res.Warnings) != 0 {
				t.Fatalf("warnings = %q", res.Warnings)
			}
			pbCheckMsgs(t, res.Messages, []trace.Message{
				f.want("UDP", pbWantReq("INVITE", "k1", 1), p, 1, mt0),
				f.want("UDP", pbWantReq("BYE", "k2", 2), p, 2, mt0.Add(time.Millisecond)),
			})
		})
	}
}

// The packet buffer is reused between packets. Messages must hold copies of
// the header strings, never views into it, even when later packets overwrite
// the buffer with different content of different sizes.
func TestClassicBufferReuse(t *testing.T) {
	f := flow4
	const n = 300
	recs := make([]pbRec, 0, n)
	want := make([]trace.Message, 0, n)
	for i := range n {
		id := "call-" + strconv.Itoa(i) + strings.Repeat("x", (i*37)%400) // sizes up, down, up
		m := "OPTIONS"
		if i%3 == 0 {
			m = "REGISTER"
		}
		ts := mt0.Add(time.Duration(i) * time.Millisecond)
		recs = append(recs, pbRec{ts: ts, data: pbEth(0x0800, f.udpIP(pbSIP(m, id, i+1)))})
		want = append(want, f.want("UDP", pbWantReq(m, id, i+1), "", i+1, ts))
	}
	res, p := pbMustRead(t, "x.pcap", pbPcap(pbPcapOpts{lt: layers.LinkTypeEthernet}, recs...))
	for i := range want {
		want[i].File = p
	}
	pbCheckMsgs(t, res.Messages, want)

	t.Run("reader hands out one buffer", func(t *testing.T) {
		c, err := capture.NewClassicReader(bytes.NewReader(pbPcap(pbPcapOpts{lt: layers.LinkTypeEthernet},
			pbRec{ts: mt0, data: []byte("AAAAAAAA")}, pbRec{ts: mt0, data: []byte("BBBB")})))
		if err != nil {
			t.Fatal(err)
		}
		d1, _, _, err := c.Next()
		if err != nil {
			t.Fatal(err)
		}
		first := d1[:1]
		if string(d1) != "AAAAAAAA" {
			t.Fatalf("first = %q", d1)
		}
		d2, _, _, err := c.Next()
		if err != nil {
			t.Fatal(err)
		}
		if string(d2) != "BBBB" || &first[0] != &d2[0] {
			t.Errorf("second = %q, buffer reused = %v", d2, &first[0] == &d2[0])
		}
	})
}

func TestClassicGzip(t *testing.T) {
	f := flow4
	good := pbPcap(pbPcapOpts{lt: layers.LinkTypeEthernet},
		pbRec{ts: mt0, data: pbEth(0x0800, f.udpIP(pbSIP("OPTIONS", "gz", 1)))})
	var gz bytes.Buffer
	w := newGzip(&gz)
	_, _ = w.Write(good)
	_ = w.Close()
	res, p := pbMustRead(t, "x.pcap.gz", gz.Bytes())
	pbCheckMsgs(t, res.Messages, []trace.Message{f.want("UDP", pbWantReq("OPTIONS", "gz", 1), p, 1, mt0)})
}

func FuzzClassicReader(f *testing.F) {
	flows := []flow{flow4, flow6}
	var recs []pbRec
	for i, fl := range flows {
		recs = append(recs, pbRec{ts: mt0, data: pbEth(pbEtherType(fl.v6()), fl.udpIP(pbSIP("INVITE", "fz", i+1)))})
	}
	for _, o := range []pbPcapOpts{
		{lt: layers.LinkTypeEthernet},
		{lt: layers.LinkTypeEthernet, nanos: true, bigEndian: true},
		{lt: layers.LinkTypeLinuxSLL},
		{lt: layers.LinkTypeRaw, snaplen: 1},
	} {
		file := pbPcap(o, recs...)
		f.Add(file)
		f.Add(file[:len(file)-7])
		f.Add(pbPcapVersion(file, 2, 3))
	}
	f.Add(pbPcap(pbPcapOpts{lt: layers.LinkTypeEthernet}, pbRec{ts: mt0, data: recs[0].data, orig: 1}))
	f.Add(pbKuzPcap(binary.LittleEndian, layers.LinkTypeEthernet, recs...))
	f.Add(pbKuzPcap(binary.BigEndian, layers.LinkTypeEthernet, recs...))
	f.Add([]byte{})
	f.Add([]byte{0xd4, 0xc3, 0xb2, 0xa1})
	f.Fuzz(func(t *testing.T, data []byte) {
		if src, err := capture.NewSource(bytes.NewReader(data)); err == nil {
			for {
				pkt, capLen, _, err := src.Next()
				if err != nil {
					break
				}
				if capLen != len(pkt) || capLen > capture.MaxSnaplen {
					t.Fatalf("capture length %d, data %d", capLen, len(pkt))
				}
			}
		}
		// The whole pipeline, with the SIP handler (TCP reassembly included).
		_, _ = capture.ReadStream(context.Background(), "fuzz", bytes.NewReader(data),
			capture.Options{Handlers: []capture.Factory{sip.NewHandler(sip.ParseOptions{Bodies: sip.BodyAll})}})
	})
}
