package capture_test

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"github.com/sotoz/sipcurious/internal/trace"
)

// flow is one direction of a transport conversation.
type flow struct {
	src, dst   netip.Addr
	sport, dpt uint16
}

var (
	flow4 = flow{pbAddr("192.0.2.10"), pbAddr("198.51.100.20"), 5060, 5060}
	flow6 = flow{pbAddr("2001:db8::10"), pbAddr("2001:db8:1::20"), 5061, 5080}
)

func (f flow) v6() bool { return f.src.Is6() }

func (f flow) udpIP(payload string) []byte {
	return f.ip(pbProtoUDP, pbUDP(f.src, f.dst, f.sport, f.dpt, []byte(payload)))
}

func (f flow) tcpIP(seq uint32, flags byte, payload string) []byte {
	return f.ip(pbProtoTCP, pbTCP(f.src, f.dst, f.sport, f.dpt, seq, flags, []byte(payload)))
}

func (f flow) ip(proto byte, l4 []byte, exts ...pbExt6) []byte {
	if f.v6() {
		return pbIPv6(f.src, f.dst, proto, l4, exts...)
	}
	return pbIPv4(f.src, f.dst, proto, l4, pbIP4Opts{})
}

// want returns the expectation for a message carried on this flow.
func (f flow) want(transport string, m trace.Message, file string, index int, ts time.Time) trace.Message {
	m.File, m.Index, m.Time = file, index, ts
	m.Src, m.Dst, m.SrcPort, m.DstPort, m.Transport = f.src, f.dst, f.sport, f.dpt, transport
	return m
}

var mt0 = time.Date(2023, 11, 14, 22, 13, 20, 123456000, time.UTC) // microsecond-exact

// linkCase wraps a bare IP packet into a link layer.
type linkCase struct {
	name string
	lt   layers.LinkType
	wrap func(v6 bool, ip []byte) []byte
}

func linkCases() []linkCase {
	return []linkCase{
		{"ethernet", layers.LinkTypeEthernet, func(v6 bool, ip []byte) []byte { return pbEth(pbEtherType(v6), ip) }},
		{"ethernet+802.1Q", layers.LinkTypeEthernet, func(v6 bool, ip []byte) []byte {
			return pbEth(0x8100, append(pbTag(42, pbEtherType(v6)), ip...))
		}},
		{"ethernet+Q-in-Q (88a8, 8100)", layers.LinkTypeEthernet, func(v6 bool, ip []byte) []byte {
			return pbEth(0x88a8, append(pbTag(100, 0x8100), append(pbTag(200, pbEtherType(v6)), ip...)...))
		}},
		{"ethernet+802.1Q+802.1Q (8100, 8100)", layers.LinkTypeEthernet, func(v6 bool, ip []byte) []byte {
			return pbEth(0x8100, append(pbTag(100, 0x8100), append(pbTag(200, pbEtherType(v6)), ip...)...))
		}},
		{"linux sll", layers.LinkTypeLinuxSLL, pbSLL},
		{"linux sll2", layers.LinkTypeLinuxSLL2, pbSLL2},
		{"raw (101)", layers.LinkTypeRaw, func(_ bool, ip []byte) []byte { return ip }},
		{"ipv4/ipv6 (228/229)", 0, func(_ bool, ip []byte) []byte { return ip }}, // lt chosen per family below
		{"null LE AF_INET/AF_INET6(darwin)", layers.LinkTypeNull, func(v6 bool, ip []byte) []byte {
			if v6 {
				return pbNull(30, false, ip)
			}
			return pbNull(2, false, ip)
		}},
		{"null BE", layers.LinkTypeNull, func(v6 bool, ip []byte) []byte {
			if v6 {
				return pbNull(30, true, ip)
			}
			return pbNull(2, true, ip)
		}},
		{"null AF_INET6 linux(10)", layers.LinkTypeNull, func(v6 bool, ip []byte) []byte {
			if v6 {
				return pbNull(10, false, ip)
			}
			return pbNull(2, false, ip)
		}},
		{"null AF_INET6 freebsd(28)", layers.LinkTypeNull, func(v6 bool, ip []byte) []byte {
			if v6 {
				return pbNull(28, false, ip)
			}
			return pbNull(2, false, ip)
		}},
		{"null AF_INET6 bsd(24)", layers.LinkTypeNull, func(v6 bool, ip []byte) []byte {
			if v6 {
				return pbNull(24, false, ip)
			}
			return pbNull(2, false, ip)
		}},
		{"loop (OpenBSD, BE family)", layers.LinkTypeLoop, func(v6 bool, ip []byte) []byte {
			if v6 {
				return pbNull(24, true, ip)
			}
			return pbNull(2, true, ip)
		}},
		{"ppp hdlc framed", layers.LinkTypePPP, pbPPP},
	}
}

func (c linkCase) linkType(v6 bool) layers.LinkType {
	if c.lt == 0 && c.name[0] == 'i' {
		if v6 {
			return layers.LinkTypeIPv6
		}
		return layers.LinkTypeIPv4
	}
	return c.lt
}

func TestLinkLayerMatrix(t *testing.T) {
	for _, lc := range linkCases() {
		for _, f := range []flow{flow4, flow6} {
			fam := "v4"
			if f.v6() {
				fam = "v6"
			}
			t.Run(lc.name+"/"+fam, func(t *testing.T) {
				req := pbSIP("INVITE", "link-"+lc.name, 7)
				ip := f.udpIP(req)
				pkt := lc.wrap(f.v6(), ip)
				junk := lc.wrap(f.v6(), f.udpIP("not sip"))
				file := pbPcap(pbPcapOpts{lt: lc.linkType(f.v6())},
					pbRec{ts: mt0, data: junk},
					pbRec{ts: mt0.Add(time.Second), data: pkt},
				)
				res, path := pbMustRead(t, "x.pcap", file)
				if res.Packets != 2 || res.Skipped != 1 {
					t.Errorf("packets/skipped = %d/%d, want 2/1", res.Packets, res.Skipped)
				}
				pbCheckMsgs(t, res.Messages, []trace.Message{
					f.want("UDP", pbWantReq("INVITE", "link-"+lc.name, 7), path, 2, mt0.Add(time.Second)),
				})
			})
		}
	}
}

func TestLinkLayerMatrixPcapng(t *testing.T) {
	// One interface per link type in a single file, each with its own
	// timestamp resolution, packets interleaved.
	type ifc struct {
		lc     linkCase
		f      flow
		tsresp byte // if_tsresol option value (0x06 = microseconds, 0x09 = ns, 0x03 = ms, 0x80|n = 2^-n)
		unit   time.Duration
	}
	var ifaces []ifc
	resols := []struct {
		code byte
		unit time.Duration
	}{{6, time.Microsecond}, {9, time.Nanosecond}, {3, time.Millisecond}, {0, time.Microsecond /* default */}}
	for i, lc := range linkCases() {
		f := flow4
		if i%2 == 1 {
			f = flow6
		}
		r := resols[i%len(resols)]
		ifaces = append(ifaces, ifc{lc, f, r.code, r.unit})
	}
	ng := newPbNG(false).shb(pbOpt{pbOptComment, []byte("hello")})
	for i, ic := range ifaces {
		opts := []pbOpt{{pbOptIfName, []byte(fmt.Sprintf("if%d", i))}}
		if ic.tsresp != 0 {
			opts = append(opts, pbOpt{pbOptIfTSResol, []byte{ic.tsresp}})
		}
		ng.idb(ic.lc.linkType(ic.f.v6()), 0, opts...)
	}
	var want []trace.Message
	// Emit in reverse interface order so file order differs from interface order.
	idx := 0
	for i := len(ifaces) - 1; i >= 0; i-- {
		ic := ifaces[i]
		idx++
		ts := mt0.Add(time.Duration(i) * 10 * time.Millisecond)
		raw := uint64(ts.UnixNano()) / uint64(ic.unit)
		id := fmt.Sprintf("ng-%d", i)
		ng.epb(uint32(i), raw, ic.lc.wrap(ic.f.v6(), ic.f.udpIP(pbSIP("OPTIONS", id, i+1))), 0)
		want = append(want, ic.f.want("UDP", pbWantReq("OPTIONS", id, i+1), "", idx, ts.Truncate(ic.unit)))
	}
	res, path := pbMustRead(t, "x.pcapng", ng.bytes())
	for i := range want {
		want[i].File = path
	}
	pbCheckMsgs(t, res.Messages, want)
}

func TestNetworkLayers(t *testing.T) {
	ping := func(f flow, ip []byte) []byte { return pbEth(pbEtherType(f.v6()), ip) }
	req := pbSIP("REGISTER", "net", 3)
	udp6 := func(exts ...pbExt6) []byte {
		return pbIPv6(flow6.src, flow6.dst, pbProtoUDP, pbUDP(flow6.src, flow6.dst, flow6.sport, flow6.dpt, []byte(req)), exts...)
	}
	tcp6 := func(exts ...pbExt6) []byte {
		return pbIPv6(flow6.src, flow6.dst, pbProtoTCP, pbTCP(flow6.src, flow6.dst, flow6.sport, flow6.dpt, 1, pbACK|pbPSH, []byte(req)), exts...)
	}
	opt4 := func(opts []byte, proto byte, l4 []byte) []byte {
		return pbIPv4(flow4.src, flow4.dst, proto, l4, pbIP4Opts{options: opts})
	}
	udp4l4 := pbUDP(flow4.src, flow4.dst, flow4.sport, flow4.dpt, []byte(req))
	tcp4l4 := pbTCP(flow4.src, flow4.dst, flow4.sport, flow4.dpt, 1, pbACK|pbPSH, []byte(req))

	tests := []struct {
		name      string
		f         flow
		transport string
		ip        []byte
	}{
		{"ipv6 udp no extensions", flow6, "UDP", udp6()},
		{"ipv6 udp hop-by-hop", flow6, "UDP", udp6(pbHopByHop)},
		{"ipv6 udp routing", flow6, "UDP", udp6(pbRouting)},
		{"ipv6 udp destination options", flow6, "UDP", udp6(pbDestOpts)},
		{"ipv6 udp hbh+routing+dest", flow6, "UDP", udp6(pbHopByHop, pbRouting, pbDestOpts)},
		{"ipv6 udp dest+dest", flow6, "UDP", udp6(pbDestOpts, pbDestOpts)},
		{"ipv6 tcp hop-by-hop", flow6, "TCP", tcp6(pbHopByHop)},
		{"ipv6 tcp routing", flow6, "TCP", tcp6(pbRouting)},
		{"ipv6 tcp hbh+routing+dest", flow6, "TCP", tcp6(pbHopByHop, pbRouting, pbDestOpts)},
		{"ipv4 udp options (NOP*4)", flow4, "UDP", opt4([]byte{1, 1, 1, 1}, pbProtoUDP, udp4l4)},
		{"ipv4 udp options (record route, 12 bytes)", flow4, "UDP", opt4([]byte{7, 11, 4, 1, 2, 3, 4, 5, 6, 7, 8, 0}, pbProtoUDP, udp4l4)},
		{"ipv4 udp max options (40 bytes)", flow4, "UDP", opt4(bytes.Repeat([]byte{1}, 40), pbProtoUDP, udp4l4)},
		{"ipv4 tcp options", flow4, "TCP", opt4([]byte{1, 1, 1, 0}, pbProtoTCP, tcp4l4)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			file := pbPcap(pbPcapOpts{lt: layers.LinkTypeEthernet}, pbRec{ts: mt0, data: ping(tc.f, tc.ip)})
			res, path := pbMustRead(t, "x.pcap", file)
			pbCheckMsgs(t, res.Messages, []trace.Message{
				tc.f.want(tc.transport, pbWantReq("REGISTER", "net", 3), path, 1, mt0),
			})
		})
	}
}

// TestFragments pins the behaviour for fragmented datagrams: they are
// reassembled; nothing that cannot be completed produces a message.
func TestFragments(t *testing.T) {
	big := pbSIP("INVITE", "frag", 1)
	big = big[:len(big)-2] + "X-Pad: " + strings.Repeat("p", 3000) + "\r\n\r\n"
	udpBig := pbUDP(flow4.src, flow4.dst, 5060, 5060, []byte(big))
	udpBig6 := pbUDP(flow6.src, flow6.dst, 5061, 5080, []byte(big))

	frag4 := func(id uint16, l4 []byte, off, n int, more bool) pbRec {
		fl := uint16(off / 8)
		if more {
			fl |= 0x2000
		}
		return pbRec{data: pbEth(0x0800, pbIPv4(flow4.src, flow4.dst, pbProtoUDP, l4[off:off+n], pbIP4Opts{id: id, frag: fl}))}
	}
	frag6 := func(id uint32, l4 []byte, off, n int, more bool, exts ...pbExt6) pbRec {
		e := append(append([]pbExt6{}, exts...), pbFragment6(uint16(off/8), more, id))
		return pbRec{data: pbEth(0x86dd, pbIPv6(flow6.src, flow6.dst, pbProtoUDP, l4[off:off+n], e...))}
	}
	n := len(udpBig)
	third := (n / 3) &^ 7
	wantReq := func(f flow, idx int, ts time.Time, path string) trace.Message {
		m := pbWantReq("INVITE", "frag", 1)
		return f.want("UDP", m, path, idx, ts)
	}
	at := func(r pbRec, i int) pbRec { r.ts = mt0.Add(time.Duration(i) * time.Millisecond); return r }

	t.Run("ipv4 two fragments in order", func(t *testing.T) {
		recs := []pbRec{at(frag4(1, udpBig, 0, third, true), 0), at(frag4(1, udpBig, third, n-third, false), 1)}
		res, path := pbMustRead(t, "x.pcap", pbPcap(pbPcapOpts{lt: layers.LinkTypeEthernet}, recs...))
		pbCheckMsgs(t, res.Messages, []trace.Message{wantReq(flow4, 2, mt0.Add(time.Millisecond), path)})
		if res.Packets != 2 || res.Skipped != 1 {
			t.Errorf("packets/skipped = %d/%d, want 2/1", res.Packets, res.Skipped)
		}
	})
	t.Run("ipv4 three fragments, out of order", func(t *testing.T) {
		recs := []pbRec{
			at(frag4(2, udpBig, 2*third, n-2*third, false), 0),
			at(frag4(2, udpBig, 0, third, true), 1),
			at(frag4(2, udpBig, third, third, true), 2),
		}
		res, path := pbMustRead(t, "x.pcap", pbPcap(pbPcapOpts{lt: layers.LinkTypeEthernet}, recs...))
		pbCheckMsgs(t, res.Messages, []trace.Message{wantReq(flow4, 3, mt0.Add(2*time.Millisecond), path)})
	})
	t.Run("ipv4 interleaved datagrams, duplicate fragment", func(t *testing.T) {
		recs := []pbRec{
			at(frag4(10, udpBig, 0, third, true), 0),
			at(frag4(11, udpBig, 0, third, true), 1),
			at(frag4(10, udpBig, 0, third, true), 2), // duplicate
			at(frag4(11, udpBig, third, n-third, false), 3),
			at(frag4(10, udpBig, third, n-third, false), 4),
		}
		res, path := pbMustRead(t, "x.pcap", pbPcap(pbPcapOpts{lt: layers.LinkTypeEthernet}, recs...))
		pbCheckMsgs(t, res.Messages, []trace.Message{
			wantReq(flow4, 4, mt0.Add(3*time.Millisecond), path),
			wantReq(flow4, 5, mt0.Add(4*time.Millisecond), path),
		})
	})
	t.Run("ipv4 overlapping fragments", func(t *testing.T) {
		recs := []pbRec{
			at(frag4(3, udpBig, 0, third, true), 0),
			at(frag4(3, udpBig, third-64, n-third+64, false), 1),
		}
		res, path := pbMustRead(t, "x.pcap", pbPcap(pbPcapOpts{lt: layers.LinkTypeEthernet}, recs...))
		pbCheckMsgs(t, res.Messages, []trace.Message{wantReq(flow4, 2, mt0.Add(time.Millisecond), path)})
	})
	t.Run("ipv4 missing middle fragment", func(t *testing.T) {
		recs := []pbRec{at(frag4(4, udpBig, 0, third, true), 0), at(frag4(4, udpBig, 2*third, n-2*third, false), 1)}
		res, _ := pbMustRead(t, "x.pcap", pbPcap(pbPcapOpts{lt: layers.LinkTypeEthernet}, recs...))
		if len(res.Messages) != 0 || res.Packets != 2 || res.Skipped != 2 {
			t.Fatalf("messages/packets/skipped = %d/%d/%d, want 0/2/2", len(res.Messages), res.Packets, res.Skipped)
		}
	})
	t.Run("ipv4 only the last fragment", func(t *testing.T) {
		res, _ := pbMustRead(t, "x.pcap", pbPcap(pbPcapOpts{lt: layers.LinkTypeEthernet}, at(frag4(5, udpBig, third, n-third, false), 0)))
		if len(res.Messages) != 0 {
			t.Fatalf("messages = %+v", res.Messages)
		}
	})
	t.Run("ipv4 same id different source are different datagrams", func(t *testing.T) {
		other := frag4(6, udpBig, third, n-third, false)
		other.data = pbEth(0x0800, pbIPv4(pbAddr("192.0.2.99"), flow4.dst, pbProtoUDP, udpBig[third:], pbIP4Opts{id: 6, frag: uint16(third / 8)}))
		recs := []pbRec{at(frag4(6, udpBig, 0, third, true), 0), at(other, 1)}
		res, _ := pbMustRead(t, "x.pcap", pbPcap(pbPcapOpts{lt: layers.LinkTypeEthernet}, recs...))
		if len(res.Messages) != 0 {
			t.Fatalf("fragments of different sources were combined: %+v", res.Messages)
		}
	})
	t.Run("ipv4 fragment cut by snaplen is not reassembled", func(t *testing.T) {
		a := at(frag4(7, udpBig, 0, third, true), 0)
		b := at(frag4(7, udpBig, third, n-third, false), 1)
		b.orig, b.data = len(b.data), b.data[:len(b.data)-100]
		res, _ := pbMustRead(t, "x.pcap", pbPcap(pbPcapOpts{lt: layers.LinkTypeEthernet}, a, b))
		if len(res.Messages) != 0 {
			t.Fatalf("messages = %+v", res.Messages)
		}
	})
	t.Run("ipv4 tiny first fragment with start line cut", func(t *testing.T) {
		// First fragment holds the UDP header and 8 bytes of payload only.
		recs := []pbRec{at(frag4(8, udpBig, 0, 16, true), 0), at(frag4(8, udpBig, 16, n-16, false), 1)}
		res, path := pbMustRead(t, "x.pcap", pbPcap(pbPcapOpts{lt: layers.LinkTypeEthernet}, recs...))
		pbCheckMsgs(t, res.Messages, []trace.Message{wantReq(flow4, 2, mt0.Add(time.Millisecond), path)})
	})
	t.Run("ipv6 two fragments", func(t *testing.T) {
		recs := []pbRec{at(frag6(77, udpBig6, 0, third, true), 0), at(frag6(77, udpBig6, third, len(udpBig6)-third, false), 1)}
		res, path := pbMustRead(t, "x.pcap", pbPcap(pbPcapOpts{lt: layers.LinkTypeEthernet}, recs...))
		pbCheckMsgs(t, res.Messages, []trace.Message{wantReq(flow6, 2, mt0.Add(time.Millisecond), path)})
	})
	t.Run("ipv6 fragments after destination options", func(t *testing.T) {
		recs := []pbRec{
			at(frag6(78, udpBig6, third, len(udpBig6)-third, false, pbDestOpts), 0),
			at(frag6(78, udpBig6, 0, third, true, pbDestOpts), 1),
		}
		res, path := pbMustRead(t, "x.pcap", pbPcap(pbPcapOpts{lt: layers.LinkTypeEthernet}, recs...))
		pbCheckMsgs(t, res.Messages, []trace.Message{wantReq(flow6, 2, mt0.Add(time.Millisecond), path)})
	})
	t.Run("ipv6 missing fragment", func(t *testing.T) {
		res, _ := pbMustRead(t, "x.pcap", pbPcap(pbPcapOpts{lt: layers.LinkTypeEthernet}, at(frag6(79, udpBig6, 0, third, true), 0)))
		if len(res.Messages) != 0 {
			t.Fatalf("messages = %+v", res.Messages)
		}
	})
	t.Run("atomic fragment (offset 0, no more) is decoded", func(t *testing.T) {
		r := frag6(80, udpBig6, 0, len(udpBig6), false)
		r.ts = mt0
		res, path := pbMustRead(t, "x.pcap", pbPcap(pbPcapOpts{lt: layers.LinkTypeEthernet}, r))
		pbCheckMsgs(t, res.Messages, []trace.Message{wantReq(flow6, 1, mt0, path)})
	})
	t.Run("many incomplete datagrams do not blow up", func(t *testing.T) {
		var recs []pbRec
		for i := 0; i < 3000; i++ {
			recs = append(recs, at(frag4(uint16(i), udpBig, 0, third, true), i))
		}
		res, _ := pbMustRead(t, "x.pcap", pbPcap(pbPcapOpts{lt: layers.LinkTypeEthernet}, recs...))
		if len(res.Messages) != 0 || res.Packets != 3000 {
			t.Fatalf("messages/packets = %d/%d", len(res.Messages), res.Packets)
		}
	})
}

func TestTunnels(t *testing.T) {
	inner := flow{pbAddr("10.15.193.31"), pbAddr("10.15.197.103"), 33093, 5090}
	outer := flow{pbAddr("10.15.196.229"), pbAddr("10.15.194.19"), 0, 0}
	req := pbSIP("INVITE", "tun", 1)
	innerIP := inner.udpIP(req)
	t.Run("ipip uses the inner endpoints", func(t *testing.T) {
		ip := pbIPv4(outer.src, outer.dst, 4, innerIP, pbIP4Opts{})
		res, path := pbMustRead(t, "x.pcap", pbPcap(pbPcapOpts{lt: layers.LinkTypeEthernet}, pbRec{ts: mt0, data: pbEth(0x0800, ip)}))
		pbCheckMsgs(t, res.Messages, []trace.Message{inner.want("UDP", pbWantReq("INVITE", "tun", 1), path, 1, mt0)})
	})
	t.Run("ip6-in-ip4 (proto 41)", func(t *testing.T) {
		in6 := flow6.udpIP(req)
		ip := pbIPv4(outer.src, outer.dst, 41, in6, pbIP4Opts{})
		res, path := pbMustRead(t, "x.pcap", pbPcap(pbPcapOpts{lt: layers.LinkTypeEthernet}, pbRec{ts: mt0, data: pbEth(0x0800, ip)}))
		pbCheckMsgs(t, res.Messages, []trace.Message{flow6.want("UDP", pbWantReq("INVITE", "tun", 1), path, 1, mt0)})
	})
	t.Run("gre carrying ipv4", func(t *testing.T) {
		gre := append([]byte{0, 0, 0x08, 0x00}, innerIP...)
		ip := pbIPv4(outer.src, outer.dst, 47, gre, pbIP4Opts{})
		res, path := pbMustRead(t, "x.pcap", pbPcap(pbPcapOpts{lt: layers.LinkTypeEthernet}, pbRec{ts: mt0, data: pbEth(0x0800, ip)}))
		pbCheckMsgs(t, res.Messages, []trace.Message{inner.want("UDP", pbWantReq("INVITE", "tun", 1), path, 1, mt0)})
	})
}

func TestTransports(t *testing.T) {
	f := flow{pbAddr("10.1.1.1"), pbAddr("10.2.2.2"), 40000, 5060}
	eth := func(ip []byte) []byte { return pbEth(0x0800, ip) }
	rec := func(i int, data []byte) pbRec {
		return pbRec{ts: mt0.Add(time.Duration(i) * time.Millisecond), data: eth(data)}
	}
	ts := func(i int) time.Time { return mt0.Add(time.Duration(i) * time.Millisecond) }
	run := func(t *testing.T, recs ...pbRec) (sipResult, string) {
		return pbMustRead(t, "x.pcap", pbPcap(pbPcapOpts{lt: layers.LinkTypeEthernet}, recs...))
	}

	t.Run("tcp start line", func(t *testing.T) {
		res, path := run(t, rec(0, f.tcpIP(1, pbACK|pbPSH, pbSIP("INVITE", "t1", 1))))
		pbCheckMsgs(t, res.Messages, []trace.Message{f.want("TCP", pbWantReq("INVITE", "t1", 1), path, 1, ts(0))})
	})
	t.Run("tcp response", func(t *testing.T) {
		r := flow{f.dst, f.src, 5060, 40000}
		res, path := run(t, rec(0, r.tcpIP(1, pbACK|pbPSH, pbSIPResp(200, "OK", "INVITE", "t2", 1))))
		pbCheckMsgs(t, res.Messages, []trace.Message{r.want("TCP", pbWantResp(200, "OK", "INVITE", "t2", 1), path, 1, ts(0))})
	})
	t.Run("two SIP messages in one segment are both reported", func(t *testing.T) {
		seg := pbSIP("INVITE", "t3a", 1) + pbSIP("BYE", "t3b", 2)
		res, path := run(t, rec(0, f.tcpIP(1, pbACK|pbPSH, seg)))
		pbCheckMsgs(t, res.Messages, []trace.Message{
			f.want("TCP", pbWantReq("INVITE", "t3a", 1), path, 1, ts(0)),
			f.want("TCP", pbWantReq("BYE", "t3b", 2), path, 1, ts(0)),
		})
	})
	t.Run("message split over two segments is reassembled", func(t *testing.T) {
		m := pbSIP("INVITE", "t4", 1)
		cut := strings.Index(m, "Call-ID")
		a, b := m[:cut+10], m[cut+10:]
		res, path := run(t, rec(0, f.tcpIP(1, pbACK|pbPSH, a)), rec(1, f.tcpIP(uint32(1+len(a)), pbACK|pbPSH, b)))
		// Attributed to the packet that carried its first byte.
		pbCheckMsgs(t, res.Messages, []trace.Message{f.want("TCP", pbWantReq("INVITE", "t4", 1), path, 1, ts(0))})
		if res.Skipped != 0 {
			t.Errorf("skipped = %d, want 0 (both segments belong to the message)", res.Skipped)
		}
	})
	t.Run("segment split after complete header line is reassembled", func(t *testing.T) {
		m := pbSIP("INVITE", "t4b", 1)
		cut := strings.Index(m, "CSeq")
		res, path := run(t, rec(0, f.tcpIP(1, pbACK|pbPSH, m[:cut])), rec(1, f.tcpIP(uint32(1+cut), pbACK|pbPSH, m[cut:])))
		pbCheckMsgs(t, res.Messages, []trace.Message{f.want("TCP", pbWantReq("INVITE", "t4b", 1), path, 1, ts(0))})
	})
	t.Run("mid-stream segment without start line ignored", func(t *testing.T) {
		res, _ := run(t,
			rec(0, f.tcpIP(100, pbACK|pbPSH, "Content-Length: 0\r\n\r\n")),
			rec(1, f.tcpIP(200, pbACK|pbPSH, "v=0\r\no=- 1 1 IN IP4 10.1.1.1\r\n")),
			rec(2, f.tcpIP(300, pbACK|pbPSH, "\x16\x03\x03\x00\x20 binary tls")),
		)
		if len(res.Messages) != 0 || res.Skipped != 3 {
			t.Fatalf("messages/skipped = %d/%d", len(res.Messages), res.Skipped)
		}
	})
	t.Run("handshake and ack-only packets", func(t *testing.T) {
		res, path := run(t,
			rec(0, f.tcpIP(0, pbSYN, "")),
			rec(1, flow{f.dst, f.src, f.dpt, f.sport}.tcpIP(0, pbSYN|pbACK, "")),
			rec(2, f.tcpIP(1, pbACK, "")),
			rec(3, f.tcpIP(1, pbACK|pbPSH, pbSIP("OPTIONS", "t5", 1))),
			rec(4, f.tcpIP(1000, pbFIN|pbACK, "")),
			rec(5, f.tcpIP(1001, pbRST, "")),
		)
		pbCheckMsgs(t, res.Messages, []trace.Message{f.want("TCP", pbWantReq("OPTIONS", "t5", 1), path, 4, ts(3))})
		if res.Packets != 6 || res.Skipped != 5 {
			t.Errorf("packets/skipped = %d/%d", res.Packets, res.Skipped)
		}
	})
	t.Run("tcp SYN carrying data (fast open) with SIP", func(t *testing.T) {
		res, path := run(t, rec(0, f.tcpIP(1, pbSYN, pbSIP("OPTIONS", "tfo", 1))))
		pbCheckMsgs(t, res.Messages, []trace.Message{f.want("TCP", pbWantReq("OPTIONS", "tfo", 1), path, 1, ts(0))})
	})
	t.Run("tcp with options", func(t *testing.T) {
		seg := pbTCP(f.src, f.dst, f.sport, f.dpt, 1, pbACK|pbPSH, nil)
		// Rebuild with 12 bytes of options (NOP NOP timestamp) and data offset 8.
		seg = append(seg[:20:20], 1, 1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 2)
		seg[12] = 8 << 4
		seg = append(seg, pbSIP("OPTIONS", "topt", 1)...)
		res, path := run(t, rec(0, pbIPv4(f.src, f.dst, pbProtoTCP, seg, pbIP4Opts{})))
		pbCheckMsgs(t, res.Messages, []trace.Message{f.want("TCP", pbWantReq("OPTIONS", "topt", 1), path, 1, ts(0))})
	})

	t.Run("udp zero-length payload", func(t *testing.T) {
		res, _ := run(t, rec(0, f.udpIP("")))
		if len(res.Messages) != 0 || res.Packets != 1 || res.Skipped != 1 {
			t.Fatalf("res = %+v", res)
		}
	})
	t.Run("udp checksum zero", func(t *testing.T) {
		l4 := pbUDP(f.src, f.dst, f.sport, f.dpt, []byte(pbSIP("OPTIONS", "csum0", 1)))
		l4[6], l4[7] = 0, 0
		res, path := run(t, rec(0, pbIPv4(f.src, f.dst, pbProtoUDP, l4, pbIP4Opts{})))
		pbCheckMsgs(t, res.Messages, []trace.Message{f.want("UDP", pbWantReq("OPTIONS", "csum0", 1), path, 1, ts(0))})
	})
	t.Run("udp bad checksum is still decoded", func(t *testing.T) {
		l4 := pbUDP(f.src, f.dst, f.sport, f.dpt, []byte(pbSIP("OPTIONS", "csumbad", 1)))
		l4[6] ^= 0xff
		res, _ := run(t, rec(0, pbIPv4(f.src, f.dst, pbProtoUDP, l4, pbIP4Opts{})))
		if len(res.Messages) != 1 {
			t.Fatalf("messages = %d", len(res.Messages))
		}
	})
	t.Run("ethernet padding after a short udp datagram", func(t *testing.T) {
		pkt := eth(f.udpIP(pbSIP("OPTIONS", "pad", 1)))
		pkt = append(pkt, make([]byte, 6)...)
		res, path := run(t, pbRec{ts: mt0, data: pkt})
		pbCheckMsgs(t, res.Messages, []trace.Message{f.want("UDP", pbWantReq("OPTIONS", "pad", 1), path, 1, mt0)})
	})
	t.Run("udp length shorter than payload cuts the message", func(t *testing.T) {
		m := pbSIP("OPTIONS", "ulen", 1)
		l4 := pbUDP(f.src, f.dst, f.sport, f.dpt, []byte(m))
		cut := strings.Index(m, "Call-ID")
		l4[4], l4[5] = byte((8+cut)>>8), byte(8+cut)
		res, path := run(t, rec(0, pbIPv4(f.src, f.dst, pbProtoUDP, l4, pbIP4Opts{})))
		want := pbWantReq("OPTIONS", "", 1)
		want.CSeq, want.Contact, want.CallID = "", "", ""
		pbCheckMsgs(t, res.Messages, []trace.Message{f.want("UDP", want, path, 1, ts(0))})
	})

	t.Run("sctp data chunk", func(t *testing.T) {
		sctp := pbSCTP(f.sport, f.dpt, pbSCTPData(1, 0, []byte(pbSIP("INVITE", "s1", 1))))
		res, path := run(t, rec(0, pbIPv4(f.src, f.dst, pbProtoSCTP, sctp, pbIP4Opts{})))
		pbCheckMsgs(t, res.Messages, []trace.Message{f.want("SCTP", pbWantReq("INVITE", "s1", 1), path, 1, ts(0))})
	})
	t.Run("sctp ipv6", func(t *testing.T) {
		sctp := pbSCTP(flow6.sport, flow6.dpt, pbSCTPData(1, 0, []byte(pbSIP("INVITE", "s2", 1))))
		res, path := run(t, pbRec{ts: mt0, data: pbEth(0x86dd, pbIPv6(flow6.src, flow6.dst, pbProtoSCTP, sctp))})
		pbCheckMsgs(t, res.Messages, []trace.Message{flow6.want("SCTP", pbWantReq("INVITE", "s2", 1), path, 1, mt0)})
	})
	t.Run("sctp two data chunks bundled, one control chunk, odd payload padding", func(t *testing.T) {
		// SACK-like chunk (type 3) before, then two DATA chunks (payload lengths not multiples of 4).
		sack := pbSCTPChunk(3, 0, make([]byte, 12))
		m1 := pbSIP("INVITE", "s3a", 1)
		m2 := pbSIPResp(180, "Ringing", "INVITE", "s3b", 1)
		if len(m1)%4 == 0 {
			m1 += "\r\n"
		}
		sctp := pbSCTP(f.sport, f.dpt, sack, pbSCTPData(1, 0, []byte(m1)), pbSCTPData(2, 0, []byte(m2)))
		res, path := run(t, rec(0, pbIPv4(f.src, f.dst, pbProtoSCTP, sctp, pbIP4Opts{})))
		pbCheckMsgs(t, res.Messages, []trace.Message{
			f.want("SCTP", pbWantReq("INVITE", "s3a", 1), path, 1, ts(0)),
			f.want("SCTP", pbWantResp(180, "Ringing", "INVITE", "s3b", 1), path, 1, ts(0)),
		})
	})
	t.Run("sctp without data chunk and with non-sip data", func(t *testing.T) {
		init := pbSCTPChunk(1, 0, make([]byte, 16))
		res, _ := run(t,
			rec(0, pbIPv4(f.src, f.dst, pbProtoSCTP, pbSCTP(f.sport, f.dpt, init), pbIP4Opts{})),
			rec(1, pbIPv4(f.src, f.dst, pbProtoSCTP, pbSCTP(f.sport, f.dpt, pbSCTPData(1, 0, []byte("hello"))), pbIP4Opts{})),
		)
		if len(res.Messages) != 0 || res.Skipped != 2 {
			t.Fatalf("res = %+v", res)
		}
	})
	t.Run("sctp bad chunk length does not crash", func(t *testing.T) {
		bad := pbSCTP(f.sport, f.dpt, []byte{0, 3, 0xff, 0xff, 1, 2, 3, 4})
		res, _ := run(t, rec(0, pbIPv4(f.src, f.dst, pbProtoSCTP, bad, pbIP4Opts{})))
		if len(res.Messages) != 0 {
			t.Fatalf("messages = %+v", res.Messages)
		}
	})
}

func TestSIPPortIndependence(t *testing.T) {
	for _, port := range []uint16{5060, 5061, 5080, 49152, 1, 65535, 53, 80, 443} {
		for _, tr := range []string{"UDP", "TCP"} {
			t.Run(fmt.Sprintf("%s/%d", tr, port), func(t *testing.T) {
				f := flow{pbAddr("10.1.1.1"), pbAddr("10.2.2.2"), port, port}
				m := pbSIP("OPTIONS", "port", 1)
				ip := f.udpIP(m)
				if tr == "TCP" {
					ip = f.tcpIP(1, pbACK|pbPSH, m)
				}
				res, path := pbMustRead(t, "x.pcap", pbPcap(pbPcapOpts{lt: layers.LinkTypeEthernet}, pbRec{ts: mt0, data: pbEth(0x0800, ip)}))
				pbCheckMsgs(t, res.Messages, []trace.Message{f.want(tr, pbWantReq("OPTIONS", "port", 1), path, 1, mt0)})
			})
		}
	}
	t.Run("non-sip protocol on sip port", func(t *testing.T) {
		f := flow4
		res, _ := pbMustRead(t, "x.pcap", pbPcap(pbPcapOpts{lt: layers.LinkTypeEthernet},
			pbRec{ts: mt0, data: pbEth(0x0800, f.udpIP("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))},
			pbRec{ts: mt0, data: pbEth(0x0800, f.tcpIP(1, pbACK|pbPSH, "HTTP/1.1 200 OK\r\n\r\n"))},
		))
		if len(res.Messages) != 0 {
			t.Fatalf("messages = %+v", res.Messages)
		}
	})
	t.Run("sip embedded in dns txt record", func(t *testing.T) {
		dns := []byte{0xab, 0xcd, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 3, 'f', 'o', 'o', 0, 0, 16, 0, 1, 0xc0, 12, 0, 16, 0, 1, 0, 0, 0, 60}
		txt := "INVITE sip:bob@example.com SIP/2.0\r\nCall-ID: dns\r\n\r\n"
		dns = append(dns, 0, byte(len(txt)+1), byte(len(txt)))
		dns = append(dns, txt...)
		f := flow{pbAddr("10.1.1.1"), pbAddr("10.2.2.2"), 53, 40000}
		ip := pbIPv4(f.src, f.dst, pbProtoUDP, pbUDP(f.src, f.dst, 53, 40000, dns), pbIP4Opts{})
		res, _ := pbMustRead(t, "x.pcap", pbPcap(pbPcapOpts{lt: layers.LinkTypeEthernet}, pbRec{ts: mt0, data: pbEth(0x0800, ip)}))
		if len(res.Messages) != 0 {
			t.Fatalf("DNS TXT payload reported as SIP: %+v", res.Messages)
		}
	})
}

// ---------------------------------------------------------------- file formats

func TestPcapFormats(t *testing.T) {
	f := flow4
	pkt := func(id string) []byte { return pbEth(0x0800, f.udpIP(pbSIP("OPTIONS", id, 1))) }
	tsA := time.Date(2024, 2, 29, 23, 59, 59, 999999000, time.UTC)
	tsB := time.Date(2038, 1, 19, 3, 14, 8, 1000, time.UTC) // beyond int32 seconds
	tsC := time.Date(1999, 12, 31, 23, 59, 59, 0, time.UTC)

	for _, bigEndian := range []bool{false, true} {
		for _, nanos := range []bool{false, true} {
			t.Run(fmt.Sprintf("bigEndian=%v nanos=%v", bigEndian, nanos), func(t *testing.T) {
				a := tsA
				if nanos {
					a = a.Add(999 * time.Nanosecond)
				}
				file := pbPcap(pbPcapOpts{bigEndian: bigEndian, nanos: nanos, lt: layers.LinkTypeEthernet},
					pbRec{ts: a, data: pkt("a")}, pbRec{ts: tsB, data: pkt("b")}, pbRec{ts: tsC, data: pkt("c")})
				res, path := pbMustRead(t, "x.pcap", file)
				pbCheckMsgs(t, res.Messages, []trace.Message{
					// tsC is the earliest but ReadFile itself keeps file order; ReadFiles sorts.
					f.want("UDP", pbWantReq("OPTIONS", "a", 1), path, 1, a),
					f.want("UDP", pbWantReq("OPTIONS", "b", 1), path, 2, tsB),
					f.want("UDP", pbWantReq("OPTIONS", "c", 1), path, 3, tsC),
				})
			})
		}
	}

	t.Run("microsecond file truncates sub-microsecond input", func(t *testing.T) {
		in := mt0.Add(789 * time.Nanosecond)
		res, _ := pbMustRead(t, "x.pcap", pbPcap(pbPcapOpts{lt: layers.LinkTypeEthernet}, pbRec{ts: in, data: pkt("a")}))
		if len(res.Messages) != 1 || !res.Messages[0].Time.Equal(mt0) {
			t.Fatalf("time = %v, want %v", res.Messages[0].Time, mt0)
		}
	})
	t.Run("time is UTC", func(t *testing.T) {
		res, _ := pbMustRead(t, "x.pcap", pbPcap(pbPcapOpts{lt: layers.LinkTypeEthernet}, pbRec{ts: mt0, data: pkt("a")}))
		if loc := res.Messages[0].Time.Location(); loc != time.UTC {
			t.Fatalf("location = %v, want UTC", loc)
		}
	})
	t.Run("zero packets", func(t *testing.T) {
		res, _ := pbMustRead(t, "x.pcap", pbPcap(pbPcapOpts{lt: layers.LinkTypeEthernet}))
		if res.Packets != 0 || len(res.Messages) != 0 {
			t.Fatalf("res = %+v", res)
		}
	})
	t.Run("pcapng with only section header and interface", func(t *testing.T) {
		res, _ := pbMustRead(t, "x.pcapng", newPbNG(false).shb().idb(layers.LinkTypeEthernet, 0).bytes())
		if res.Packets != 0 || len(res.Messages) != 0 {
			t.Fatalf("res = %+v", res)
		}
	})
	t.Run("pcapng section header only", func(t *testing.T) {
		res, _ := pbMustRead(t, "x.pcapng", newPbNG(false).shb().bytes())
		if res.Packets != 0 {
			t.Fatalf("res = %+v", res)
		}
	})
	t.Run("huge snaplen in header", func(t *testing.T) {
		res, _ := pbMustRead(t, "x.pcap", pbPcap(pbPcapOpts{lt: layers.LinkTypeEthernet, snaplen: 0xffffffff}, pbRec{ts: mt0, data: pkt("a")}))
		if len(res.Messages) != 1 {
			t.Fatalf("messages = %d", len(res.Messages))
		}
	})
	t.Run("packet larger than the announced snaplen is tolerated", func(t *testing.T) {
		// Several writers (dpkt, hand-rolled tools) ignore their own snaplen; libpcap accepts it.
		res, _ := pbMustRead(t, "x.pcap", pbPcap(pbPcapOpts{lt: layers.LinkTypeEthernet, snaplen: 60}, pbRec{ts: mt0, data: pkt("a")}))
		if len(res.Messages) != 1 {
			t.Fatalf("messages = %d", len(res.Messages))
		}
	})
}

func TestSnaplenTruncatedPackets(t *testing.T) {
	f := flow4
	m := pbSIP("INVITE", "snap", 5)
	full := pbEth(0x0800, f.udpIP(m))
	hdr := 14 + 20 + 8 // ethernet + ip + udp
	tests := []struct {
		name string
		cut  int
		want func() (trace.Message, bool)
	}{
		{"full", len(full), func() (trace.Message, bool) { return pbWantReq("INVITE", "snap", 5), true }},
		{"mid ethernet header", 10, nil},
		{"mid ip header", 14 + 10, nil},
		{"after ip header, mid udp header", 14 + 20 + 4, nil},
		{"udp header only", hdr, nil},
		{"mid start line", hdr + 12, nil},
		{"just the start line without newline", hdr + len("INVITE sip:bob@example.com SIP/2.0"), func() (trace.Message, bool) {
			return trace.Message{IsRequest: true, Method: "INVITE", RequestURI: "sip:bob@example.com"}, true
		}},
		{"start line and newline", hdr + len("INVITE sip:bob@example.com SIP/2.0\r\n"), func() (trace.Message, bool) {
			return trace.Message{IsRequest: true, Method: "INVITE", RequestURI: "sip:bob@example.com"}, true
		}},
		{"mid call-id value", hdr + strings.Index(m, "Call-ID: ") + len("Call-ID: sn"), func() (trace.Message, bool) {
			w := pbWantReq("INVITE", "snap", 5)
			w.CallID, w.CSeq, w.Contact = "", "", "" // the cut line is dropped, not recorded as half a Call-ID
			return w, true
		}},
		{"mid body", len(full) - 3, func() (trace.Message, bool) { return pbWantReq("INVITE", "snap", 5), true }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			file := pbPcap(pbPcapOpts{lt: layers.LinkTypeEthernet, snaplen: uint32(tc.cut)},
				pbRec{ts: mt0, data: full[:tc.cut], orig: len(full)})
			res, path := pbMustRead(t, "x.pcap", file)
			if res.Packets != 1 {
				t.Fatalf("packets = %d", res.Packets)
			}
			if tc.want == nil {
				if len(res.Messages) != 0 {
					t.Fatalf("messages = %+v", res.Messages)
				}
				return
			}
			w, _ := tc.want()
			pbCheckMsgs(t, res.Messages, []trace.Message{f.want("UDP", w, path, 1, mt0)})
		})
	}
}

func TestPcapngVariants(t *testing.T) {
	f := flow4
	pkt := func(id string) []byte { return pbEth(0x0800, f.udpIP(pbSIP("OPTIONS", id, 1))) }
	wantOpt := func(path, id string, idx int, ts time.Time) trace.Message {
		return f.want("UDP", pbWantReq("OPTIONS", id, 1), path, idx, ts)
	}
	ns := func(ts time.Time) uint64 { return uint64(ts.UnixNano()) }

	for _, be := range []bool{false, true} {
		t.Run(fmt.Sprintf("EPB bigEndian=%v", be), func(t *testing.T) {
			ng := newPbNG(be).shb().idb(layers.LinkTypeEthernet, 0, pbOpt{pbOptIfTSResol, []byte{9}})
			ng.epb(0, ns(mt0), pkt("a"), 0)
			res, path := pbMustRead(t, "x.pcapng", ng.bytes())
			pbCheckMsgs(t, res.Messages, []trace.Message{wantOpt(path, "a", 1, mt0)})
		})
	}
	t.Run("timestamp resolutions", func(t *testing.T) {
		base := time.Date(2024, 5, 6, 7, 8, 9, 0, time.UTC)
		ng := newPbNG(false).shb()
		ng.idb(layers.LinkTypeEthernet, 0)                                           // default: microseconds
		ng.idb(layers.LinkTypeEthernet, 0, pbOpt{pbOptIfTSResol, []byte{3}})         // ms
		ng.idb(layers.LinkTypeEthernet, 0, pbOpt{pbOptIfTSResol, []byte{9}})         // ns
		ng.idb(layers.LinkTypeEthernet, 0, pbOpt{pbOptIfTSResol, []byte{0x80 | 10}}) // 2^-10 s
		ng.idb(layers.LinkTypeEthernet, 0, pbOpt{pbOptIfTSResol, []byte{6}}, pbOpt{pbOptIfTSOff, []byte{0x10, 0, 0, 0, 0, 0, 0, 0}})
		sec := uint64(base.Unix())
		ng.epb(0, sec*1_000_000+123456, pkt("us"), 0)
		ng.epb(1, sec*1_000+123, pkt("ms"), 0)
		ng.epb(2, sec*1_000_000_000+123456789, pkt("ns"), 0)
		ng.epb(3, sec<<10|512, pkt("bin"), 0) // .5 s
		ng.epb(4, (sec-16)*1_000_000+1, pkt("off"), 0)
		res, path := pbMustRead(t, "x.pcapng", ng.bytes())
		pbCheckMsgs(t, res.Messages, []trace.Message{
			wantOpt(path, "us", 1, base.Add(123456*time.Microsecond)),
			wantOpt(path, "ms", 2, base.Add(123*time.Millisecond)),
			wantOpt(path, "ns", 3, base.Add(123456789)),
			wantOpt(path, "bin", 4, res.Messages[3].Time), // exact value checked below
			wantOpt(path, "off", 5, base.Add(1*time.Microsecond)),
		})
		// pcapgo scales 2^-10 s ticks with integer arithmetic, so allow 1 us.
		if d := res.Messages[3].Time.Sub(base.Add(500 * time.Millisecond)); d < -time.Microsecond || d > time.Microsecond {
			t.Errorf("2^-10 resolution time = %v, want %v", res.Messages[3].Time, base.Add(500*time.Millisecond))
		}
	})
	t.Run("simple packet blocks", func(t *testing.T) {
		ng := newPbNG(false).shb().idb(layers.LinkTypeEthernet, 0)
		ng.spb(pkt("spb1"), 0)
		ng.epb(0, uint64(mt0.UnixNano()/1000), pkt("epb"), 0)
		ng.spb(pkt("spb2"), 0)
		res, path := pbMustRead(t, "x.pcapng", ng.bytes())
		if res.Packets != 3 || len(res.Messages) != 3 {
			t.Fatalf("packets/messages = %d/%d", res.Packets, len(res.Messages))
		}
		// An SPB has no timestamp: the zero time of the gopacket reader (1970 or year 1) is reported.
		got := res.Messages[0]
		w := wantOpt(path, "spb1", 1, got.Time)
		pbCheckMsgs(t, res.Messages[:1], []trace.Message{w})
		if got.Time.After(mt0) {
			t.Errorf("SPB time = %v", got.Time)
		}
		pbCheckMsgs(t, res.Messages[1:2], []trace.Message{wantOpt(path, "epb", 2, mt0)})
	})
	t.Run("EPB with options, comment blocks, NRB, ISB, custom and decryption secrets blocks", func(t *testing.T) {
		ng := newPbNG(false).shb(pbOpt{pbOptComment, []byte("a comment")}, pbOpt{4, []byte("app")})
		ng.idb(layers.LinkTypeEthernet, 0, pbOpt{pbOptIfName, []byte("eth0")}, pbOpt{pbOptComment, []byte("c")}, pbOpt{pbOptIfTSResol, []byte{6}})
		ng.block(0x0000000a, append([]byte{0x4c, 0x53, 0x44, 0x54, 0, 0, 0, 0}, []byte("secrets!")...)) // DSB TLS key log
		ng.block(0x00000bad, []byte("custom copyable block")[:20])                                      // custom/unknown
		ng.block(0x40000bad, []byte("custom nocopy block")[:16])
		ng.block(4, []byte{0, 0, 0, 0, 0, 0, 0, 0}) // empty NRB
		ng.epb(0, uint64(mt0.UnixNano()/1000), pkt("a"), 0, pbOpt{pbOptComment, []byte("pkt comment")}, pbOpt{2, []byte{1, 0, 0, 0}})
		ng.block(5, append(append([]byte{}, 0, 0, 0, 0), make([]byte, 8)...)) // ISB
		ng.epb(0, uint64(mt0.UnixNano()/1000)+1, pkt("b"), 0)
		res, path := pbMustRead(t, "x.pcapng", ng.bytes())
		pbCheckMsgs(t, res.Messages, []trace.Message{
			wantOpt(path, "a", 1, mt0), wantOpt(path, "b", 2, mt0.Add(time.Microsecond)),
		})
	})
	t.Run("two sections with different link types and interface numbering restart", func(t *testing.T) {
		ng := newPbNG(false).shb().idb(layers.LinkTypeEthernet, 0)
		ng.epb(0, uint64(mt0.UnixNano()/1000), pkt("s1"), 0)
		ng.shb().idb(layers.LinkTypeRaw, 0)
		ng.epb(0, uint64(mt0.UnixNano()/1000)+5, f.udpIP(pbSIP("OPTIONS", "s2", 1)), 0)
		res, path := pbMustRead(t, "x.pcapng", ng.bytes())
		pbCheckMsgs(t, res.Messages, []trace.Message{
			wantOpt(path, "s1", 1, mt0), wantOpt(path, "s2", 2, mt0.Add(5*time.Microsecond)),
		})
	})
	t.Run("mixed endianness across sections", func(t *testing.T) {
		le := newPbNG(false).shb().idb(layers.LinkTypeEthernet, 0)
		le.epb(0, uint64(mt0.UnixNano()/1000), pkt("le"), 0)
		be := newPbNG(true).shb().idb(layers.LinkTypeEthernet, 0)
		be.epb(0, uint64(mt0.UnixNano()/1000)+1, pkt("be"), 0)
		res, path := pbMustRead(t, "x.pcapng", append(le.bytes(), be.bytes()...))
		pbCheckMsgs(t, res.Messages, []trace.Message{
			wantOpt(path, "le", 1, mt0), wantOpt(path, "be", 2, mt0.Add(time.Microsecond)),
		})
	})
	t.Run("EPB referencing an unknown interface stops the file with a warning", func(t *testing.T) {
		ng := newPbNG(false).shb().idb(layers.LinkTypeEthernet, 0)
		ng.epb(0, 1, pkt("ok"), 0)
		ng.epb(3, 2, pkt("a"), 0)
		res, p, err := pbRead(t, "x.pcapng", ng.bytes())
		if err != nil {
			t.Fatalf("err = %v", err)
		}
		if len(res.Messages) != 1 || len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], p) {
			t.Fatalf("messages = %d, warnings = %q", len(res.Messages), res.Warnings)
		}
	})
	t.Run("snaplen-truncated EPB", func(t *testing.T) {
		full := pkt("ng-snap")
		ng := newPbNG(false).shb().idb(layers.LinkTypeEthernet, 100)
		ng.epb(0, uint64(mt0.UnixNano()/1000), full[:100], len(full))
		res, _ := pbMustRead(t, "x.pcapng", ng.bytes())
		if res.Packets != 1 {
			t.Fatalf("packets = %d", res.Packets)
		}
		// 100 bytes = headers (42) + 58 bytes of SIP; the start line is intact.
		if len(res.Messages) != 1 || res.Messages[0].Method != "OPTIONS" {
			t.Fatalf("messages = %+v", res.Messages)
		}
	})
	t.Run("pcapng truncated inside a block keeps earlier packets and warns", func(t *testing.T) {
		ng := newPbNG(false).shb().idb(layers.LinkTypeEthernet, 0)
		ng.epb(0, 1, pkt("a"), 0)
		ng.epb(0, 2, pkt("b"), 0)
		b := ng.bytes()
		res, p, err := pbRead(t, "x.pcapng", b[:len(b)-9])
		if err != nil {
			t.Fatalf("err = %v", err)
		}
		if res.Packets != 1 || len(res.Messages) != 1 || len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], p) {
			t.Fatalf("packets = %d, messages = %d, warnings = %q", res.Packets, len(res.Messages), res.Warnings)
		}
	})
}

// ---------------------------------------------------------------- malformed files

func TestMalformedFiles(t *testing.T) {
	good := pbPcap(pbPcapOpts{lt: layers.LinkTypeEthernet},
		pbRec{ts: mt0, data: pbEth(0x0800, flow4.udpIP(pbSIP("OPTIONS", "a", 1)))},
		pbRec{ts: mt0, data: pbEth(0x0800, flow4.udpIP(pbSIP("OPTIONS", "b", 1)))})

	t.Run("must error naming the file", func(t *testing.T) {
		rnd := make([]byte, 4096)
		seed := uint32(12345)
		for i := range rnd {
			seed = seed*1664525 + 1013904223
			rnd[i] = byte(seed >> 24)
		}
		var gz bytes.Buffer
		gzw := newGzip(&gz)
		_, _ = gzw.Write(good)
		_ = gzw.Close()
		tests := []struct {
			name string
			data []byte
		}{
			{"empty", nil},
			{"one byte", []byte{0xd4}},
			{"text file", []byte("this is a text file\nwith two lines\nand some more text to be longer than a header\n")},
			{"random bytes", rnd},
			{"pcap magic only", good[:4]},
			{"pcap header cut", good[:23]},
			{"pcapng magic only", []byte{0x0a, 0x0d, 0x0d, 0x0a}},
			{"pcapng SHB with bogus length", append([]byte{0x0a, 0x0d, 0x0d, 0x0a, 0xff, 0xff, 0xff, 0x7f}, make([]byte, 32)...)},
			{"pcap wrong version", func() []byte { b := append([]byte{}, good...); b[4] = 9; return b }()},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				_, p, err := pbRead(t, "x.pcap", tc.data)
				if err == nil {
					t.Fatal("expected an error")
				}
				if !strings.Contains(err.Error(), p) {
					t.Errorf("error %q does not name the file", err)
				}
			})
		}
	})
	// Damage after a valid file header keeps what was read and warns.
	t.Run("damaged records keep earlier packets and warn", func(t *testing.T) {
		tests := []struct {
			name    string
			data    []byte
			packets int
		}{
			{"cut in a record header", good[:24+10], 0},
			{"cut in a record body", good[:24+16+20], 0},
			{"second record cut", good[:len(good)-5], 1},
			{"huge caplen", func() []byte {
				b := append([]byte{}, good[:24]...)
				return append(b, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0x7f, 0xff, 0xff, 0xff, 0x7f)
			}(), 0},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				res, p, err := pbRead(t, "x.pcap", tc.data)
				if err != nil {
					t.Fatalf("err = %v", err)
				}
				if res.Packets != tc.packets || len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], p) {
					t.Errorf("packets = %d (want %d), warnings = %q", res.Packets, tc.packets, res.Warnings)
				}
			})
		}
	})
	t.Run("gzip-compressed pcap", func(t *testing.T) {
		// Behaviour is whatever pcapgo does; the point is: it must not crash
		// and must either decode correctly or fail naming the file.
		var gz bytes.Buffer
		w := newGzip(&gz)
		_, _ = w.Write(good)
		_ = w.Close()
		res, p, err := pbRead(t, "x.pcap.gz", gz.Bytes())
		if err != nil {
			if !strings.Contains(err.Error(), p) {
				t.Fatalf("error %q does not name the file", err)
			}
			return
		}
		if len(res.Messages) != 2 {
			t.Fatalf("messages = %d, want 2", len(res.Messages))
		}
	})
	t.Run("directory", func(t *testing.T) {
		dir := t.TempDir()
		_, err := readFile(context.Background(), dir)
		if err == nil || !strings.Contains(err.Error(), dir) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("unsupported link type is skipped, not fatal", func(t *testing.T) {
		for _, lt := range []layers.LinkType{layers.LinkTypeIEEE802_11, layers.LinkType(147), layers.LinkType(9999), layers.LinkTypeFDDI} {
			file := pbPcap(pbPcapOpts{lt: lt}, pbRec{ts: mt0, data: bytes.Repeat([]byte{0x45}, 100)}, pbRec{ts: mt0, data: []byte{1}})
			res, _ := pbMustRead(t, "x.pcap", file)
			if res.Packets != 2 || res.Skipped != 2 {
				t.Errorf("lt %v: packets/skipped = %d/%d", lt, res.Packets, res.Skipped)
			}
		}
	})
	t.Run("garbage packets never panic", func(t *testing.T) {
		// Deterministic pseudo-random packets under every link type, plus SIP
		// payloads behind random-but-plausible header bytes.
		seed := uint32(1)
		next := func() byte { seed = seed*1664525 + 1013904223; return byte(seed >> 24) }
		lts := []layers.LinkType{layers.LinkTypeEthernet, layers.LinkTypeLinuxSLL, layers.LinkTypeLinuxSLL2, layers.LinkTypeRaw,
			layers.LinkTypeIPv4, layers.LinkTypeIPv6, layers.LinkTypeNull, layers.LinkTypeLoop, layers.LinkTypePPP}
		for _, lt := range lts {
			var recs []pbRec
			for i := 0; i < 400; i++ {
				b := make([]byte, 1+int(next())%120)
				for j := range b {
					b[j] = next()
				}
				recs = append(recs, pbRec{ts: mt0, data: b})
			}
			if _, err := readFile(context.Background(), pbWriteFile(t, "x.pcap", pbPcap(pbPcapOpts{lt: lt}, recs...))); err != nil {
				t.Errorf("lt %v: %v", lt, err)
			}
		}
		// Bit flips on a valid packet for each prefix length.
		base := pbEth(0x0800, flow4.udpIP(pbSIP("OPTIONS", "flip", 1)))
		var recs []pbRec
		for i := 0; i < len(base)*8 && i < 8*80; i++ {
			b := append([]byte{}, base...)
			b[i/8] ^= 1 << (i % 8)
			recs = append(recs, pbRec{ts: mt0, data: b})
		}
		if _, err := readFile(context.Background(), pbWriteFile(t, "x.pcap", pbPcap(pbPcapOpts{lt: layers.LinkTypeEthernet}, recs...))); err != nil {
			t.Error(err)
		}
	})
}

// ---------------------------------------------------------------- ReadFiles

func TestReadFilesMergeManyFiles(t *testing.T) {
	const nFiles = 50
	dir := t.TempDir()
	var paths []string
	type key struct{ file, packet int }
	// Packet k of file i has timestamp (k/2) seconds + (i%5) ms: lots of ties
	// across files (equal i%5) and inside a file (pairs k, k+1).
	for i := 0; i < nFiles; i++ {
		var recs []pbRec
		for k := 0; k < 6; k++ {
			ts := mt0.Add(time.Duration(k/2)*time.Second + time.Duration(i%5)*time.Millisecond)
			id := fmt.Sprintf("f%02d-p%d", i, k)
			recs = append(recs, pbRec{ts: ts, data: pbEth(0x0800, flow4.udpIP(pbSIP("OPTIONS", id, 1)))})
		}
		p := filepath.Join(dir, fmt.Sprintf("f%02d.pcap", i))
		if err := os.WriteFile(p, pbPcap(pbPcapOpts{lt: layers.LinkTypeEthernet}, recs...), 0o644); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, p)
	}
	// Expected order: by time, ties by file order (argument order) then packet order.
	type exp struct {
		ts   time.Time
		file int
		k    int
	}
	var want []exp
	for k := 0; k < 6; k++ {
		_ = k
	}
	for sec := 0; sec < 3; sec++ {
		for ms := 0; ms < 5; ms++ {
			for i := 0; i < nFiles; i++ {
				if i%5 != ms {
					continue
				}
				for k := 2 * sec; k < 2*sec+2; k++ {
					want = append(want, exp{mt0.Add(time.Duration(sec)*time.Second + time.Duration(ms)*time.Millisecond), i, k})
				}
			}
		}
	}
	for round := 0; round < 3; round++ { // repeat: concurrency must not change the result
		res, err := readFiles(context.Background(), paths)
		if err != nil {
			t.Fatal(err)
		}
		if res.Packets != nFiles*6 || len(res.Messages) != nFiles*6 {
			t.Fatalf("packets/messages = %d/%d", res.Packets, len(res.Messages))
		}
		for n, m := range res.Messages {
			w := want[n]
			if !m.Time.Equal(w.ts) || m.File != paths[w.file] || m.Index != w.k+1 || m.CallID != fmt.Sprintf("f%02d-p%d", w.file, w.k) {
				t.Fatalf("round %d message %d = {%s %s idx %d %s}, want {file %d pkt %d at %s}", round, n, m.Time.Format(time.RFC3339Nano), filepath.Base(m.File), m.Index, m.CallID, w.file, w.k+1, w.ts.Format(time.RFC3339Nano))
			}
		}
		// Reversing the argument order reverses the tie order between files.
		rev := make([]string, len(paths))
		for i, p := range paths {
			rev[len(paths)-1-i] = p
		}
		res2, err := readFiles(context.Background(), rev)
		if err != nil {
			t.Fatal(err)
		}
		if res2.Messages[0].File != paths[0] { // i=0 has ms=0 and is alone first among the ms=0 files? it is the last in rev order
			// ties at the first instant: files 0,5,10,...,45; reversed argument order puts 45 first
			if res2.Messages[0].File != paths[45] {
				t.Fatalf("tie order not by argument order: first = %s", filepath.Base(res2.Messages[0].File))
			}
		} else {
			t.Fatalf("tie order not by argument order: first message is from file 0 for reversed arguments")
		}
	}
}

func TestReadFilesBadFileNoGoroutineLeak(t *testing.T) {
	dir := t.TempDir()
	good := pbPcap(pbPcapOpts{lt: layers.LinkTypeEthernet}, pbRec{ts: mt0, data: pbEth(0x0800, flow4.udpIP(pbSIP("OPTIONS", "a", 1)))})
	var paths []string
	for i := 0; i < 60; i++ {
		p := filepath.Join(dir, fmt.Sprintf("f%02d.pcap", i))
		data := good
		if i == 37 {
			data = []byte("not a capture, just some text that is long enough")
		}
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, p)
	}
	before := runtime.NumGoroutine()
	for round := 0; round < 20; round++ {
		res, err := readFiles(context.Background(), paths)
		if err == nil || !strings.Contains(err.Error(), paths[37]) {
			t.Fatalf("err = %v, want an error naming %s", err, paths[37])
		}
		if len(res.Messages) != 0 || res.Packets != 0 {
			t.Fatalf("partial result returned alongside error: %+v", res)
		}
	}
	waitGoroutines(t, before)
}

func waitGoroutines(t *testing.T, before int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		runtime.GC()
		n := runtime.NumGoroutine()
		if n <= before {
			return
		}
		if time.Now().After(deadline) {
			buf := make([]byte, 1<<16)
			buf = buf[:runtime.Stack(buf, true)]
			t.Fatalf("goroutines: %d before, %d after\n%s", before, n, buf)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// bigCapture writes a capture with n SIP packets and returns its path.
func bigCapture(t *testing.T, n int) string {
	t.Helper()
	pkt := pbEth(0x0800, flow4.udpIP(pbSIP("OPTIONS", "big", 1)))
	recs := make([]pbRec, n)
	for i := range recs {
		recs[i] = pbRec{ts: mt0.Add(time.Duration(i) * time.Microsecond), data: pkt}
	}
	return pbWriteFile(t, "big.pcap", pbPcap(pbPcapOpts{lt: layers.LinkTypeEthernet}, recs...))
}

func TestReadFilesContext(t *testing.T) {
	const n = 100_000
	big := bigCapture(t, n)

	t.Run("big capture, uncancelled", func(t *testing.T) {
		res, err := readFile(context.Background(), big)
		if err != nil || res.Packets != n || len(res.Messages) != n {
			t.Fatalf("packets/messages/err = %d/%d/%v", res.Packets, len(res.Messages), err)
		}
		for i, m := range res.Messages {
			if m.Index != i+1 {
				t.Fatalf("message %d has index %d", i, m.Index)
			}
		}
	})
	t.Run("cancelled before start", func(t *testing.T) {
		before := runtime.NumGoroutine()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		res, err := readFiles(ctx, []string{big, big, big})
		if err == nil || !errorsIs(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
		if len(res.Messages) != 0 {
			t.Fatalf("messages returned on cancel: %d", len(res.Messages))
		}
		waitGoroutines(t, before)
	})
	t.Run("deadline exceeded is reported as such", func(t *testing.T) {
		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		defer cancel()
		_, err := readFiles(ctx, []string{big})
		if !errorsIs(err, context.DeadlineExceeded) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("cancelled mid-way", func(t *testing.T) {
		paths := make([]string, 8)
		for i := range paths {
			paths[i] = big
		}
		for _, delay := range []time.Duration{0, time.Millisecond, 5 * time.Millisecond, 20 * time.Millisecond} {
			before := runtime.NumGoroutine()
			ctx, cancel := context.WithCancel(context.Background())
			time.AfterFunc(delay, cancel)
			done := make(chan struct{})
			var res sipResult
			var err error
			go func() { res, err = readFiles(ctx, paths); close(done) }()
			select {
			case <-done:
			case <-time.After(30 * time.Second):
				t.Fatal("ReadFiles did not return after cancel")
			}
			cancel()
			if err != nil {
				if !errorsIs(err, context.Canceled) {
					t.Fatalf("delay %v: err = %v", delay, err)
				}
				if len(res.Messages) != 0 {
					t.Fatalf("delay %v: partial result with error", delay)
				}
			} else if len(res.Messages) != len(paths)*n {
				// The read can legitimately complete before the cancel fires; then it must be complete.
				t.Fatalf("delay %v: nil error but %d messages", delay, len(res.Messages))
			}
			waitGoroutines(t, before)
		}
	})
}

// ------------------------------------------------------------ gopacket oracle

// TestAgainstGopacketWriter cross-checks the hand-built packets against
// gopacket's own serializer, so the byte builders above cannot all be wrong in
// the same way as the decoder.
func TestAgainstGopacketWriter(t *testing.T) {
	src, dst := pbAddr("203.0.113.5"), pbAddr("203.0.113.6")
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 9, Protocol: layers.IPProtocolUDP, SrcIP: src.AsSlice(), DstIP: dst.AsSlice()}
	u := &layers.UDP{SrcPort: 5060, DstPort: 5062}
	if err := u.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ip, u, gopacket.Payload(pbSIP("OPTIONS", "oracle", 1))); err != nil {
		t.Fatal(err)
	}
	mine := pbIPv4(src, dst, pbProtoUDP, pbUDP(src, dst, 5060, 5062, []byte(pbSIP("OPTIONS", "oracle", 1))), pbIP4Opts{})
	if len(mine) != len(buf.Bytes()) {
		t.Fatalf("length %d != %d", len(mine), len(buf.Bytes()))
	}
	// Compare everything except the IP header fields the builders set differently (TTL, ID).
	theirs := buf.Bytes()
	if !bytes.Equal(mine[20:], theirs[20:]) { // UDP header incl. checksum + payload
		t.Fatalf("udp part differs:\n%x\n%x", mine[20:], theirs[20:])
	}
	// Our IP header checksum must verify.
	if pbFold(pbSum(mine[:20], 0)) != 0 {
		t.Fatalf("ipv4 header checksum invalid")
	}

	var out bytes.Buffer
	w, err := pcapgo.NewNgWriter(&out, layers.LinkTypeRaw)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WritePacket(gopacket.CaptureInfo{Timestamp: mt0, CaptureLength: len(theirs), Length: len(theirs)}, theirs); err != nil {
		t.Fatal(err)
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	res, path := pbMustRead(t, "x.pcapng", out.Bytes())
	pbCheckMsgs(t, res.Messages, []trace.Message{
		(flow{src, dst, 5060, 5062}).want("UDP", pbWantReq("OPTIONS", "oracle", 1), path, 1, mt0),
	})
}
